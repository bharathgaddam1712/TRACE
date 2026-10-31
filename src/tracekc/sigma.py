"""Compile Sigma rules (single-event + v2 correlation rules) into DuckDB SQL.

Supported:
  * detection maps (AND of fields), lists of maps (OR), value lists (OR, or AND with |all)
  * modifiers: contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte
  * conditions: and / or / not / parentheses / "1 of x*" / "all of x*" / "1 of them" / "all of them"
  * correlation types: event_count, value_count, temporal_ordered
Matching is case-insensitive (Sigma default) except |re.
Not supported (rejected at load time with an error): keyword lists, |base64 family, |windash,
correlation type "temporal" (unordered). Rules are the B-4 extension point: drop a YAML file into
rules/ and re-run.
"""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LEVELS = {"informational": 10, "low": 25, "medium": 50, "high": 75, "critical": 100}

# Sigma / ECS field name -> normalized events column.
FIELD_MAP = {
    "event.action": "action", "event.outcome": "outcome", "event.kind": "kind",
    "event.dataset": "dataset", "event.category": "category",
    "message": "message", "rule.name": "vendor_rule_name", "rule.id": "vendor_rule_id",
    "host.name": "host", "host.hostname": "host", "Computer": "host",
    "user.name": "user_name", "user.domain": "user_domain", "User": "user_name", "TargetUserName": "user_name",
    "source.ip": "src_ip", "source.port": "src_port", "IpAddress": "src_ip", "SourceIp": "src_ip",
    "destination.ip": "dst_ip", "destination.port": "dst_port", "destination.domain": "dst_domain",
    "DestinationIp": "dst_ip", "DestinationPort": "dst_port", "DestinationHostname": "dst_domain",
    "network.direction": "direction", "network.protocol": "net_protocol", "network.bytes": "net_bytes",
    "network.transport": "net_transport",
    "process.name": "proc_name", "process.pid": "proc_pid", "process.command_line": "proc_cmd",
    "process.executable": "proc_exe", "process.parent.name": "parent_name", "process.parent.pid": "parent_pid",
    "CommandLine": "proc_cmd", "Image": "proc_exe", "OriginalFileName": "proc_name",
    "file.path": "file_path", "file.name": "file_name", "file.extension": "file_ext", "file.size": "file_size",
    "TargetFilename": "file_path",
    "registry.path": "reg_path", "registry.data.strings": "reg_data", "TargetObject": "reg_path", "Details": "reg_data",
    "dns.question.name": "dns_name", "QueryName": "dns_name",
    "winlog.event_id": "win_event_id", "EventID": "win_event_id",
    "winlog.logon.type": "logon_type", "LogonType": "logon_type",
    "labels_extra.failed_count_5min": "failed_count", "labels_extra.files_renamed_60s": "renamed_count",
}
NUMERIC_COLS = {"src_port", "dst_port", "net_bytes", "proc_pid", "parent_pid", "win_event_id",
                "failed_count", "renamed_count", "file_size"}

# Columns every rule relation carries, so correlations can group by any of them.
ENTITY_COLS = ["host", "user_name", "src_ip", "dst_ip", "src_host", "dst_host", "dst_domain", "proc_name", "proc_pid"]

# logsource -> SQL constraint (None = no constraint).
LOGSOURCE = {
    ("category", "process_creation"): "action = 'process_created'",
    ("category", "network_connection"): "action = 'network_connection'",
    ("category", "dns_query"): "action = 'dns_query'",
    ("category", "dns"): "action = 'dns_query'",
    ("category", "registry_set"): "action = 'registry_value_set'",
    ("category", "registry_event"): "category = 'registry'",
    ("category", "file_event"): "category = 'file'",
    ("category", "file_rename"): "action = 'file_rename'",
    ("category", "authentication"): "action = 'user_logon'",
    ("product", "windows"): "(os_type = 'windows' OR win_event_id IS NOT NULL)",
    ("product", "linux"): "os_type = 'linux'",
    ("service", "security"): None,
}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "cidr", "gt", "gte", "lt", "lte", 'exists', 'fieldref'}


class SigmaError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    kind: str                      # "base" | "correlation"
    level: str
    severity: int
    techniques: list[str]
    tactic_hint: str | None
    author: str
    source_file: str
    where: str | None = None       # base rules
    corr: dict = field(default_factory=dict)
    always_emit: bool = False
    logsource: dict = field(default_factory=dict)


def lit(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _wildcards(s: str) -> str:
    return _escape_like(s).replace("*", "%").replace("?", "_")


def cidr_sql(col: str, cidrs) -> str:
    parts = []
    for c in ([cidrs] if isinstance(cidrs, str) else cidrs):
        net = ipaddress.ip_network(str(c), strict=False)
        if net.version != 4:
            raise SigmaError(f"only IPv4 cidr supported: {c}")
        parts.append(f"ipv4_int({col}) BETWEEN {int(net.network_address)} AND {int(net.broadcast_address)}")
    return "(" + " OR ".join(parts) + ")"


def _column(name: str) -> str:
    if name not in FIELD_MAP:
        raise SigmaError(f"unknown field '{name}' (add it to sigma.FIELD_MAP)")
    return FIELD_MAP[name]


def _value_sql(col: str, mods: list[str], value) -> str:
    if value is None:
        return f"{col} IS NULL"
    for op, sym in (("gte", ">="), ("gt", ">"), ("lte", "<="), ("lt", "<")):
        if op in mods:
            return f"{col} {sym} {float(value)!r}"
    if col in NUMERIC_COLS and not {"contains", "startswith", "endswith", "re"} & set(mods):
        try:
            return f"{col} = {int(value)}"
        except (TypeError, ValueError):
            raise SigmaError(f"field {col} is numeric, got {value!r}") from None
    text = f"CAST({col} AS VARCHAR)"
    if "re" in mods:
        _check_regex(str(value))
        return f"regexp_matches({text}, {lit(value)})"
    s = str(value).lower()
    if "contains" in mods:
        pattern = "%" + _wildcards(s) + "%"
    elif "startswith" in mods:
        pattern = _wildcards(s) + "%"
    elif "endswith" in mods:
        pattern = "%" + _wildcards(s)
    elif "*" in s or "?" in s:
        pattern = _wildcards(s)
    else:
        return f"lower({text}) = {lit(s)}"
    return f"lower({text}) LIKE {lit(pattern)} ESCAPE '\\'"


@lru_cache(maxsize=4096)
def _check_regex(pattern):
    import duckdb
    try:
        with duckdb.connect() as connection:
            connection.execute("SELECT regexp_matches('', ?)", [pattern]).fetchone()
    except duckdb.Error:
        raise SigmaError('regular expression is not supported by DuckDB/RE2') from None


def _field_sql(key: str, value) -> str:
    name, *mods = key.split("|")
    bad = set(mods) - SUPPORTED_MODS
    if bad:
        raise SigmaError(f"unsupported modifier(s) {sorted(bad)} on {name}")
    col = _column(name)
    if 'exists' in mods:
        if not isinstance(value,bool):
            raise SigmaError('exists modifier requires a boolean')
        return f'{col} IS NOT NULL' if value else f'{col} IS NULL'
    if 'fieldref' in mods:
        if not isinstance(value,str) or len(mods)!=1:
            raise SigmaError('fieldref requires a single field name')
        return f'{col} = {_column(value)}'
    if "cidr" in mods:
        return cidr_sql(col, value)
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"empty value list for {key}")
    joiner = " AND " if "all" in mods else " OR "
    return "(" + joiner.join(_value_sql(col, mods, v) for v in values) + ")"


def _selection_sql(name: str, sel) -> str:
    if isinstance(sel, dict):
        if not sel:
            raise SigmaError(f"empty selection {name}")
        return "(coalesce((" + " AND ".join(_field_sql(k, v) for k, v in sel.items()) + "), FALSE))"
    if isinstance(sel, list) and all(isinstance(x, dict) for x in sel):
        return "(" + " OR ".join(_selection_sql(name, x) for x in sel) + ")"
    raise SigmaError(f"selection {name}: keyword lists are not supported")


_TOKEN = re.compile(r"\s*(\(|\)|(?:1|any|all)\s+of\s+[\w*]+|[\w*]+)", re.I)


def _condition_sql(cond: str, sels: dict[str, str]) -> str:
    tokens = [t for t in _TOKEN.findall(cond)]
    if "".join(tokens).replace(" ", "") != cond.replace(" ", ""):
        raise SigmaError(f"cannot parse condition: {cond!r}")
    pos = 0

    def peek():
        return tokens[pos].lower() if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def expr():
        parts = [term()]
        while peek() == "or":
            take()
            parts.append(term())
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"

    def term():
        parts = [factor()]
        while peek() == "and":
            take()
            parts.append(factor())
        return parts[0] if len(parts) == 1 else "(" + " AND ".join(parts) + ")"

    def factor():
        tok = peek()
        if tok is None:
            raise SigmaError(f"unexpected end of condition: {cond!r}")
        if tok == "not":
            take()
            return f"(NOT {factor()})"
        if tok == "(":
            take()
            inner = expr()
            if peek() != ")":
                raise SigmaError(f"missing ')' in {cond!r}")
            take()
            return inner
        raw = take()
        m = re.match(r"(1|any|all)\s+of\s+([\w*]+)", raw, re.I)
        if m:
            quant, pat = m.group(1).lower(), m.group(2)
            if pat == "them":
                names = list(sels)
            else:
                rx = re.compile("^" + re.escape(pat).replace("\\*", ".*") + "$")
                names = [n for n in sels if rx.match(n)]
            if not names:
                raise SigmaError(f"'{raw}' matches no selection")
            j = " AND " if quant == "all" else " OR "
            return "(" + j.join(sels[n] for n in names) + ")"
        if raw not in sels:
            raise SigmaError(f"condition references unknown selection '{raw}'")
        return sels[raw]

    out = expr()
    if pos != len(tokens):
        raise SigmaError(f"trailing tokens in condition {cond!r}")
    return out


def _timespan_ms(span: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(span).strip())
    if not m:
        raise SigmaError(f"bad timespan {span!r}")
    return int(m.group(1)) * {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[m.group(2)]


def _tags(tags):
    techniques, tactic = [], None
    for t in tags or []:
        t = str(t).lower()
        if not t.startswith("attack."):
            continue
        v = t[len("attack."):]
        if re.fullmatch(r"t\d{4}(\.\d{3})?", v):
            techniques.append(v.upper())
        elif tactic is None and not re.fullmatch(r"[gs]\d{4}", v):
            tactic = v.replace("_", "-")
    return techniques, tactic


def parse_rule(doc: dict, source_file: str) -> Rule:
    rid = str(doc.get("id") or "").strip()
    if not rid:
        raise SigmaError("rule without id")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise SigmaError(f"{rid}: unknown level {level}")
    techniques, tactic = _tags(doc.get("tags"))
    base = dict(id=rid, title=str(doc.get("title", rid)), level=level, severity=LEVELS[level],
                techniques=techniques, tactic_hint=tactic, author=str(doc.get("author", "")),
                source_file=source_file, always_emit=bool((doc.get("trace") or {}).get("always_emit")),
                logsource=dict(doc.get('logsource') or {}))
    if "correlation" in doc:
        c = doc["correlation"]
        ctype = c.get("type")
        if ctype not in ("event_count", "value_count", "temporal_ordered"):
            raise SigmaError(f"{rid}: correlation type {ctype!r} not supported")
        rules = c.get("rules") or []
        if not rules:
            raise SigmaError(f"{rid}: correlation without rules")
        group = [_column(g) for g in (c.get("group-by") or [])]
        for g in group:
            if g not in ENTITY_COLS:
                raise SigmaError(f"{rid}: group-by column {g} must be one of {ENTITY_COLS}")
        cond = c.get("condition") or {}
        corr = dict(type=ctype, rules=[str(r) for r in rules], group=group,
                    span_ms=_timespan_ms(c.get("timespan", "5m")), generate=bool(c.get("generate", False)))
        if ctype in ("event_count", "value_count"):
            ops = [(k, v) for k, v in cond.items() if k in ("gt", "gte", "lt", "lte", "eq")]
            if len(ops) != 1:
                raise SigmaError(f"{rid}: condition needs exactly one of gt/gte/lt/lte/eq")
            corr["op"] = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "="}[ops[0][0]]
            corr["threshold"] = int(ops[0][1])
            if ctype == "value_count":
                corr["field"] = _column(cond.get("field", ""))
        return Rule(kind="correlation", corr=corr, **base)

    det = doc.get("detection") or {}
    cond = det.get("condition")
    if not isinstance(cond, str):
        raise SigmaError(f"{rid}: detection.condition must be a single string")
    sels = {k: _selection_sql(k, v) for k, v in det.items() if k != "condition"}
    where = _condition_sql(cond, sels)
    ls = doc.get("logsource") or {}
    constraints = []
    for key in ("category", "product", "service"):
        if key in ls:
            k = (key, str(ls[key]).lower())
            if k not in LOGSOURCE:
                raise SigmaError(f"{rid}: unsupported logsource {key}={ls[key]}")
            if LOGSOURCE[k]:
                constraints.append(LOGSOURCE[k])
    if constraints:
        where = "(" + " AND ".join(constraints + [where]) + ")"
    return Rule(kind="base", where=where, **base)


def load_rules(rules_dir: str | Path) -> tuple[dict[str, Rule], list[str]]:
    root=Path(rules_dir)
    files=tuple((str(path),path.stat().st_size,path.stat().st_mtime_ns) for path in sorted(root.rglob('*.y*ml')))
    rules,errors=_load_rules_cached(files)
    return dict(rules),list(errors)


@lru_cache(maxsize=8)
def _load_rules_cached(files) -> tuple[dict[str, Rule], list[str]]:
    """Load every *.yml/*.yaml under rules_dir. Returns (rules by id, error messages)."""
    rules: dict[str, Rule] = {}
    errors: list[str] = []
    for filename,_,_ in files:
        path=Path(filename)
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8-sig")))
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: YAML error: {exc}")
            continue
        for doc in docs:
            if not doc:
                continue
            try:
                rule = parse_rule(doc, path.name)
                if rule.id in rules:
                    raise SigmaError(f"duplicate rule id {rule.id}")
                rules[rule.id] = rule
            except SigmaError as exc:
                errors.append(f"{path.name}: {exc}")
    for r in list(rules.values()):
        if r.kind == "correlation":
            missing = [x for x in r.corr["rules"] if x not in rules]
            if missing:
                errors.append(f"{r.source_file}: {r.id} references unknown rules {missing}")
                del rules[r.id]
    return rules, errors


def emitting_rule_ids(rules: dict[str, Rule]) -> set[str]:
    """Rules whose matches become detections. Per Sigma v2, rules referenced by a correlation are
    building blocks and stay silent unless the correlation sets generate: true (or the rule sets the
    TRACE extension trace.always_emit)."""
    referenced, released = set(), set()
    for r in rules.values():
        if r.kind == "correlation":
            referenced.update(r.corr["rules"])
            if r.corr["generate"]:
                released.update(r.corr["rules"])
    return {rid for rid, r in rules.items() if rid not in referenced or rid in released or r.always_emit}


# ---------------------------------------------------------------- correlation SQL

def relation_sql(rule_id: str, rules: dict[str, Rule], cap: int, _stack=()) -> str:
    """SQL producing one row per match of rule_id with columns:
    ts_first_ms, ts_last_ms, event_count, event_ids, <ENTITY_COLS>."""
    if rule_id in _stack:
        raise SigmaError(f"correlation cycle via {rule_id}")
    r = rules[rule_id]
    ent = ", ".join(ENTITY_COLS)
    if r.kind == "base":
        return (f"SELECT ts_ms AS ts_first_ms, ts_ms AS ts_last_ms, 1::BIGINT AS event_count, "
                f"[event_id] AS event_ids, {ent} FROM rule_hits WHERE list_contains(hits, {lit(rule_id)})")
    c = r.corr
    stack = _stack + (rule_id,)
    g = c["group"]
    others = [col for col in ENTITY_COLS if col not in g]
    if c["type"] in ("event_count", "value_count"):
        inner = " UNION ALL ".join(f"({relation_sql(x, rules, cap, stack)})" for x in c["rules"])
        part = ", ".join(g) if g else "1"
        notnull = " AND ".join(f"{x} IS NOT NULL" for x in g) or "TRUE"
        gsel = "".join(f"{x}, " for x in g)
        # an entity is kept only when unique inside the group (a spray has no single victim account);
        # deterministic, unlike mode() which breaks ties arbitrarily
        agg_others = ", ".join(f"CASE WHEN count(DISTINCT {x}) = 1 THEN min({x}) END AS {x}" for x in others)
        if c["type"] == "event_count":
            having = f"max(win) {c['op']} {c['threshold']}"
        else:
            having = f"count(DISTINCT {c['field']}) {c['op']} {c['threshold']}"
        span = c["span_ms"]
        return f"""
SELECT {gsel}min(ts_first_ms) AS ts_first_ms, max(ts_last_ms) AS ts_last_ms,
       sum(event_count)::BIGINT AS event_count,
       flatten(list(event_ids ORDER BY ts_first_ms))[1:{cap}] AS event_ids{', ' + agg_others if agg_others else ''}
FROM (
  SELECT *, sum(brk) OVER (PARTITION BY {part} ORDER BY ts_first_ms ROWS UNBOUNDED PRECEDING) AS sess
  FROM (
    SELECT *,
      sum(event_count) OVER (PARTITION BY {part} ORDER BY ts_first_ms
                             RANGE BETWEEN {span} PRECEDING AND CURRENT ROW) AS win,
      CASE WHEN ts_first_ms - lag(ts_last_ms) OVER (PARTITION BY {part} ORDER BY ts_first_ms) > {span}
           THEN 1 ELSE 0 END AS brk
    FROM ({inner}) r WHERE {notnull}
  )
)
GROUP BY {gsel}sess
HAVING {having}"""
    # temporal_ordered: each stage must follow the previous one for the same group within timespan
    if not g:
        raise SigmaError(f"{rule_id}: temporal_ordered needs group-by")
    cur = relation_sql(c["rules"][0], rules, cap, stack)
    for nxt_id in c["rules"][1:]:
        nxt = relation_sql(nxt_id, rules, cap, stack)
        on = " AND ".join(f"a.{x} = b.{x}" for x in g)
        ents = ", ".join(f"coalesce(b.{x}, a.{x}) AS {x}" for x in ENTITY_COLS)
        cur = f"""
SELECT a.ts_first_ms, b.ts_last_ms, (a.event_count + b.event_count)::BIGINT AS event_count,
       (a.event_ids || b.event_ids)[1:{cap}] AS event_ids, {ents}
FROM ({cur}) a ASOF JOIN ({nxt}) b ON {on} AND a.ts_last_ms <= b.ts_first_ms
WHERE b.ts_first_ms - a.ts_first_ms <= {c['span_ms']}"""
    return cur
