"""Stages 4-5: collapse detections into signals, link signals into incidents, gate and score them.

Signals: detections with the same technique + entities with gaps under dedupe_window_s (capped at one recurrence bucket) merge into one signal
(the merged count is reported, B-3). Linking runs in DuckDB as sessionized pivots: for each user,
host and external IP, signals are ordered in time and consecutive ones inside session_gap_s are linked.
That yields O(n) edges instead of O(n^2). Hub pivots (a host touched by many users, e.g. a domain
controller or NAT address) are not used to link, so one busy server cannot glue unrelated attacks.
Components of the edge graph are candidate incidents; the FP gate promotes only multi-tactic or
critical ones. Everything else is reported as an isolated finding, never dropped.
"""
from __future__ import annotations

import bisect
import json
import logging
from collections import defaultdict

from tracekc.engine import dicts, one, run
from tracekc.sigma import lit

log = logging.getLogger(__name__)

SIGNAL_COLS = ("signal_id, sig_key, host, user_name, src_ip, dst_ip, dst_domain, src_host, dst_host, technique, source_technique, techniques, "
               "technique_name, tactic, tactic_name, tactic_order, kill_chain_stage, lockheed_phase, mapping_source, "
               "mapping_version, mapping_reason, title, severity, ts_first_ms, ts_last_ms, n_detections, n_events, rule_ids, "
               "rule_sources, authors, event_ids, vendor_corroborated, evidence, procs, process_keys, recurrence, recurrent")


def build_signals(con, cfg: dict, suppressions: list[dict]) -> dict:
    c = cfg["correlation"]
    dedupe = int(c["dedupe_window_s"]) * 1000
    cap = int(cfg["detection"]["max_event_ids"])
    bucket = int(c["recurrence_bucket_s"]) * 1000
    part = "sig_key, host, user_name, src_ip, dkey, win, fingerprint"
    fp = ("md5(concat_ws('|', coalesce(technique, rule_id), host, user_name, src_ip, dst_ip, dst_domain, "
          "json_extract_string(evidence, '$.cmd'), json_extract_string(evidence, '$.registry'), "
          "json_extract_string(evidence, '$.file')))")
    # Recurrence (scheduled-job / alert-fatigue control): the same alert fingerprint - rule, account,
    # host, addresses, command line, registry key - appearing in many separate time buckets is baseline
    # behaviour, not a one-off attack step. Counted per detection so that a pattern repeating more often
    # than the dedupe window is still seen in every bucket it occurs in.
    run(con, f"""
        CREATE OR REPLACE TABLE recurrence AS
        SELECT {fp} AS fingerprint, count(DISTINCT ts_first_ms // {bucket}) AS buckets
        FROM labeled GROUP BY 1""")
    # Signals: same technique + entities with gaps under dedupe_window_s, capped at one recurrence bucket
    # so a signal never spans hours and an attack step cannot be absorbed into long-running repeated noise.
    run(con, f"""
        CREATE OR REPLACE TABLE signals AS
        WITH d AS (SELECT *, coalesce(technique, rule_id) AS sig_key, coalesce(dst_ip, dst_domain, '') AS dkey,
                          ts_first_ms // {bucket} AS win, {fp} AS fingerprint
                   FROM labeled),
        o AS (SELECT *, CASE WHEN ts_first_ms - lag(ts_last_ms) OVER w > {dedupe} THEN 1 ELSE 0 END AS brk
              FROM d WINDOW w AS (PARTITION BY {part} ORDER BY ts_first_ms, det_id)),
        s AS (SELECT *, sum(brk) OVER (PARTITION BY {part} ORDER BY ts_first_ms, det_id
                                       ROWS UNBOUNDED PRECEDING) AS sess FROM o)
        SELECT row_number() OVER (ORDER BY min(ts_first_ms), sig_key, host, user_name, src_ip, dkey) AS signal_id,
               sig_key, host, user_name, src_ip,
               any_value(dst_ip) AS dst_ip, any_value(dst_domain) AS dst_domain,
               any_value(src_host) AS src_host, any_value(dst_host) AS dst_host,
               arg_max(technique, severity) AS technique, arg_max(technique_name, severity) AS technique_name,
               arg_max(source_technique,severity) AS source_technique,
               list_distinct(flatten(list(techniques))) AS techniques,
               arg_max(tactic, severity) AS tactic, arg_max(tactic_name, severity) AS tactic_name,
               arg_max(tactic_order, severity) AS tactic_order, arg_max(kill_chain_stage, severity) AS kill_chain_stage,
               arg_max(lockheed_phase, severity) AS lockheed_phase, arg_max(mapping_source, severity) AS mapping_source,
               any_value(mapping_version) AS mapping_version, arg_max(rule_title, severity) AS title,
               arg_max(mapping_reason, severity) AS mapping_reason,
               max(severity) AS severity, min(ts_first_ms) AS ts_first_ms, max(ts_last_ms) AS ts_last_ms,
               count(*) AS n_detections, sum(event_count)::BIGINT AS n_events,
               list(DISTINCT rule_id ORDER BY rule_id) AS rule_ids,
               list(DISTINCT rule_source ORDER BY rule_source) AS rule_sources,
               list(DISTINCT author ORDER BY author) AS authors,
               flatten(list(event_ids ORDER BY ts_first_ms))[1:{cap}] AS event_ids,
               bool_or(vendor_corroborated) AS vendor_corroborated,
               arg_max(evidence, severity) AS evidence,
               fingerprint,
               list(DISTINCT proc_name ORDER BY proc_name) FILTER (WHERE proc_name IS NOT NULL) AS procs,
               list(DISTINCT proc_pid ORDER BY proc_pid) FILTER (WHERE proc_pid IS NOT NULL) AS pids,
               list(DISTINCT json_extract_string(evidence, '$.process_entity_id'))
                 FILTER (WHERE json_extract_string(evidence, '$.process_entity_id') IS NOT NULL) AS process_keys,
               NULL::VARCHAR AS suppressed_reason
        FROM s GROUP BY {part}, sess""")
    keymap = {"rule_id": "list_contains(rule_ids, {v})", "technique": "technique = {v}",
              "user": "user_name = lower({v})", "host": "host = upper({v})", "src_ip": "src_ip = {v}",
              "dst_ip": "dst_ip = {v}", "dst_domain": "dst_domain = lower({v})"}
    for sup in suppressions:
        reason = sup.get("reason")
        conds = [keymap[k].format(v=lit(v)) for k, v in sup.items() if k in keymap]
        if not reason or not conds:
            raise ValueError(f"suppression needs a reason and at least one match key: {sup}")
        run(con, f"UPDATE signals SET suppressed_reason = {lit(reason)} "
                 f"WHERE suppressed_reason IS NULL AND {' AND '.join(conds)}")
    # Recurrent signals stay visible as findings but neither link steps together nor count towards promotion.
    run(con, f"""
        CREATE OR REPLACE TABLE signals AS
        SELECT s.* EXCLUDE (fingerprint), r.buckets AS recurrence,
               r.buckets >= {int(c['recurrence_min_buckets'])} AS recurrent
        FROM signals s JOIN recurrence r USING (fingerprint)""")
    total, suppressed, merged, recurrent = one(con, """
        SELECT count(*), count(suppressed_reason), sum(n_detections), count(*) FILTER (WHERE recurrent)
        FROM signals""")
    return {"signals": total, "suppressed_signals": suppressed, "recurrent_signals": recurrent,
            "detections_merged": int(merged or 0)}


def link_edges(con, cfg: dict) -> list[tuple[int, int, str]]:
    c = cfg["correlation"]
    gap = int(c["session_gap_s"]) * 1000
    excl = ", ".join(lit(u) for u in c["excluded_users"]) or "''"
    sev = int(c["link_min_severity"])
    run(con, f"""CREATE OR REPLACE VIEW linkable AS SELECT * FROM signals
                 WHERE suppressed_reason IS NULL AND NOT recurrent AND severity >= {sev}""")
    acct = f"CASE WHEN user_name IN ({excl}) THEN '' ELSE coalesce(user_name, '') END"
    run(con, f"""
        CREATE OR REPLACE TABLE pivots AS
        SELECT * FROM (
          SELECT signal_id, 'user' AS ptype, user_name AS pkey, ts_first_ms AS ts, user_name, host
          FROM linkable WHERE user_name IS NOT NULL AND user_name NOT IN ({excl})
          UNION ALL
          -- same host, same account
          SELECT signal_id, 'hostuser', h || '|' || {acct}, ts_first_ms, user_name, host
          FROM (SELECT signal_id, unnest(list_distinct([host, src_host, dst_host])) AS h, ts_first_ms, user_name, host
                FROM linkable)
          UNION ALL
          -- same host, any account (hub-guarded: a host touched by many accounts does not link)
          SELECT signal_id, 'host', unnest(list_distinct([host, src_host, dst_host])), ts_first_ms, user_name, host
          FROM linkable
          UNION ALL
          SELECT signal_id, 'ip', unnest(list_distinct([src_ip, dst_ip])), ts_first_ms, user_name, host
          FROM linkable
          UNION ALL
          SELECT signal_id, 'process_entity', host || ':' || identity, ts_first_ms, user_name, host
          FROM (SELECT signal_id, host, unnest(process_keys) AS identity, ts_first_ms, user_name FROM linkable))
        WHERE pkey IS NOT NULL AND (ptype <> 'ip' OR NOT is_internal(pkey))""")
    run(con, f"""
        CREATE OR REPLACE TABLE pivot_sessions AS
        SELECT *, sum(brk) OVER (PARTITION BY ptype, pkey ORDER BY ts, signal_id ROWS UNBOUNDED PRECEDING) AS sess
        FROM (SELECT *, CASE WHEN ts - lag(ts) OVER (PARTITION BY ptype, pkey ORDER BY ts, signal_id) > {gap}
                             THEN 1 ELSE 0 END AS brk FROM pivots)""")
    rows = run(con, f"""
        WITH hubs AS (
          SELECT ptype, pkey, sess, count(DISTINCT user_name) AS users, count(DISTINCT host) AS hosts
          FROM pivot_sessions GROUP BY ALL),
        ok AS (
          SELECT p.* FROM pivot_sessions p JOIN hubs h USING (ptype, pkey, sess)
          WHERE NOT ((p.ptype IN ('host', 'ip') AND h.users > {int(c['hub_max_users'])})
                  OR (p.ptype IN ('user', 'ip') AND h.hosts > {int(c['hub_max_hosts'])})))
        SELECT a, b, ptype FROM (
          SELECT lag(signal_id) OVER (PARTITION BY ptype, pkey, sess ORDER BY ts, signal_id) AS a,
                 signal_id AS b, ptype FROM ok)
        WHERE a IS NOT NULL AND a <> b""")
    # Lateral logons link to the nearest earlier medium+ signal of the same account on the source host
    # and the nearest later one on the target host. Targeted ASOF edges survive hub pivots.
    rows += run(con, f"""
        WITH lat AS (SELECT signal_id, src_host, host, user_name, ts_first_ms FROM linkable
                     WHERE src_host IS NOT NULL AND src_host <> host AND user_name IS NOT NULL
                       AND json_extract_string(evidence, '$.action') = 'user_logon'
                       AND json_extract_string(evidence, '$.outcome') = 'success'),
        cand AS (SELECT signal_id, host, user_name, ts_first_ms FROM linkable WHERE severity >= 50)
        SELECT c.signal_id, l.signal_id, 'lateral' FROM lat l ASOF JOIN cand c
          ON l.src_host = c.host AND l.user_name = c.user_name AND l.ts_first_ms >= c.ts_first_ms
        WHERE l.ts_first_ms - c.ts_first_ms <= {gap}
        UNION ALL
        SELECT l.signal_id, c.signal_id, 'lateral' FROM lat l ASOF JOIN cand c
          ON l.host = c.host AND l.user_name = c.user_name AND l.ts_first_ms <= c.ts_first_ms
        WHERE c.ts_first_ms - l.ts_first_ms <= {gap}""")
    from tracekc.graph_algorithms import link_decision
    signals = {s['signal_id']: s for s in dicts(con, 'SELECT signal_id, host, user_name, src_ip, dst_ip, technique, process_keys FROM linkable')}
    accepted=[]
    for a,b,relation in rows:
        if a == b: continue
        if link_decision(signals[a],signals[b],relation,c)['accepted']:
            accepted.append((int(a),int(b),relation))
    return sorted(set(accepted))


class _UF:
    def __init__(self):
        self.parent: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _longest_progression(orders: list[int]) -> int:
    """Length of the longest non-decreasing kill-chain subsequence (RapSheet-style progression)."""
    tails: list[int] = []
    for o in orders:
        i = bisect.bisect_right(tails, o)
        if i == len(tails):
            tails.append(o)
        else:
            tails[i] = o
    return len(tails)


def _split_oversized(group: list[dict], c: dict) -> list[list[dict]]:
    """Linear-time orphan assignment followed by hard signal/host bounds."""
    max_signals=int(c['max_incident_signals']);max_hosts=int(c['max_incident_hosts'])
    if len(group)<=max_signals and len({s['host'] for s in group})<=max_hosts:return [group]
    by_user=defaultdict(list);owners=defaultdict(lambda:defaultdict(int));orphans=[]
    for signal in group:
        if signal['user_name']:
            by_user[signal['user_name']].append(signal);owners[signal['host']][signal['user_name']]+=1
        else:orphans.append(signal)
    for signal in orphans:
        known=owners.get(signal['host'],{})
        owner=max(known,key=lambda user:(known[user],user)) if known else '_host:'+str(signal['host'])
        by_user[owner].append(signal)
    result=[]
    for signals in by_user.values():
        current=[];hosts=set()
        for signal in sorted(signals,key=lambda item:(item['ts_first_ms'],item['signal_id'])):
            involved={signal['host']}
            if current and (len(current)>=max_signals or len(hosts|involved)>max_hosts):
                result.append(current);current=[];hosts=set()
            current.append(signal);hosts.update(involved)
        if current:result.append(current)
    return result


def score_incident(signals: list[dict], p: dict) -> tuple[bool, float, dict]:
    core = [s for s in signals if s["tactic"] and s["severity"] >= p["core_min_severity"] and not s["recurrent"]]
    tactics = {s["tactic"] for s in core}
    critical = any(s["severity"] >= p["critical_severity"] and not s["recurrent"] for s in signals)
    promote = len(tactics) >= p["min_tactics"] or (critical and p.get("promote_single_critical", False))
    progression = _longest_progression([s["tactic_order"] for s in core if s["tactic_order"] is not None])
    best_per_tactic = defaultdict(int)
    for s in core:
        best_per_tactic[s["tactic"]] = max(best_per_tactic[s["tactic"]], s["severity"])
    hosts = {s["host"] for s in signals}
    score = (40 * min(sum(best_per_tactic.values()) / 400, 1)
             + 30 * min(len(tactics), 6) / 6
             + 20 * min(progression, 6) / 6
             + 5 * min(len(hosts), 4) / 4
             + 5 * any(s["vendor_corroborated"] for s in signals))
    detail = {"tactics": sorted(tactics), "kill_chain_progression": progression, "critical": critical,
              "hosts": len(hosts)}
    return promote, round(score, 1), detail


def assemble(con, cfg: dict, edges: list[tuple[int, int, str]]) -> tuple[list[list[dict]], list[list[dict]]]:
    """Return (promoted incident signal-groups sorted by score, isolated groups)."""
    c, p = cfg["correlation"], cfg["promotion"]
    signals = {s["signal_id"]: s for s in dicts(
        con, f"SELECT {SIGNAL_COLS} FROM signals WHERE suppressed_reason IS NULL")}
    uf = _UF()
    for sid in signals:
        uf.find(sid)
    for a, b, _ in edges:
        if a in signals and b in signals:
            uf.union(a, b)
    comps: dict[int, list[dict]] = defaultdict(list)
    for sid, s in signals.items():
        comps[uf.find(sid)].append(s)
    promoted, isolated = [], []
    for group in comps.values():
        for sub in _split_oversized(group, c):
            sub.sort(key=lambda s: (s["ts_first_ms"], s["tactic_order"] or 99, s["signal_id"]))
            ok, score, detail = score_incident(sub, p)
            (promoted if ok else isolated).append((score, detail, sub))
    promoted.sort(key=lambda x: (-x[0], x[2][0]["ts_first_ms"]))
    isolated.sort(key=lambda x: (-x[0], x[2][0]["ts_first_ms"]))
    return promoted, isolated


def record_assignment(con, promoted, isolated, work_dir) -> None:
    """Persist signal -> incident assignment (used by the scorer and for drill-down)."""
    run(con, "CREATE OR REPLACE TABLE signal_incident (signal_id BIGINT, incident_id INTEGER, step INTEGER)")
    path = work_dir / "signal_incident.csv"
    with path.open("w") as fh:  # bulk load through CSV: executemany is too slow for millions of rows
        fh.write("signal_id,incident_id,step\n")
        for i, (_, _, sigs) in enumerate(promoted, start=1):
            for k, s in enumerate(sigs, start=1):
                fh.write(f"{s['signal_id']},{i},{k}\n")
        for _, _, sigs in isolated:
            for s in sigs:
                fh.write(f"{s['signal_id']},,\n")
    run(con, f"COPY signal_incident FROM {lit(path)} (HEADER true)")
    run(con, """
        CREATE OR REPLACE TABLE step_index AS
        SELECT unnest(s.event_ids) AS event_id, s.signal_id, si.incident_id, si.step, s.technique, s.tactic,
               s.ts_first_ms, s.suppressed_reason
        FROM signals s LEFT JOIN signal_incident si USING (signal_id)""")


def evidence_dict(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return {k: v for k, v in json.loads(raw).items() if v not in (None, "", [])}
    except (TypeError, ValueError):
        return {"raw": raw}
