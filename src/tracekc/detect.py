"""PASS 2: detections.

Four families, all executed inside DuckDB:
  sigma    - every single-event Sigma rule is evaluated in ONE scan of the events (combined predicate)
  sigma correlation - event_count / value_count / temporal_ordered over the matched rows
  vendor   - EDR alert rows (kind=alert) that our rules did not already cover
  builtin  - first-seen lateral logon, unusual outbound volume, rare process lineage
Several rules firing on the same event collapse into one detection (highest severity wins).
"""
from __future__ import annotations

import logging

from tracekc.engine import one, run
from tracekc.sigma import ENTITY_COLS, LOGSOURCE, Rule, emitting_rule_ids, lit, relation_sql
import re

log = logging.getLogger(__name__)

ENT = ", ".join(ENTITY_COLS)

EVIDENCE_SQL = """to_json({
  'action': action, 'outcome': outcome, 'logon_type': logon_type, 'cmd': proc_cmd, 'parent': parent_name,
  'process_entity_id': proc_entity_id, 'process_pid': proc_pid, 'parent_entity_id': parent_entity_id,
  'parent_pid': parent_pid, 'process_name': proc_name,
  'message': message, 'dataset': dataset, 'vendor_rule': vendor_rule_name,
  'exe': proc_exe, 'registry': reg_path, 'registry_data': reg_data, 'file': file_path, 'dns': dns_name,
  'dst_domain': dst_domain, 'dst_port': dst_port, 'bytes': net_bytes, 'failed_count': failed_count,
  'renamed_count': renamed_count, 'win_event_id': win_event_id, 'src_file': src_file})::VARCHAR"""

DETECTIONS_DDL = """
CREATE OR REPLACE TABLE detections (
  det_id VARCHAR, rule_id VARCHAR, rule_ids VARCHAR[], rule_title VARCHAR, rule_source VARCHAR,
  technique VARCHAR, techniques VARCHAR[], tactic_hint VARCHAR, severity INTEGER, author VARCHAR,
  ts_first_ms BIGINT, ts_last_ms BIGINT,
  host VARCHAR, user_name VARCHAR, src_ip VARCHAR, dst_ip VARCHAR, src_host VARCHAR, dst_host VARCHAR,
  dst_domain VARCHAR, proc_name VARCHAR, proc_pid BIGINT,
  event_count BIGINT, event_ids VARCHAR[], evidence VARCHAR, vendor_corroborated BOOLEAN)"""

VENDOR_SEVERITY = "CASE vendor_rule_severity WHEN 'critical' THEN 100 WHEN 'high' THEN 75 WHEN 'medium' THEN 50 " \
                  "WHEN 'low' THEN 25 ELSE greatest(10, least(100, coalesce(vendor_severity, 5) * 10)) END"


def _register_rules(con, rules: dict[str, Rule]) -> None:
    emit = emitting_rule_ids(rules)
    run(con, """CREATE OR REPLACE TABLE rules_meta (rule_id VARCHAR, title VARCHAR, kind VARCHAR,
                technique VARCHAR, techniques VARCHAR[], tactic_hint VARCHAR, severity INTEGER,
                author VARCHAR, emit BOOLEAN)""")
    if rules:
        run(con,'BEGIN TRANSACTION')
        try:
            con.executemany('INSERT INTO rules_meta VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [[r.id,r.title,r.kind,r.techniques[0] if r.techniques else None,r.techniques,r.tactic_hint,r.severity,r.author,r.id in emit] for r in rules.values()])
            run(con,'COMMIT')
        except Exception:
            run(con,'ROLLBACK')
            raise


def _rule_hits(con, rules: dict[str, Rule], batch_size: int = 16) -> int:
    base = [r for r in rules.values() if r.kind == "base"]
    actions={row[0] for row in run(con,'SELECT DISTINCT action FROM ev')}
    os_types={row[0] for row in run(con,'SELECT DISTINCT os_type FROM ev WHERE os_type IS NOT NULL')}
    has_windows='windows' in os_types or one(con,'SELECT count(*) FROM ev WHERE win_event_id IS NOT NULL')[0]>0
    def applicable(rule):
        if rule.logsource.get('product')=='windows' and not has_windows:return False
        if rule.logsource.get('product')=='linux' and 'linux' not in os_types:return False
        scope=LOGSOURCE.get(('category',rule.logsource.get('category','')))
        matched=re.fullmatch(r"action = '([^']+)'",scope or '')
        return not matched or matched.group(1) in actions
    base=[r for r in base if applicable(r)]
    run(con,'CREATE OR REPLACE TABLE evaluated_rules (rule_id VARCHAR)')
    if base:
        con.executemany('INSERT INTO evaluated_rules VALUES (?)',[(r.id,) for r in base])
    if not base:
        run(con, f"CREATE OR REPLACE TABLE rule_hits AS SELECT event_id, ts_ms, {ENT}, "
                 f"NULL::VARCHAR AS evidence, []::VARCHAR[] AS hits FROM ev WHERE FALSE")
        return 0
    # Bound SQL planner memory and compilation time as community coverage grows.
    run(con, f"CREATE OR REPLACE TABLE raw_rule_hits AS SELECT event_id, ts_ms, {ENT}, "
             f"NULL::VARCHAR AS evidence, []::VARCHAR[] AS hits FROM ev WHERE FALSE")
    base.sort(key=lambda rule:(str(rule.logsource),rule.id))
    for offset in range(0,len(base),batch_size):
        batch=base[offset:offset+batch_size]
        cases = ",\n      ".join(f"CASE WHEN {r.where} THEN {lit(r.id)} END" for r in batch)
        any_match = "\n   OR ".join(f"({r.where})" for r in batch)
        run(con, f"""INSERT INTO raw_rule_hits
            SELECT event_id,ts_ms,{ENT},{EVIDENCE_SQL} AS evidence,list_distinct([{cases}]) AS hits
            FROM ev WHERE {any_match}""")
    run(con, f"""CREATE OR REPLACE TABLE rule_hits AS
        SELECT event_id,any_value(ts_ms) AS ts_ms,
               {', '.join(f'any_value({column}) AS {column}' for column in ENTITY_COLS)},
               any_value(evidence) AS evidence,list_distinct(flatten(list(hits))) AS hits
        FROM raw_rule_hits GROUP BY event_id""")
    return one(con, "SELECT count(*) FROM rule_hits")[0]


def _single_event_detections(con) -> None:
    run(con, f"""
        INSERT INTO detections
        SELECT * FROM (
          WITH x AS (SELECT event_id, unnest(hits) AS rule_id FROM rule_hits),
          m AS (SELECT x.event_id, r.rule_id, r.severity, r.techniques FROM x JOIN rules_meta r USING (rule_id) WHERE r.emit),
          agg AS (SELECT event_id, arg_max(rule_id, (starts_with(rule_id,'trace-'),severity,rule_id)) AS rule_id,
                         list(rule_id ORDER BY severity DESC, rule_id) AS rule_ids, max(severity) AS severity,
                         list_distinct(flatten(list(techniques))) AS techniques
                  FROM m GROUP BY event_id)
          SELECT md5('ev|' || h.event_id), a.rule_id, a.rule_ids, r.title, 'sigma', r.technique, a.techniques,
                 r.tactic_hint, a.severity, r.author, h.ts_ms, h.ts_ms, {", ".join("h." + c for c in ENTITY_COLS)},
                 1, [h.event_id], h.evidence, FALSE
          FROM agg a JOIN rules_meta r USING (rule_id) JOIN rule_hits h USING (event_id))""")


def _correlation_detections(con, rules: dict[str, Rule], cap: int) -> None:
    emit = emitting_rule_ids(rules)
    for r in rules.values():
        if r.kind != "correlation" or r.id not in emit:
            continue
        rel = relation_sql(r.id, rules, cap)
        run(con, f"""
            INSERT INTO detections
            SELECT md5({lit(r.id)} || '|' || ts_first_ms || '|' || concat_ws('|', {ENT})),
                   {lit(r.id)}, [{lit(r.id)}], {lit(r.title)}, 'sigma_correlation',
                   {lit(r.techniques[0]) if r.techniques else 'NULL'}, {_list_lit(r.techniques)},
                   {lit(r.tactic_hint) if r.tactic_hint else 'NULL'}, {r.severity}, {lit(r.author)},
                   ts_first_ms, ts_last_ms, {ENT}, event_count, event_ids,
                   to_json({{'event_count': event_count, 'correlation': {lit(r.corr['type'])}}})::VARCHAR, FALSE
            FROM ({rel}) c""")


def _list_lit(items: list[str]) -> str:
    return "[" + ", ".join(lit(x) for x in items) + "]::VARCHAR[]"


def _vendor_detections(con, use_vendor: bool) -> None:
    # EDR alerts our rules already matched only corroborate; the rest become detections of their own.
    run(con, """
        UPDATE detections SET vendor_corroborated = TRUE
        WHERE rule_source = 'sigma'
          AND event_ids[1] IN (SELECT event_id FROM ev WHERE kind = 'alert')""")
    if not use_vendor:
        return
    run(con, f"""
        INSERT INTO detections
        SELECT md5('vendor|' || event_id), 'vendor:' || coalesce(vendor_rule_id, 'unknown'),
               ['vendor:' || coalesce(vendor_rule_id, 'unknown')], coalesce(vendor_rule_name, 'EDR alert'), 'vendor',
               upper(vendor_techniques[1]), list_transform(vendor_techniques, lambda t: upper(t)),
               replace(lower(vendor_tactics[1]), ' ', '-'), {VENDOR_SEVERITY}, 'EDR vendor',
               ts_ms, ts_ms, {ENT}, 1, [event_id], {EVIDENCE_SQL}, TRUE
        FROM ev
        WHERE kind = 'alert'
          AND event_id NOT IN (SELECT event_ids[1] FROM detections WHERE rule_source = 'sigma')""")


def _lateral(con, c: dict) -> None:
    types = ", ".join(lit(t.lower()) for t in c["logon_types"])
    run(con, f"""
        INSERT INTO detections
        SELECT * FROM (
          WITH s AS (SELECT * FROM ev WHERE action = 'user_logon' AND outcome = 'success'
                     AND src_host IS NOT NULL AND src_host <> host AND logon_type IN ({types})),
          p AS (SELECT user_name, src_host, host, count(*) AS n FROM s GROUP BY ALL)
          SELECT md5('lat|' || s.event_id), 'trace-lateral-first-seen', ['trace-lateral-first-seen'],
                 'First-seen remote logon from another internal host', 'builtin',
                 CASE WHEN s.logon_type IN ('remoteinteractive', '10') THEN 'T1021.001'
                      WHEN s.logon_type IN ('network', '3') THEN 'T1021.002' ELSE 'T1021' END,
                 NULL::VARCHAR[], 'lateral-movement', 25, 'TRACE builtin',
                 s.ts_ms, s.ts_ms, {", ".join("s." + x for x in ENTITY_COLS)}, 1, [s.event_id],
                 {EVIDENCE_SQL}, FALSE
          FROM s JOIN p USING (user_name, src_host, host)
          WHERE p.n <= {int(c['max_pair_count'])}
            -- pivot evidence: the source host or the account already shows medium+ activity shortly before
            AND EXISTS (SELECT 1 FROM detections d
                        WHERE d.severity >= 50 AND (d.host = s.src_host OR d.user_name = s.user_name)
                          AND d.ts_first_ms BETWEEN s.ts_ms - {int(c['pivot_lookback_s']) * 1000} AND s.ts_ms))""")


def _volume(con, c: dict, cap: int) -> None:
    run(con, f"""
        INSERT INTO detections
        SELECT * FROM (
          WITH f AS (
            SELECT host, dst_ip, ts_ms // 3600000 AS bucket, any_value(dst_domain) AS dst_domain,
                   arg_max(user_name, net_bytes) AS user_name, arg_max(proc_name, net_bytes) AS proc_name,
                   arg_max(proc_pid, net_bytes) AS proc_pid,
                   any_value(src_ip) AS src_ip, any_value(src_host) AS src_host, any_value(dst_host) AS dst_host,
                   sum(net_bytes) AS total, count(*) AS n, min(ts_ms) AS t0, max(ts_ms) AS t1,
                   list(event_id ORDER BY net_bytes DESC)[1:{cap}] AS ids
            FROM ev
            WHERE action = 'network_connection' AND net_bytes IS NOT NULL AND dst_ip IS NOT NULL
              AND coalesce(direction, 'outbound') = 'outbound' AND NOT is_internal(dst_ip)
            GROUP BY host, dst_ip, bucket),
          pop AS (SELECT dst_ip, count(DISTINCT host) AS hosts FROM f GROUP BY dst_ip),
          st AS (SELECT median(total) AS med FROM f),
          mad AS (SELECT median(abs(total - st.med)) AS mad FROM f, st),
          hs AS (SELECT host, median(total) AS med, count(*) AS samples FROM f GROUP BY host),
          hm AS (SELECT f.host, median(abs(f.total - hs.med)) AS mad FROM f JOIN hs USING (host) GROUP BY f.host),
          baseline AS (SELECT hs.host,
            CASE WHEN samples >= 5 THEN hs.med ELSE st.med END AS med,
            CASE WHEN samples >= 5 THEN hm.mad ELSE mad.mad END AS mad,
            CASE WHEN samples >= 5 THEN 'host' ELSE 'fleet_fallback' END AS scope
            FROM hs JOIN hm USING (host), st, mad)
          SELECT md5('vol|' || f.host || '|' || f.dst_ip || '|' || f.bucket), 'trace-outbound-volume',
                 ['trace-outbound-volume'], 'Unusually large outbound transfer to a rare external destination',
                 'builtin', {lit(c['technique'])}, [{lit(c['technique'])}], 'exfiltration', 50, 'TRACE builtin',
                 f.t0, f.t1, f.host, f.user_name, f.src_ip, f.dst_ip, f.src_host, f.dst_host, f.dst_domain,
                 f.proc_name, f.proc_pid, f.n, f.ids,
                 to_json({{'bytes_total': f.total, 'connections': f.n, 'baseline_scope': baseline.scope, 'threshold_bytes':
                           greatest({int(c['min_bytes'])}, baseline.med + {float(c['mad_k'])} * baseline.mad)}})::VARCHAR, FALSE
          FROM f JOIN pop USING (dst_ip) JOIN baseline USING (host)
          WHERE pop.hosts <= 3 AND f.total >= {int(c['min_bytes'])}
            AND f.total > baseline.med + {float(c['mad_k'])} * baseline.mad)""")


def _rarity(con, c: dict) -> None:
    run(con, f"""
        INSERT INTO detections
        SELECT * FROM (
          WITH p AS (SELECT parent_name, proc_name, count(*) AS n FROM ev
                     WHERE action = 'process_created' AND parent_name IS NOT NULL AND proc_name IS NOT NULL
                     GROUP BY ALL),
          tot AS (SELECT sum(n) AS t FROM p)
          SELECT md5('rare|' || e.event_id), 'trace-rare-process-lineage', ['trace-rare-process-lineage'],
                 'Rare parent->child process pair across the fleet', 'builtin', NULL, NULL::VARCHAR[], NULL, 25,
                 'TRACE builtin', e.ts_ms, e.ts_ms, {", ".join("e." + x for x in ENTITY_COLS)}, 1, [e.event_id],
                 to_json({{'parent': e.parent_name, 'child': e.proc_name, 'cmd': e.proc_cmd,
                           'fleet_count': p.n}})::VARCHAR, FALSE
          FROM ev e JOIN p USING (parent_name, proc_name), tot
          WHERE e.action = 'process_created' AND p.n <= {int(c['max_fleet_count'])}
            AND tot.t >= {int(c['min_process_events'])})""")


def detect(con, cfg: dict, rules: dict[str, Rule]) -> dict:
    d = cfg["detection"]
    cap = int(d["max_event_ids"])
    run(con, DETECTIONS_DDL)
    _register_rules(con, rules)
    hits = _rule_hits(con, rules, max(1,min(128,int(d.get('rules_sql_batch_size',16)))))
    _single_event_detections(con)
    _correlation_detections(con, rules, cap)
    _vendor_detections(con, bool(d.get("use_vendor_alerts", True)))
    if d["lateral"]["enabled"]:
        _lateral(con, d["lateral"])
    if d["volume"]["enabled"]:
        _volume(con, d["volume"], cap)
    if d["rarity"]["enabled"]:
        _rarity(con, d["rarity"])
    by_source = dict(run(con, "SELECT rule_source, count(*) FROM detections GROUP BY 1 ORDER BY 1"))
    by_rule = dict(run(con, "SELECT rule_id, count(*) FROM detections GROUP BY 1 ORDER BY 2 DESC"))
    log.info("detections by source: %s", by_source)
    return {"rule_hit_events": hits, "detections_by_source": by_source, "detections_by_rule": by_rule,
            'base_rules_evaluated':one(con,'SELECT count(*) FROM evaluated_rules')[0],
            'base_rules_loaded':sum(r.kind=='base' for r in rules.values()),
            'applicability_note':'Rules for absent declared event actions are pruned; other rules are still evaluated.'}
