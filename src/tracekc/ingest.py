"""PASS 1: stream raw NDJSON (ECS) logs once, normalize, write compact Parquet.

Nothing here pulls raw rows into Python: DuckDB reads the files in parallel, projects only the
columns below, spills to disk under memory pressure and writes zstd Parquet.
"""
from __future__ import annotations

import logging
from pathlib import Path

from tracekc.engine import one, run
from tracekc.sigma import lit

log = logging.getLogger(__name__)

# Explicit schema: no inference pass over 50 GB, and unknown keys are ignored.
ECS_COLUMNS = {
    "@timestamp": "VARCHAR",
    "event": "STRUCT(id VARCHAR, kind VARCHAR, category VARCHAR[], type VARCHAR[], action VARCHAR, "
             "severity INTEGER, module VARCHAR, dataset VARCHAR, outcome VARCHAR)",
    "host": "STRUCT(name VARCHAR, hostname VARCHAR, ip VARCHAR[], os STRUCT(type VARCHAR))",
    "user": "STRUCT(name VARCHAR, domain VARCHAR)",
    "process": "STRUCT(pid BIGINT, name VARCHAR, executable VARCHAR, command_line VARCHAR, entity_id VARCHAR, "
               "parent STRUCT(pid BIGINT, name VARCHAR))",
    "source": "STRUCT(ip VARCHAR, port INTEGER)",
    "destination": "STRUCT(ip VARCHAR, port INTEGER, domain VARCHAR)",
    "network": "STRUCT(transport VARCHAR, direction VARCHAR, protocol VARCHAR, bytes BIGINT)",
    "dns": "STRUCT(question STRUCT(name VARCHAR, type VARCHAR), response_code VARCHAR, resolved_ip VARCHAR[])",
    "file": "STRUCT(path VARCHAR, name VARCHAR, size BIGINT, extension VARCHAR)",
    "registry": "STRUCT(path VARCHAR, data STRUCT(strings VARCHAR[]))",
    "winlog": "STRUCT(event_id INTEGER, logon STRUCT(type VARCHAR))",
    "threat": "STRUCT(framework VARCHAR, technique STRUCT(id VARCHAR[], name VARCHAR[]), tactic STRUCT(name VARCHAR[]))",
    "rule": "STRUCT(id VARCHAR, name VARCHAR, severity VARCHAR)",
    "labels": "STRUCT(synthetic VARCHAR, simulated_detection VARCHAR)",
    "labels_extra": "STRUCT(failed_count_5min BIGINT, files_renamed_60s BIGINT)",
}

NORMALIZE_SQL = r"""
SELECT
  coalesce(event.id, md5(concat_ws('|', filename, "@timestamp", host.name, event.action,
           CAST(process.pid AS VARCHAR), source.ip, destination.ip, file.path, registry.path))) AS event_id,
  epoch_ms(try_cast("@timestamp" AS TIMESTAMPTZ)) AS ts_ms,
  lower(event.kind) AS kind,
  lower(event.dataset) AS dataset,
  lower(event.action) AS action,
  lower(event.category[1]) AS category,
  lower(event.outcome) AS outcome,
  event.severity AS vendor_severity,
  nullif(upper(split_part(coalesce(host.name, host.hostname), '.', 1)), '') AS host,
  host.ip AS host_ips,
  lower(host.os.type) AS os_type,
  nullif(lower(regexp_replace(user.name, '^.*\\|@.*$', '', 'g')), '') AS user_name,
  user.domain AS user_domain,
  source.ip AS src_ip, source.port AS src_port,
  destination.ip AS dst_ip, destination.port AS dst_port, lower(destination.domain) AS dst_domain,
  lower(network.direction) AS direction, lower(network.protocol) AS net_protocol,
  lower(network.transport) AS net_transport, network.bytes AS net_bytes,
  lower(process.name) AS proc_name, process.pid AS proc_pid, process.command_line AS proc_cmd,
  process.executable AS proc_exe, process.entity_id AS proc_entity_id,
  lower(process.parent.name) AS parent_name, process.parent.pid AS parent_pid,
  file.path AS file_path, file.name AS file_name, lower(file.extension) AS file_ext, file.size AS file_size,
  registry.path AS reg_path, array_to_string(registry.data.strings, ';') AS reg_data,
  lower(dns.question.name) AS dns_name,
  winlog.event_id AS win_event_id, lower(winlog.logon.type) AS logon_type,
  rule.id AS vendor_rule_id, rule.name AS vendor_rule_name, lower(rule.severity) AS vendor_rule_severity,
  threat.technique.id AS vendor_techniques, threat.tactic.name AS vendor_tactics,
  coalesce(labels.simulated_detection = 'true', FALSE) AS gt_label,
  labels_extra.failed_count_5min AS failed_count, labels_extra.files_renamed_60s AS renamed_count,
  filename AS src_file
FROM raw
"""


def find_inputs(input_dir: Path, patterns: list[str]) -> list[Path]:
    if input_dir.is_file():
        return [input_dir]
    files = {p for pat in patterns for p in input_dir.rglob(pat) if p.is_file()}
    return sorted(files)


def ingest(con, cfg: dict, input_dir: Path, work_dir: Path) -> dict:
    files = find_inputs(input_dir, cfg["ingest"]["patterns"])
    if not files:
        raise FileNotFoundError(f"no input files matching {cfg['ingest']['patterns']} under {input_dir}")
    file_list = "[" + ", ".join(lit(f) for f in files) + "]"
    columns = "{" + ", ".join(f"{lit(k)}: {lit(v)}" for k, v in ECS_COLUMNS.items()) + "}"
    run(con, f"""
        CREATE OR REPLACE VIEW raw AS
        SELECT * FROM read_json({file_list}, format='newline_delimited', columns={columns},
                                filename=true, ignore_errors=true, compression='auto',
                                maximum_object_size={int(cfg['ingest']['maximum_object_size'])})""")
    events_path = work_dir / "events.parquet"
    dedupe = "QUALIFY row_number() OVER (PARTITION BY event_id ORDER BY ts_ms) = 1" \
        if cfg["ingest"].get("dedupe_events", True) else ""
    run(con, f"""
        COPY (SELECT * FROM ({NORMALIZE_SQL}) n {dedupe})
        TO {lit(events_path)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 122880)""")
    run(con, f"CREATE OR REPLACE VIEW events_all AS SELECT * FROM read_parquet({lit(events_path)})")
    # quarantine: rows we cannot place in time or on a host are counted, kept, and excluded downstream
    run(con, "CREATE OR REPLACE VIEW events AS SELECT * FROM events_all WHERE ts_ms IS NOT NULL AND host IS NOT NULL")
    run(con, "CREATE OR REPLACE VIEW bad_rows AS SELECT * FROM events_all WHERE ts_ms IS NULL OR host IS NULL")
    # entity resolution: IP -> host (most frequent owner), used to name the source/destination host
    run(con, """
        CREATE OR REPLACE TABLE ip_host AS
        SELECT ip, host FROM (
          SELECT ip, host, count(*) AS n
          FROM (SELECT unnest(host_ips) AS ip, host FROM events WHERE host_ips IS NOT NULL)
          WHERE ip IS NOT NULL GROUP BY ALL)
        QUALIFY row_number() OVER (PARTITION BY ip ORDER BY n DESC, host) = 1""")
    run(con, """
        CREATE OR REPLACE VIEW ev AS
        SELECT e.*, sh.host AS src_host, dh.host AS dst_host
        FROM events e
        LEFT JOIN ip_host sh ON e.src_ip = sh.ip
        LEFT JOIN ip_host dh ON e.dst_ip = dh.ip""")
    total, bad, tmin, tmax = one(
        con, "SELECT count(*), count(*) FILTER (WHERE ts_ms IS NULL OR host IS NULL), min(ts_ms), max(ts_ms) FROM events_all")
    stats = {
        "input_files": len(files),
        "input_bytes": sum(f.stat().st_size for f in files),
        "events": int(total),
        "quarantined_rows": int(bad),
        "ts_min_ms": tmin, "ts_max_ms": tmax,
        "hosts_with_ips": one(con, "SELECT count(DISTINCT host) FROM ip_host")[0],
        "parquet_bytes": events_path.stat().st_size,
    }
    log.info("ingested %s events from %s files (%s quarantined)", total, len(files), bad)
    return stats
