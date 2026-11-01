"""DuckDB connection with memory cap, spill directory and shared SQL macros."""
from __future__ import annotations

import ipaddress
import os
import re
import time
import json
import hashlib
from pathlib import Path

import duckdb

_QUERY_PROFILES = {}


def _literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def connect(cfg: dict, db_file: Path, temp_dir: Path) -> duckdb.DuckDBPyConnection:
    temp_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_file))
    e = cfg["engine"]
    run(con, f"SET memory_limit={_literal(e['memory_limit'])}")
    threads = int(e.get("threads") or 0) or min(4, os.cpu_count() or 4)
    if not 1 <= threads <= 256:
        raise ValueError('engine.threads must be between 1 and 256 (or 0 for conservative auto)')
    run(con, f"SET threads={threads}")
    run(con, f"SET temp_directory={_literal(temp_dir)}")
    if e.get('max_temp_directory_size'):
        run(con, f"SET max_temp_directory_size={_literal(e['max_temp_directory_size'])}")
    run(con, "SET preserve_insertion_order=false")
    run(con, "SET TimeZone='UTC'")
    install_macros(con, cfg.get("internal_networks", []))
    if e.get('profile_queries',False):
        _QUERY_PROFILES[id(con)] = {'path':db_file.parent.parent/'query_timings.json', 'queries':{}}
    return con


def finish_query_profile(con):
    profile = _QUERY_PROFILES.pop(id(con),None)
    if profile:
        rows = sorted(profile['queries'].values(),key=lambda r:-r['seconds'])
        profile['path'].write_text(json.dumps({'note':'Wall time including result drain; not operator CPU time. SQL values/paths omitted.',
                                              'queries':rows},indent=2),encoding='utf-8')


def install_macros(con, internal_networks: list[str]) -> None:
    run(con, r"""
        CREATE OR REPLACE MACRO ipv4_int(ip) AS
        CASE WHEN regexp_full_match(CAST(ip AS VARCHAR), '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') THEN
          split_part(ip, '.', 1)::BIGINT * 16777216 + split_part(ip, '.', 2)::BIGINT * 65536
          + split_part(ip, '.', 3)::BIGINT * 256 + split_part(ip, '.', 4)::BIGINT
        END""")
    ranges = []
    for c in internal_networks:
        net = ipaddress.ip_network(c, strict=False)
        if net.version == 4:
            ranges.append(f"ipv4_int(ip) BETWEEN {int(net.network_address)} AND {int(net.broadcast_address)}")
    v4 = " OR ".join(ranges) or "FALSE"
    # IPv6: loopback, unique-local (fc00::/7) and link-local (fe80::/10) count as internal
    run(con, f"""
        CREATE OR REPLACE MACRO is_internal(ip) AS
        ip IS NOT NULL AND (({v4}) OR lower(ip) = '::1' OR regexp_matches(lower(ip), '^f[cd][0-9a-f]{{2}}:')
                            OR regexp_matches(lower(ip), '^fe[89ab][0-9a-f]:'))""")


def run(con, sql: str, params: list | None = None) -> list[tuple]:
    """Execute and always drain the result (DuckDB 2.x refuses new work while a result is open)."""
    profile = _QUERY_PROFILES.get(id(con))
    started = time.perf_counter()
    try:
        return con.execute(sql, params or []).fetchall()
    finally:
        if profile is not None:
            # Aggregate query shapes without persisting source paths or log values.
            shape = re.sub(r"'(?:''|[^'])*'", "?", sql)
            shape = re.sub(r'\s+',' ',shape).strip()
            key = hashlib.sha256(shape.encode()).hexdigest()[:16]
            row = profile['queries'].setdefault(key,{'query_id':key,'operation':shape.split(' ',1)[0],
                                                    'shape_preview':shape[:300], 'calls':0,'seconds':0.0})
            row['calls'] += 1
            row['seconds'] += time.perf_counter()-started


def one(con, sql: str, params: list | None = None) -> tuple:
    rows = run(con, sql, params)
    return rows[0] if rows else ()


def dicts(con, sql: str, params: list | None = None) -> list[dict]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def iter_dicts(con, sql: str, params: list | None = None, batch_size=1024):
    """Bound Python conversion memory; callers must close before another query.

    Drain on close as well: DuckDB 2.x rejects new work with a pending result.
    """
    if batch_size<1:raise ValueError('batch_size must be positive')
    cur=con.execute(sql,params or []);columns=[d[0] for d in cur.description]
    try:
        while rows:=cur.fetchmany(batch_size):
            for row in rows:yield dict(zip(columns,row))
    finally:
        while cur.fetchmany(batch_size):pass
