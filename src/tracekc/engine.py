"""DuckDB connection with memory cap, spill directory and shared SQL macros."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path

import duckdb


def connect(cfg: dict, db_file: Path, temp_dir: Path) -> duckdb.DuckDBPyConnection:
    temp_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_file))
    e = cfg["engine"]
    run(con, f"SET memory_limit='{e['memory_limit']}'")
    threads = int(e.get("threads") or 0) or os.cpu_count() or 4
    run(con, f"SET threads={threads}")
    run(con, f"SET temp_directory='{temp_dir}'")
    run(con, "SET preserve_insertion_order=false")
    run(con, "SET TimeZone='UTC'")
    install_macros(con, cfg.get("internal_networks", []))
    return con


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
    return con.execute(sql, params or []).fetchall()


def one(con, sql: str, params: list | None = None) -> tuple:
    rows = run(con, sql, params)
    return rows[0] if rows else ()


def dicts(con, sql: str, params: list | None = None) -> list[dict]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]
