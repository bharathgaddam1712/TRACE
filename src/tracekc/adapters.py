"""Bounded CSV / syslog adapters. ECS JSON stays in DuckDB's native parallel reader."""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
from pathlib import Path


ALIASES = {"timestamp": "@timestamp", "time": "@timestamp", "hostname": "host.name",
           "host": "host.name", "username": "user.name", "user": "user.name",
           "action": "event.action", "event_id": "event.id", "src_ip": "source.ip",
           "dst_ip": "destination.ip", "src_port": "source.port", "dst_port": "destination.port",
           "bytes": "network.bytes", "command_line": "process.command_line",
           "process_name": "process.name", "pid": "process.pid", "outcome": "event.outcome"}
ARRAYS = {"host.ip", "event.category", "event.type", "threat.technique.id", "threat.tactic.name",
          "registry.data.strings", "dns.resolved_ip"}
NUMBERS = {"source.port", "destination.port", "process.pid", "process.parent.pid", "network.bytes",
           "winlog.event_id", "event.severity", "file.size"}
SYSLOG = re.compile(r"^(?:<(?P<priority>\d{1,3})>)?(?:1\s+)?(?P<ts>\d{4}-\d\d-\d\dT\S+)\s+"
                    r"(?P<host>\S+)\s+(?P<message>.*)$")


def open_text(path: Path):
    return gzip.open(path, "rt", encoding="utf-8-sig") if path.suffix.lower() == ".gz" else path.open(encoding="utf-8-sig")


def input_format(path: Path, requested: str) -> str:
    if requested != "auto":
        if requested not in {"ecs", "csv", "syslog", "fortigate"}:
            raise ValueError(f"unsupported ingest.format: {requested}")
        return requested
    suffixes = [s.lower() for s in path.suffixes]
    if ".csv" in suffixes:
        return "csv"
    # Format sniffing must not decode a later corrupt record before the native
    # reader can quarantine it. Replacement characters are used only for sniffing.
    with (gzip.open(path,'rb') if path.suffix.lower()=='.gz' else path.open('rb')) as f:
        head = f.read(4096).decode('utf-8-sig',errors='replace').lstrip()
    if not head or head.startswith("{"):
        return "ecs"
    if re.match(r'(?:<\d+>)?date=\d{4}-\d\d-\d\d\s+time=', head) and 'devname=' in head:
        return 'fortigate'
    if SYSLOG.match(head.splitlines()[0]):
        return "syslog"
    raise ValueError(f"{path.name}: unrecognized format; expected ECS NDJSON, CSV, or timestamped syslog")


def _assign(event: dict, key: str, value: str) -> None:
    key = ALIASES.get(key.strip(), key.strip())
    if not value:
        return
    if key in ARRAYS:
        value = json.loads(value) if value.startswith("[") else [s.strip() for s in value.split(";")]
    elif key in NUMBERS:
        value = int(value)
    node = event
    parts = key.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def convert(path: Path, target: Path, fmt: str, max_record: int) -> dict:
    """Disk-stream adapter output, preserving parse failures with source/line/reason."""
    stats = {"format": fmt, "records": 0, "rejected_records": 0}
    rejects = target.with_suffix(".rejects.ndjson")
    csv.field_size_limit(max_record)
    with open_text(path) as source, target.open("w", encoding="utf-8") as dest, rejects.open("w", encoding="utf-8") as bad:
        if fmt == "csv":
            reader = csv.DictReader(source)
            for line, row in enumerate(reader, 2):
                try:
                    if None in row:
                        raise ValueError("CSV record has more fields than the header")
                    event = {}
                    for key, value in row.items():
                        _assign(event, key, value or "")
                    stats["records"] += 1
                    dest.write(json.dumps(event) + "\n")
                except (ValueError, TypeError, AttributeError) as exc:
                    stats["rejected_records"] += 1
                    bad.write(json.dumps({"source": str(path), "line": line, "reason": str(exc)}) + "\n")
        else:
            line = 0
            while True:
                raw = source.readline(max_record + 1)
                if not raw:
                    break
                line += 1
                match = SYSLOG.match(raw.rstrip()) if len(raw) <= max_record else None
                if not match:
                    while raw and not raw.endswith("\n"):
                        raw = source.readline(max_record + 1)
                    stats["rejected_records"] += 1
                    bad.write(json.dumps({"source": str(path), "line": line, "reason": "invalid or oversized timestamped syslog"}) + "\n")
                    continue
                event = {"@timestamp": match['ts'], "host": {"name": match['host']},
                         "event": {"kind": "event", "action": "syslog_message", "dataset": "syslog",
                                   "id": hashlib.sha256((str(path) + str(line) + raw).encode()).hexdigest()},
                         "message": match['message']}
                dest.write(json.dumps(event) + "\n")
                stats["records"] += 1
    if stats['records'] == 0:
        raise ValueError(f"{path.name}: no parsable records; inspect {rejects}")
    return stats
