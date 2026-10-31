"""Test data: a planted, coherent attack chain with ground truth, and a scale-up generator.

The organiser's 100 MB sample has scattered single alerts but no linked chain, so the end-to-end
test plants the PRD's story (password guessing -> foothold -> persistence -> C2 -> lateral -> exfil)
in the same ECS/SimEDR shape and checks it is rebuilt in order.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

AGENT = {"type": "edr", "name": "SimEDR", "version": "1.0"}
OBSERVER = {"vendor": "Mitigata", "product": "SimEDR", "version": "1.0"}
HOSTS = {
    "WS-HR-012": ("10.10.2.12", "windows", "Windows 11 Enterprise 23H2"),
    "SRV-FILE-01": ("10.10.0.20", "windows", "Windows Server 2022"),
}


def _ts(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _base(t: datetime, host: str, user: str, category: str, etype: str, action: str, dataset: str, **event) -> dict:
    ip, ostype, osfull = HOSTS[host]
    return {
        "@timestamp": _ts(t),
        "event": {"id": str(uuid.uuid4()), "kind": "event", "category": [category], "type": [etype],
                  "action": action, "severity": 0, "module": "edr", "dataset": dataset, **event},
        "agent": {"id": uuid.uuid4().hex[:16], **AGENT}, "observer": OBSERVER,
        "host": {"name": host, "hostname": host, "ip": [ip], "os": {"type": ostype, "full": osfull}},
        "user": {"name": user, "domain": "CORP"},
    }


def planted_chain(start: datetime, user: str = "asharma", attacker_ip: str = "203.0.113.99",
                  attack_id: str = "planted-1") -> tuple[list[dict], dict]:
    """Return (events, ground_truth) for one six-step attack."""
    ws, fs = "WS-HR-012", "SRV-FILE-01"
    steps: list[tuple[str, list[dict]]] = []

    s1 = []
    for i in range(30):  # step 1: password guessing over RDP from the internet, then success
        e = _base(start + timedelta(seconds=6 * i), ws, user, "authentication", "start", "user_logon",
                  "edr.authentication", outcome="failure")
        e["winlog"] = {"event_id": 4625, "logon": {"type": "RemoteInteractive"}}
        e["source"] = {"ip": attacker_ip}
        s1.append(e)
    e = _base(start + timedelta(minutes=3, seconds=10), ws, user, "authentication", "start", "user_logon",
              "edr.authentication", outcome="success")
    e["winlog"] = {"event_id": 4624, "logon": {"type": "RemoteInteractive"}}
    e["source"] = {"ip": attacker_ip}
    s1.append(e)
    steps.append(("T1110", s1))

    e = _base(start + timedelta(minutes=6), ws, user, "process", "start", "process_created", "edr.process")
    e["process"] = {"pid": 7311, "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
                    "parent": {"pid": 6120, "name": "winword.exe"}, "entity_id": str(uuid.uuid4())}
    steps.append(("T1059.001", [e]))

    e = _base(start + timedelta(minutes=7), ws, user, "registry", "change", "registry_value_set", "edr.registry")
    e["registry"] = {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync",
                     "data": {"strings": ["%AppData%\\odsync.exe"]}}
    e["process"] = {"pid": 7311, "name": "powershell.exe"}
    steps.append(("T1547.001", [e]))

    s4 = []
    for i in range(5):  # step 4: beaconing every minute
        e = _base(start + timedelta(minutes=8 + i), ws, user, "network", "connection", "network_connection",
                  "edr.network")
        e["process"] = {"pid": 7311, "name": "powershell.exe"}
        e["source"] = {"ip": HOSTS[ws][0], "port": 50110 + i}
        e["destination"] = {"ip": attacker_ip, "port": 443, "domain": "cdn-update.example-c2.net"}
        e["network"] = {"transport": "tcp", "direction": "outbound", "protocol": "https", "bytes": 3100 + i}
        s4.append(e)
    steps.append(("T1071.001", s4))

    e = _base(start + timedelta(minutes=20), fs, user, "authentication", "start", "user_logon", "edr.authentication",
              outcome="success")
    e["winlog"] = {"event_id": 4624, "logon": {"type": "RemoteInteractive"}}
    e["source"] = {"ip": HOSTS[ws][0]}
    steps.append(("T1021.001", [e]))

    s6 = []
    for i in range(5):  # step 6: 650 MB out to the same attacker infrastructure
        e = _base(start + timedelta(minutes=30, seconds=40 * i), fs, user, "network", "connection",
                  "network_connection", "edr.network")
        e["process"] = {"pid": 9020, "name": "rclone.exe"}
        e["source"] = {"ip": HOSTS[fs][0], "port": 51000 + i}
        e["destination"] = {"ip": attacker_ip, "port": 443, "domain": "files.drop-example.net"}
        e["network"] = {"transport": "tcp", "direction": "outbound", "protocol": "https", "bytes": 130_000_000}
        s6.append(e)
    steps.append(("T1048", s6))

    events = [e for _, evs in steps for e in evs]
    gt = {"attacks": [{"attack_id": attack_id, "description": "password guess -> macro -> run key -> C2 -> RDP -> exfil",
                       "steps": [{"step": k, "technique": tech, "event_ids": [e["event"]["id"] for e in evs]}
                                 for k, (tech, evs) in enumerate(steps, start=1)]}]}
    return events, gt


def write_planted(out_dir: Path, start: datetime | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    start = start or datetime(2026, 10, 31, 9, 0, 0, tzinfo=timezone.utc)
    events, gt = planted_chain(start)
    ev_path, gt_path = out_dir / "planted_chain.json", out_dir / "planted_gt.json"
    ev_path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events))
    gt_path.write_text(json.dumps(gt, indent=1))
    return ev_path, gt_path


_ID = re.compile(r'"id":"[0-9a-f-]{36}"')
_TS = re.compile(r'"@timestamp":"([^"]+)"')
_PID = re.compile(r'"pid":(\d+)')


def scale_up(sample: Path, out_dir: Path, target_gb: float, span_hours: float = 8.0,
             file_mb: int = 1024, plant: bool = True) -> dict:
    """Replicate the sample to roughly target_gb of NDJSON for load tests (fresh event ids, timestamps
    spread over span_hours). Optionally plants one attack chain mid-way and writes its ground truth."""
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = sample.read_text(encoding="utf-8-sig").splitlines()
    sample_bytes = sum(len(x) + 1 for x in lines)
    copies = max(1, int(target_gb * 1024 ** 3 / sample_bytes))
    t0 = datetime(2026, 10, 31, 0, 0, tzinfo=timezone.utc)
    step_ms = span_hours * 3_600_000 / copies
    written, part, fh, file_bytes = 0, 0, None, 0
    plant_at = copies // 2 if plant else -1
    for c in range(copies):
        if fh is None or file_bytes >= file_mb * 1024 ** 2:
            if fh:
                fh.close()
            fh = (out_dir / f"edr_{part:04d}.json").open("w")
            part, file_bytes = part + 1, 0
        base = t0 + timedelta(milliseconds=c * step_ms)
        stamp = _ts(base)
        prefix = f"{c:08x}"
        buf = []
        shift = (c * 7919) % 60000  # fresh process ids per copy: real hosts do not reuse pids like a replay would
        for ln in lines:
            ln = _ID.sub(lambda m: '"id":"' + prefix + m.group(0)[14:], ln, count=1)
            ln = _PID.sub(lambda m: f'"pid":{(int(m.group(1)) + shift) % 65536 + 4}', ln)
            buf.append(_TS.sub(f'"@timestamp":"{stamp}"', ln, count=1))
        chunk = "\n".join(buf) + "\n"
        fh.write(chunk)
        file_bytes += len(chunk)
        written += len(chunk)
        if c == plant_at:
            events, gt = planted_chain(base)
            fh.write("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events))
            (out_dir.parent / f"{out_dir.name}_gt.json").write_text(json.dumps(gt, indent=1))
    if fh:
        fh.close()
    return {"copies": copies, "bytes": written, "files": part}
