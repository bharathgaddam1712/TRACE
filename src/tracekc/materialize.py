"""Stage 7: write API-ready JSON once, so opening an incident never runs a query (FR-5, B-1..B-3).

out/
  index.json               incidents sorted by risk score
  incidents/<id>.json      timeline, host path, graph, ATT&CK labels, look-ahead, narrative, evidence ids
  findings.json            isolated (non-promoted) findings, highest score first
  suppressed.json          audited suppressions
  signals.parquet / step_index.parquet   full detail for audit and scoring
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from tracekc.correlate import evidence_dict
from tracekc.engine import dicts, run
from tracekc.sigma import lit

MAX_FINDINGS_JSON = 2000


def iso(ms: int | None) -> str | None:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _is_external(ip: str | None, internal_hosts_ips: set[str]) -> bool:
    if not ip:
        return False
    if ip in internal_hosts_ips:
        return False
    return not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1$|f[cd]|fe[89ab])", ip)


def _host_role(host: str) -> str:
    h = host.upper()
    if "DC" in h:
        return "domain-controller"
    if h.startswith("SRV") or "SERVER" in h:
        return "server"
    return "workstation"


def _link(prev: dict, cur: dict, ext_ips: set[str]) -> tuple[list[str], str]:
    reasons, observed = [], False
    if cur["user_name"] and cur["user_name"] == prev["user_name"]:
        reasons.append(f"same account {cur['user_name']}")
    if cur["host"] == prev["host"]:
        reasons.append(f"same host {cur['host']}")
        observed = observed or (cur["user_name"] == prev["user_name"])
    if cur["src_host"] and cur["src_host"] == prev["host"] and cur["host"] != prev["host"]:
        reasons.append(f"logon from {prev['host']} to {cur['host']}")
        observed = True
    if prev["dst_host"] and prev["dst_host"] == cur["host"] and cur["host"] != prev["host"]:
        reasons.append(f"{prev['host']} connected to {cur['host']}")
        observed = True
    shared_ext = ({prev["src_ip"], prev["dst_ip"]} & {cur["src_ip"], cur["dst_ip"]}) & ext_ips
    for ip in sorted(shared_ext):
        reasons.append(f"same external address {ip}")
        observed = True
    return reasons, "observed" if observed else "inferred"


def _step(k: int, s: dict, n_ids: int) -> dict:
    return {
        "step": k, "signal_id": s["signal_id"], "ts": iso(s["ts_first_ms"]), "ts_last": iso(s["ts_last_ms"]),
        "title": s["title"], "technique": s["technique"], "technique_name": s["technique_name"],
        "tactic": s["tactic_name"], "kill_chain_stage": s["kill_chain_stage"], "lockheed_phase": s["lockheed_phase"],
        "mapping_source": s["mapping_source"], "mapping_version": s["mapping_version"], "severity": s["severity"],
        "host": s["host"], "user": s["user_name"], "src_ip": s["src_ip"], "src_host": s["src_host"],
        "dst_ip": s["dst_ip"], "dst_host": s["dst_host"], "dst_domain": s["dst_domain"],
        "merged_detections": s["n_detections"], "event_count": s["n_events"],
        "event_ids": list(s["event_ids"] or [])[:n_ids], "rule_ids": s["rule_ids"], "rule_sources": s["rule_sources"],
        "rule_authors": s["authors"], "vendor_corroborated": bool(s["vendor_corroborated"]),
        "evidence": evidence_dict(s["evidence"]),
    }


def _graph(sigs: list[dict], ext_ips: set[str], reach: dict) -> dict:
    nodes, edges = {}, {}

    def node(nid, label, ntype, **kw):
        nodes.setdefault(nid, {"id": nid, "label": label, "type": ntype, **kw})

    def edge(a, b, kind, step, technique):
        e = edges.setdefault((a, b, kind), {"source": a, "target": b, "kind": kind, "steps": [], "techniques": []})
        e["steps"].append(step)
        if technique and technique not in e["techniques"]:
            e["techniques"].append(technique)

    for k, s in enumerate(sigs, start=1):
        h = f"host:{s['host']}"
        node(h, s["host"], "host", role=_host_role(s["host"]), compromised=True)
        if s["user_name"]:
            node(f"user:{s['user_name']}", s["user_name"], "user")
            edge(f"user:{s['user_name']}", h, "acted_on", k, s["technique"])
        if s["src_host"] and s["src_host"] != s["host"]:
            node(f"host:{s['src_host']}", s["src_host"], "host", role=_host_role(s["src_host"]), compromised=True)
            edge(f"host:{s['src_host']}", h, "lateral", k, s["technique"])
        if s["src_ip"] in ext_ips:
            node(f"ip:{s['src_ip']}", s["src_ip"], "external")
            edge(f"ip:{s['src_ip']}", h, "inbound", k, s["technique"])
        if s["dst_ip"] in ext_ips:
            node(f"ip:{s['dst_ip']}", s["dst_domain"] or s["dst_ip"], "external")
            edge(h, f"ip:{s['dst_ip']}", "outbound", k, s["technique"])
        elif s["dst_host"] and s["dst_host"] != s["host"]:
            node(f"host:{s['dst_host']}", s["dst_host"], "host", role=_host_role(s["dst_host"]), compromised=True)
            edge(h, f"host:{s['dst_host']}", "connected", k, s["technique"])
    for r in reach.get("reachable", []):
        nid = f"host:{r['asset']}"
        node(nid, r["asset"], "host", role=_host_role(r["asset"]), compromised=False, potential=True)
        via = r["via"].split()[-1]
        src = f"user:{via}" if r["relation"] in ("CanLogon", "AdminTo") else f"host:{via}"
        if src in nodes:
            edges.setdefault((src, nid, "could_reach"), {"source": src, "target": nid, "kind": "could_reach",
                                                         "relation": r["relation"], "confidence": r["confidence"]})
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _host_path(sigs: list[dict]) -> list[str]:
    path = []
    for s in sigs:
        for h in (s["src_host"], s["host"]) if s["src_host"] and s["src_host"] != s["host"] else (s["host"],):
            if h and h not in path:
                path.append(h)
    return path


def _narrative(inc: dict) -> str:
    """Deterministic, grounded report: every sentence is built from fields in the incident JSON."""
    t = inc["timeline"]
    users = ", ".join(inc["entities"]["users"]) or "an unidentified account"
    lines = [f"Incident {inc['id']} (risk {inc['score']}/100): between {inc['first_seen']} and {inc['last_seen']} "
             f"TRACE linked {len(t)} suspicious steps ({inc['merged_alert_count']} raw alerts) across "
             f"{', '.join(inc['host_path']) or 'one host'} involving {users}. "
             f"ATT&CK tactics observed: {', '.join(inc['tactics']) or 'none mapped'}."]
    for s in t:
        who = f"account {s['user']}" if s["user"] else "an unknown account"
        tech = f"{s['technique_name']} ({s['technique']})" if s["technique"] else "an unmapped behaviour"
        where = s["host"]
        src = s["src_host"] if s["src_host"] and s["src_host"] != where else (s["src_ip"] if not s["src_host"] else None)
        extra = f" from {src}" if src else ""
        dest = f" towards {s['dst_domain'] or s['dst_ip']}" if s["dst_ip"] or s["dst_domain"] else ""
        link = f" [{s['link']['kind']}: {'; '.join(s['link']['reasons'])}]" if s.get("link") else ""
        lines.append(f"Step {s['step']} at {s['ts']}: {who} on {where}{extra}{dest} - {s['title']}; "
                     f"labelled {tech}, stage {s['kill_chain_stage'] or 'unmapped'}.{link}")
    la = inc["lookahead"]
    if la["reachable"]:
        top = ", ".join(f"{r['asset']} ({r['relation']} via {r['via']})" for r in la["reachable"][:3])
        lines.append(f"Look-ahead: with the access observed so far the attacker could next reach {top}.")
    else:
        lines.append("Look-ahead: unknown - " + ("; ".join(la["assumptions"]) or "no access evidence."))
    return "\n".join(lines)


def materialize(con, cfg: dict, out_dir: Path, promoted, isolated, graph) -> dict:
    inc_dir = out_dir / "incidents"
    inc_dir.mkdir(parents=True, exist_ok=True)
    for old in inc_dir.glob("*.json"):
        old.unlink()
    n_ids = int(cfg["output"]["evidence_events_in_json"])
    host_ips = {r[0] for r in run(con, "SELECT ip FROM ip_host")}
    index = []
    for inc_id, (score, detail, sigs) in enumerate(promoted, start=1):
        ext_ips = {ip for s in sigs for ip in (s["src_ip"], s["dst_ip"]) if _is_external(ip, host_ips)}
        steps = [_step(k, s, n_ids) for k, s in enumerate(sigs, start=1)]
        for i in range(1, len(sigs)):
            for j in range(i - 1, -1, -1):  # nearest earlier step that shares an entity
                reasons, kind = _link(sigs[j], sigs[i], ext_ips)
                if reasons:
                    steps[i]["link"] = {"from_step": j + 1, "reasons": reasons, "kind": kind}
                    break
            else:
                steps[i]["link"] = {"from_step": i, "reasons": ["time adjacency only"], "kind": "inferred"}
        users = sorted({s["user_name"] for s in sigs if s["user_name"]})
        hosts = sorted({h for s in sigs for h in (s["host"], s["src_host"], s["dst_host"]) if h})
        reach = graph.lookahead(set(users), set(hosts))
        path = _host_path(sigs)
        tactics = []
        for s in sigs:
            if s["tactic_name"] and s["tactic_name"] not in tactics:
                tactics.append(s["tactic_name"])
        inc = {
            "id": inc_id, "score": score,
            "title": f"{tactics[0] if tactics else 'Suspicious activity'} -> {tactics[-1] if tactics else ''} "
                     f"on {' -> '.join(path)}".replace(" ->  on", " on"),
            "first_seen": iso(sigs[0]["ts_first_ms"]), "last_seen": iso(max(s["ts_last_ms"] for s in sigs)),
            "tactics": tactics, "kill_chain_progression": detail["kill_chain_progression"],
            "techniques": sorted({(s["technique"], s["technique_name"], s["tactic_name"]) for s in sigs if s["technique"]}),
            "merged_alert_count": int(sum(s["n_detections"] for s in sigs)),
            "raw_event_count": int(sum(s["n_events"] for s in sigs)),
            "signal_count": len(sigs),
            "entities": {"users": users, "hosts": hosts, "external_ips": sorted(ext_ips)},
            "host_path": path, "host_path_text": " -> ".join(path),
            "timeline": steps, "lookahead": reach,
            "attribution": sorted({a for s in sigs for a in (s["authors"] or []) if a}),
        }
        inc["techniques"] = [{"id": t, "name": n, "tactic": tac} for t, n, tac in inc["techniques"]]
        inc["graph"] = _graph(sigs, ext_ips, reach)
        inc["narrative"] = _narrative(inc)
        (inc_dir / f"{inc_id}.json").write_text(json.dumps(inc, indent=1, default=str))
        index.append({k: inc[k] for k in ("id", "title", "score", "first_seen", "last_seen", "tactics",
                                          "merged_alert_count", "signal_count", "host_path_text")}
                     | {"users": users, "hosts": hosts})
    (out_dir / "index.json").write_text(json.dumps(index, indent=1))
    findings = []
    for score, detail, sigs in isolated:
        for s in sigs:
            findings.append({"score": score, **_step(0, s, 5)})
            if len(findings) >= MAX_FINDINGS_JSON:
                break
        if len(findings) >= MAX_FINDINGS_JSON:
            break
    (out_dir / "findings.json").write_text(json.dumps(
        {"total_isolated_signals": sum(len(g[2]) for g in isolated), "shown": len(findings), "findings": findings},
        indent=1, default=str))
    suppressed = dicts(con, "SELECT signal_id, title, technique, host, user_name, suppressed_reason, n_detections "
                            "FROM signals WHERE suppressed_reason IS NOT NULL")
    (out_dir / "suppressed.json").write_text(json.dumps(suppressed, indent=1, default=str))
    run(con, f"COPY signals TO {lit(out_dir / 'signals.parquet')} (FORMAT parquet)")
    run(con, f"COPY step_index TO {lit(out_dir / 'step_index.parquet')} (FORMAT parquet)")
    return {"incidents": len(index), "isolated_groups": len(isolated),
            "isolated_signals": sum(len(g[2]) for g in isolated)}
