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
import hashlib
import os
import time
from collections import defaultdict
from functools import lru_cache
from itertools import groupby
from tracekc.graph_algorithms import link_decision
from datetime import datetime, timezone
from pathlib import Path

from tracekc.correlate import evidence_dict, SIGNAL_COLS
from tracekc.engine import dicts, iter_dicts, run
from tracekc.sigma import lit
from tracekc.graph_algorithms import GraphIndex, signal_similarity, signal_features
from tracekc.relationships import related_incidents

MAX_FINDINGS_JSON = 2000


def write_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, separators=(',', ':'), default=str), encoding='utf-8')
    # Windows file watchers/OneDrive may briefly hold a destination handle.
    # Retain atomic publication and retry only transient permission conflicts.
    for attempt in range(7):
        try:
            os.replace(temporary, path)
            break
        except PermissionError:
            if attempt == 6:
                raise
            time.sleep(.025 * 2**attempt)


@lru_cache(maxsize=8192)
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


def _step(k: int, s: dict, n_ids: int, evidence=None) -> dict:
    return {
        "step": k, "signal_id": s["signal_id"], "ts": iso(s["ts_first_ms"]), "ts_last": iso(s["ts_last_ms"]),
        "title": s["title"], "technique": s["technique"], "technique_name": s["technique_name"],
        'source_technique':s['source_technique'],
        "technique_ids": sorted(set(s.get('techniques') or []) | ({s['technique']} if s['technique'] else set())),
        "tactic": s["tactic_name"], "kill_chain_stage": s["kill_chain_stage"], "lockheed_phase": s["lockheed_phase"],
        "mapping_source": s["mapping_source"], "mapping_version": s["mapping_version"], "severity": s["severity"],
        'mapping_reason': s['mapping_reason'],
        "host": s["host"], "user": s["user_name"], "src_ip": s["src_ip"], "src_host": s["src_host"],
        "dst_ip": s["dst_ip"], "dst_host": s["dst_host"], "dst_domain": s["dst_domain"],
        "merged_detections": s["n_detections"], "event_count": s["n_events"],
        "event_ids": list(s["event_ids"] or [])[:n_ids], "rule_ids": s["rule_ids"], "rule_sources": s["rule_sources"],
        "rule_authors": s["authors"], "vendor_corroborated": bool(s["vendor_corroborated"]),
        "evidence": evidence_dict(s["evidence"]) if evidence is None else evidence,
    }


def _graph(sigs: list[dict], ext_ips: set[str], reach: dict, links=(), evidence_rows=None) -> dict:
    nodes, edges = {}, {}
    # The smallest K members of a union depend only on each input's smallest K.
    # Sort full signal evidence once, then merge at most 200 IDs per shared edge.
    edge_ids=[sorted(set(s['event_ids'] or []))[:100] for s in sigs]

    def node(nid, label, ntype, **kw):
        nodes.setdefault(nid, {"id": nid, "label": label, "type": ntype, **kw})

    def edge(a, b, kind, step, technique):
        e = edges.setdefault((a, b, kind), {"source": a, "target": b, "kind": kind, "steps": [], "techniques": [],
                                           "event_ids": [], "evidence_kind": "observed_association"})
        e["steps"].append(step)
        e['event_ids'] = sorted(set(e['event_ids']) | set(edge_ids[step - 1]))[:100]
        first,last=sigs[step-1]['ts_first_ms'],sigs[step-1]['ts_last_ms']
        e['_first_ms']=min(e.get('_first_ms',first),first)
        e['_last_ms']=max(e.get('_last_ms',last),last)
        e.setdefault('_observation_times',set()).update((first,last))
        if technique and technique not in e["techniques"]:
            e["techniques"].append(technique)

    for k, s in enumerate(sigs, start=1):
        h = f"host:{s['host']}"
        node(h, s["host"], "host", role=_host_role(s["host"]), suspected=True)
        event_node = f"signal:{s['signal_id']}"
        node(event_node, f"Step {k}: {s['title']}", 'event', steps=[k], event_ids=list(s['event_ids'] or [])[:20])
        edge(h, event_node, 'observed_on', k, s['technique'])
        evidence = evidence_dict(s['evidence']) if evidence_rows is None else evidence_rows[k-1]
        process_key = evidence.get('process_entity_id')
        if process_key:
            pid = f"process:{s['host']}:{process_key}"
            node(pid, evidence.get('process_name') or 'process', 'process', identity=process_key)
            edge(h, pid, 'ran', k, s['technique'])
            edge(pid, event_node, 'generated', k, s['technique'])
        for field, ntype, relation in [('file', 'file', 'touched'), ('dns', 'domain', 'queried'),
                                        ('dst_domain', 'domain', 'contacted'), ('registry', 'registry', 'modified')]:
            value = evidence.get(field)
            if value:
                nid = f"{ntype}:{value}"
                node(nid, value, ntype)
                edge(event_node, nid, relation, k, s['technique'])
        if s["user_name"]:
            node(f"user:{s['user_name']}", s["user_name"], "user")
            edge(f"user:{s['user_name']}", h, "acted_on", k, s["technique"])
        if s["src_host"] and s["src_host"] != s["host"]:
            node(f"host:{s['src_host']}", s["src_host"], "host", role=_host_role(s["src_host"]), suspected=True)
            edge(f"host:{s['src_host']}", h, "lateral", k, s["technique"])
        if s["src_ip"] in ext_ips:
            node(f"ip:{s['src_ip']}", s["src_ip"], "external")
            edge(f"ip:{s['src_ip']}", h, "inbound", k, s["technique"])
        if s["dst_ip"] in ext_ips:
            node(f"ip:{s['dst_ip']}", s["dst_domain"] or s["dst_ip"], "external")
            edge(h, f"ip:{s['dst_ip']}", "outbound", k, s["technique"])
        elif s["dst_host"] and s["dst_host"] != s["host"]:
            node(f"host:{s['dst_host']}", s["dst_host"], "host", role=_host_role(s["dst_host"]), suspected=True)
            edge(h, f"host:{s['dst_host']}", "connected", k, s["technique"])
    for r in reach.get("reachable", []):
        nid = f"host:{r['asset']}"
        node(nid, r["asset"], "host", role=_host_role(r["asset"]), compromised=False, potential=True)
        via = r['via_entity']
        src = f"{via['type']}:{via['id']}"
        if src in nodes:
            edges.setdefault((src, nid, "could_reach"), {"source": src, "target": nid, "kind": "could_reach",
                                                         "relation": r["relation"], "confidence": r["confidence"],
                                                         "evidence_kind": "hypothesis", "event_ids": r['evidence']['event_ids']})
    for link in links:
        left, right = sigs[link['from_step']-1], sigs[link['to_step']-1]
        edges[(left['signal_id'],right['signal_id'],link['relation'])] = {
            'source':f"signal:{left['signal_id']}", 'target':f"signal:{right['signal_id']}",
            'kind':'correlates_with', 'relation':link['relation'],
            'steps':[link['from_step'],link['to_step']], 'event_ids':link['event_ids'],
            'evidence_kind':link['kind'], 'similarity':link['similarity'],
            'observation_times_ms':[max(left['ts_first_ms'],right['ts_first_ms'])],
            'cost':1.0 if link['kind']=='observed' else 1/max(link['similarity'],0.05)}
    for value in edges.values():
        if '_first_ms' in value:
            value['first_seen']=iso(value.pop('_first_ms'))
            value['last_seen']=iso(value.pop('_last_ms'))
            value['observation_times_ms']=sorted(value.pop('_observation_times'))
    indexed = GraphIndex({'nodes':list(nodes.values()),'edges':list(edges.values())}, build_adjacency=False)
    return {'nodes':list(indexed.nodes.values()),'edges':list(indexed.edges.values()),'observation_schema_version':2}


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


def materialize(con, cfg: dict, out_dir: Path, promoted, isolated, graph, correlation_edges=()) -> dict:
    # Keep full payloads for one incident at a time. Assembly's lightweight
    # dictionaries remain small; isolated detail is bounded to the saved preview.
    preview=[]
    for _,_,group in isolated:
        for signal in group:
            preview.append(signal)
            if len(preview)>=MAX_FINDINGS_JSON:break
        if len(preview)>=MAX_FINDINGS_JSON:break
    if preview and any('event_ids' not in s for s in preview):
        lookup={s['signal_id']:s for s in preview}
        extras=','.join(map(str,lookup))
        for full in dicts(con,f'SELECT {SIGNAL_COLS} FROM signals WHERE signal_id IN ({extras})'):
            lookup[full['signal_id']].update(full)
    needs_hydration=any('event_ids' not in s for _,_,group in promoted for s in group)
    inc_dir = out_dir / "incidents"
    inc_dir.mkdir(parents=True, exist_ok=True)
    n_ids = int(cfg["output"]["evidence_events_in_json"])
    host_ips = {r[0] for r in run(con, "SELECT ip FROM ip_host")}
    index = []
    lookahead_events = set()
    edges_by_source = defaultdict(list)
    for edge in correlation_edges:
        edges_by_source[edge[0]].append(edge)
    previous_memory=run(con,"SELECT current_setting('memory_limit')")[0][0]
    graph_memory=cfg['output'].get('graph_memory_limit','512MB')
    if graph_memory:run(con,f'SET memory_limit={lit(graph_memory)}')
    hydrated=None
    if needs_hydration:
        columns=','.join('s.'+column.strip() for column in SIGNAL_COLS.split(','))
        hydrated=iter_dicts(con,f"""SELECT {columns},a.incident_id FROM signals s
            JOIN signal_incident a USING(signal_id) WHERE a.incident_id IS NOT NULL
            ORDER BY a.incident_id,a.step""")
        grouped=groupby(hydrated,key=lambda row:row['incident_id'])
    try:
        for inc_id, (score, detail, light_signals) in enumerate(promoted, start=1):
            if needs_hydration:
                assigned,records=next(grouped,(None,()))
                if assigned!=inc_id:raise ValueError('Missing ordered incident signal payload')
                sigs=list(records)
                if [s['signal_id'] for s in sigs]!=[s['signal_id'] for s in light_signals]:
                    raise ValueError('Incident payload order differs from recorded assignment')
            else:
                sigs=light_signals
            ext_ips = {ip for s in sigs for ip in (s["src_ip"], s["dst_ip"]) if _is_external(ip, host_ips)}
            evidence_rows=[evidence_dict(s['evidence']) for s in sigs]
            steps = [_step(k, s, n_ids, evidence_rows[k-1]) for k, s in enumerate(sigs, start=1)]
            step_lookup = {s['signal_id']: k for k, s in enumerate(sigs, 1)}
            features={s['signal_id']:signal_features(s) for s in sigs}
            links = []
            for a, b, relation in (edge for signal in step_lookup for edge in edges_by_source.get(signal, ())):
                if a not in step_lookup or b not in step_lookup:
                    continue
                left, right = sorted([step_lookup[a], step_lookup[b]])
                decision=link_decision(sigs[left-1],sigs[right-1],relation,cfg['correlation'],
                    features=(features[sigs[left-1]['signal_id']],features[sigs[right-1]['signal_id']]))
                links.append({'from_step': left, 'to_step': right, 'relation': relation,
                              'similarity': round(decision['similarity'],4),
                              'kind': 'observed' if relation in {'lateral', 'process_entity'} else 'inferred',
                              'reasons': [decision['reason'],
                                          'Association does not establish causation'],
                              'event_ids': sorted(set(steps[left-1]['event_ids'] + steps[right-1]['event_ids']))})
            incoming_by_step=defaultdict(list)
            for link in links:incoming_by_step[link['to_step']].append(link)
            for step in steps:
                incoming = incoming_by_step[step['step']]
                step['links'] = incoming
                if incoming:
                    step['link'] = max(incoming, key=lambda link: (link['kind'] == 'observed', link['from_step']))
            users = sorted({s["user_name"] for s in sigs if s["user_name"]})
            hosts = sorted({h for s in sigs for h in (s["host"], s["src_host"], s["dst_host"]) if h})
            cutoff = max(s['ts_last_ms'] for s in sigs)
            reach = graph.lookahead(set(users), set(hosts), as_of_ms=cutoff)
            lookahead_events.update(eid for candidate in reach['reachable'] for eid in candidate['evidence']['event_ids'])
            path = _host_path(sigs)
            tactics = []
            for s in sigs:
                if s["tactic_name"] and s["tactic_name"] not in tactics:
                    tactics.append(s["tactic_name"])
            inc = {
                "id": inc_id, "score": score,
                "fingerprint": hashlib.sha256('|'.join(sorted({eid for s in sigs for eid in (s['event_ids'] or [])})).encode()).hexdigest(),
                "score_interpretation": "heuristic priority score, not a probability",
                "correlation_links": links,
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
            inc["graph"] = _graph(sigs, ext_ips, reach, links, evidence_rows)
            inc["narrative"] = _narrative(inc)
            write_json(inc_dir / f"{inc_id}.json", inc)
            index.append({k: inc[k] for k in ("id", "title", "score", "first_seen", "last_seen", "tactics",
                                              "merged_alert_count", "signal_count", "host_path_text")}
                         | {"users": users, "hosts": hosts, "fingerprint": inc['fingerprint'], 'entities':inc['entities'],
                            'technique_ids':sorted({t for step in steps for t in step['technique_ids']})})
    finally:
        if hydrated is not None:hydrated.close()
        if graph_memory:run(con,f'SET memory_limit={lit(previous_memory)}')
    findings = []
    for score, detail, sigs in isolated:
        for s in sigs:
            findings.append({"score": score, **_step(0, s, 5)})
            if len(findings) >= MAX_FINDINGS_JSON:
                break
        if len(findings) >= MAX_FINDINGS_JSON:
            break
    write_json(out_dir / 'findings.json',
        {"total_isolated_signals": sum(len(g[2]) for g in isolated), "shown": len(findings), "findings": findings})
    suppressed = dicts(con, "SELECT signal_id, title, technique, host, user_name, suppressed_reason, n_detections "
                            "FROM signals WHERE suppressed_reason IS NOT NULL")
    (out_dir / "suppressed.json").write_text(json.dumps(suppressed, indent=1, default=str))
    run(con, f"COPY signals TO {lit(out_dir / 'signals.parquet')} (FORMAT parquet)")
    run(con, f"COPY step_index TO {lit(out_dir / 'step_index.parquet')} (FORMAT parquet)")
    run(con, 'CREATE OR REPLACE TEMP TABLE reach_evidence (event_id VARCHAR)')
    if lookahead_events:
        con.executemany('INSERT INTO reach_evidence VALUES (?)', [(eid,) for eid in sorted(lookahead_events)])
    run(con, f"COPY (SELECT * FROM events WHERE event_id IN "
             f"(SELECT unnest(event_ids) FROM signals UNION SELECT event_id FROM reach_evidence)) "
             f"TO {lit(out_dir / 'evidence.parquet')} (FORMAT parquet, COMPRESSION zstd)")
    profiles=[{**row,'timeline':[{'technique_ids':row['technique_ids']}]} for row in index]
    write_json(out_dir / 'relationships.json', related_incidents(profiles,cfg.get('relationships',{})))
    write_json(out_dir / 'index.json', index)  # publish after all incident files exist
    return {"incidents": len(index), "isolated_groups": len(isolated),
            "isolated_signals": sum(len(g[2]) for g in isolated)}
