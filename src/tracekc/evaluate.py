"""Scorer for the PRD accuracy targets.

Ground truth JSON:
  {"attacks": [{"attack_id": "a1", "steps": [{"step": 1, "technique": "T1110", "event_ids": ["..."]}, ...]}]}
A planted step is *found* when any of its event ids is inside one of our detections.
  detection_rate    found steps / all steps                          (PRD: >70% good, >90% great)
  label_accuracy    found steps whose technique matches / found      (>60% / >85%); strict and parent-level
  path_rate         attacks whose steps all sit in ONE incident in GT order / attacks (multi-step only)
  false_incident    incidents containing no ground-truth event / all incidents   (<30% / <10%)
Rates are reported twice: counting only promoted incidents ("incident") and counting every signal
including isolated findings ("any").
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import duckdb

from tracekc.sigma import lit


def gt_from_labels(input_path: Path) -> dict:
    """Pseudo ground truth from SimEDR rows labelled simulated_detection=true (one step each)."""
    con = duckdb.connect()
    files = [input_path] if input_path.is_file() else sorted(
        p for pat in ("*.json", "*.ndjson", "*.jsonl", "*.json.gz") for p in input_path.rglob(pat))
    flist = "[" + ", ".join(lit(f) for f in files) + "]"
    rows = con.execute(f"""
        SELECT event.id, threat.technique.id[1] FROM read_json({flist}, format='newline_delimited',
          columns={{'event': 'STRUCT(id VARCHAR)', 'labels': 'STRUCT(simulated_detection VARCHAR)',
                    'threat': 'STRUCT(technique STRUCT(id VARCHAR[]))'}}, ignore_errors=true)
        WHERE labels.simulated_detection = 'true'""").fetchall()
    con.close()
    return {"attacks": [{"attack_id": eid, "steps": [{"step": 1, "technique": tech, "event_ids": [eid]}]}
                        for eid, tech in rows]}


def _parent(t: str | None) -> str | None:
    return t.split(".")[0].upper() if t else None


def evaluate(out_dir: Path, gt: dict) -> dict:
    con = duckdb.connect()
    idx = con.execute(f"""SELECT event_id, signal_id, incident_id, step, technique
                          FROM read_parquet({lit(out_dir / 'step_index.parquet')})
                          WHERE suppressed_reason IS NULL""").fetchall()
    con.close()
    by_event: dict[str, list[tuple]] = defaultdict(list)
    incident_events: dict[int, set[str]] = defaultdict(set)
    for event_id, signal_id, incident_id, step, technique in idx:
        by_event[event_id].append((signal_id, incident_id, step, technique))
        if incident_id is not None:
            incident_events[int(incident_id)].add(event_id)
    n_incidents = len(json.loads((out_dir / "index.json").read_text()))

    def rates(scope: str) -> dict:
        total = found = strict = parent = 0
        paths_total = paths_ok = 0
        misses, wrong = [], []
        for atk in gt["attacks"]:
            step_hits = []
            for st in atk["steps"]:
                total += 1
                hits = [h for e in st["event_ids"] for h in by_event.get(e, [])
                        if scope == "any" or h[1] is not None]
                step_hits.append(hits)
                if not hits:
                    misses.append(f"{atk['attack_id']}#{st['step']}")
                    continue
                found += 1
                techs = {h[3] for h in hits}
                if st["technique"] and st["technique"].upper() in {t.upper() for t in techs if t}:
                    strict += 1
                    parent += 1
                elif _parent(st["technique"]) in {_parent(t) for t in techs}:
                    parent += 1
                else:
                    wrong.append(f"{atk['attack_id']}#{st['step']}: want {st['technique']} got {sorted(map(str, techs))}")
            if len(atk["steps"]) > 1:
                paths_total += 1
                if all(step_hits):
                    common = set.intersection(*({h[1] for h in hits if h[1] is not None} for hits in step_hits))
                    for inc in common:
                        order = [min(h[2] for h in hits if h[1] == inc) for hits in step_hits]
                        if order == sorted(order):
                            paths_ok += 1
                            break
        return {"steps": total, "found": found,
                "detection_rate": round(found / total, 4) if total else None,
                "label_accuracy_strict": round(strict / found, 4) if found else None,
                "label_accuracy_parent": round(parent / found, 4) if found else None,
                "multi_step_attacks": paths_total,
                "path_rate": round(paths_ok / paths_total, 4) if paths_total else None,
                "missed_steps": misses[:50], "wrong_labels": wrong[:50]}

    gt_events = {e for atk in gt["attacks"] for st in atk["steps"] for e in st["event_ids"]}
    true_incidents = {i for i, evs in incident_events.items() if evs & gt_events}
    false_rate = round(1 - len(true_incidents) / n_incidents, 4) if n_incidents else None
    return {"incidents": n_incidents, "true_incidents": len(true_incidents), "false_incident_rate": false_rate,
            "incident": rates("incident"), "any": rates("any")}
