"""Stage 3: technique -> tactic -> kill-chain stage, from the pinned ATT&CK mapping.

Also verifies / refreshes configs/attack_mapping.yaml against the official MITRE STIX bundle.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from tracekc.engine import one, run


def load_mapping(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def label(con, mapping: dict) -> dict:
    run(con, "CREATE OR REPLACE TABLE tactic_map (tactic VARCHAR, display VARCHAR, ord INTEGER, lockheed VARCHAR)")
    for short, (display, order, lockheed) in mapping["tactics"].items():
        run(con, "INSERT INTO tactic_map VALUES (?, ?, ?, ?)", [short, display, int(order), lockheed])
    run(con, "CREATE OR REPLACE TABLE tech_map (technique VARCHAR, name VARCHAR, tactics VARCHAR[])")
    for tid, t in mapping["techniques"].items():
        run(con, "INSERT INTO tech_map VALUES (?, ?, ?)", [tid.upper(), t["name"], list(t["tactics"])])
    version = str(mapping.get("attack_version", "unknown"))
    # Sub-technique missing from the table falls back to its parent's tactics. The rule's attack.<tactic>
    # tag selects among several valid tactics; a tag that is not valid for the technique is ignored.
    run(con, f"""
        CREATE OR REPLACE TABLE labeled AS
        WITH j AS (
          SELECT d.*,
                 coalesce(t.name, tp.name) AS technique_name,
                 coalesce(t.tactics, tp.tactics) AS valid_tactics,
                 CASE WHEN t.technique IS NOT NULL THEN 'attack-mapping'
                      WHEN tp.technique IS NOT NULL THEN 'attack-mapping-parent'
                      WHEN d.technique IS NOT NULL AND d.tactic_hint IS NOT NULL THEN 'rule-tag'
                      ELSE 'unmapped' END AS mapping_source
          FROM detections d
          LEFT JOIN tech_map t ON d.technique = t.technique
          LEFT JOIN tech_map tp ON t.technique IS NULL AND split_part(d.technique, '.', 1) = tp.technique),
        k AS (
          SELECT *,
                 CASE WHEN technique IS NULL THEN NULL
                      WHEN valid_tactics IS NULL THEN tactic_hint
                      WHEN list_contains(valid_tactics, tactic_hint) THEN tactic_hint
                      ELSE valid_tactics[1] END AS tactic
          FROM j)
        SELECT k.*, m.display AS tactic_name, m.ord AS tactic_order, m.display AS kill_chain_stage,
               m.lockheed AS lockheed_phase, '{version}' AS mapping_version
        FROM k LEFT JOIN tactic_map m ON k.tactic = m.tactic""")
    unmapped = one(con, "SELECT count(*) FROM labeled WHERE technique IS NOT NULL AND tactic_name IS NULL")[0]
    return {"attack_version": version, "unmapped_techniques": unmapped,
            "by_tactic": dict(run(con, "SELECT coalesce(tactic_name, '(none)'), count(*) FROM labeled GROUP BY 1"))}


# ------------------------------------------------------------------ STIX verification

def _external_id(obj: dict) -> str | None:
    ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
    return ext["external_id"].upper() if ext else None


def stix_revocations(bundle: dict) -> dict[str, str]:
    """Revoked technique id -> replacement id (from revoked-by relationships)."""
    by_ref = {o["id"]: o for o in bundle.get("objects", [])}
    out = {}
    for o in bundle.get("objects", []):
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = by_ref.get(o["source_ref"]), by_ref.get(o["target_ref"])
            if src and dst and _external_id(src) and _external_id(dst):
                out[_external_id(src)] = _external_id(dst)
    return out


def stix_techniques(stix_path: Path) -> dict[str, dict]:
    bundle = json.loads(stix_path.read_text())
    out = {"_revoked": stix_revocations(bundle)}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        out[ext["external_id"].upper()] = {
            "name": obj.get("name"),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"],
        }
    return out


def verify_mapping(mapping_path: Path, stix_path: Path, write: bool = False) -> list[str]:
    mapping = load_mapping(mapping_path)
    stix = stix_techniques(stix_path)
    problems = []
    for tid, t in mapping["techniques"].items():
        s = stix.get(tid.upper())
        if s is None:
            repl = stix["_revoked"].get(tid.upper())
            problems.append(f"{tid}: revoked, replaced by {repl}" if repl else f"{tid}: not in STIX bundle (deprecated or typo)")
            continue
        if s["name"] != t["name"]:
            problems.append(f"{tid}: name '{t['name']}' != STIX '{s['name']}'")
        if set(s["tactics"]) != set(t["tactics"]):
            problems.append(f"{tid}: tactics {t['tactics']} != STIX {s['tactics']}")
        for tac in s["tactics"]:
            if tac not in mapping["tactics"]:
                problems.append(f"{tid}: STIX tactic '{tac}' missing from tactics table")
        if write:
            t["name"], t["tactics"] = s["name"], s["tactics"]
    if write:
        mapping_path.write_text(yaml.safe_dump(mapping, sort_keys=False, width=120))
    return problems
