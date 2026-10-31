#!/usr/bin/env bash
# Build a synthetic tier from the sample (with one planted chain) and run + score it.
#   bash scripts/benchmark.sh 15        # ~15 GB
# Real tiers: skip generation and run `tracekc run --input <tier dir> --out out/tier`.
set -euo pipefail
GB=${1:?usage: benchmark.sh <size in GB>}
BIN=${BIN:-.venv/bin}
DIR=data/tiers/synthetic_${GB}gb
if [ ! -d "$DIR" ]; then
  "$BIN/tracekc" gen-scale --out "$DIR" --target-gb "$GB"
fi
OUT=out/bench_${GB}gb
"$BIN/tracekc" run --input "$DIR" --out "$OUT"
"$BIN/tracekc" eval --out "$OUT" --gt "${DIR}_gt.json" --save "$OUT/eval.json"
mkdir -p benchmarks
python3 - "$OUT" "$GB" <<'PY'
import json, sys, pathlib
out, gb = pathlib.Path(sys.argv[1]), sys.argv[2]
m = json.loads((out / "run_metrics.json").read_text())
e = json.loads((out / "eval.json").read_text())
row = {"tier_gb": gb, **m["timings"], "peak_rss_gb": m["peak_process_tree_rss_gb"], "machine": m["machine"],
       "input_bytes": m["ingest"]["input_bytes"], "events": m["ingest"]["events"],
       "incidents": e["incidents"], "false_incident_rate": e["false_incident_rate"],
       "detection_rate": e["incident"]["detection_rate"], "label_accuracy": e["incident"]["label_accuracy_strict"],
       "path_rate": e["incident"]["path_rate"], "ruleset_hash": m["rules"]["ruleset_hash"],
       "attack_version": m["attack_mapping_version"]}
p = pathlib.Path("benchmarks/results.json")
rows = json.loads(p.read_text()) if p.exists() else []
rows.append(row)
p.write_text(json.dumps(rows, indent=1))
print(json.dumps(row, indent=1))
PY
