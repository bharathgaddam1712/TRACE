# Reproducible real-log demo

Use Python 3.12+ for the pinned optional temporal ML dependencies. The core package
retains its separate Python requirement. No Neo4j, GPU, Sarvam key or Docker is
required for this demo.

## Streamlit app (local presentation)

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[demo,temporal]"
.\scripts\start_streamlit.ps1
```

Open http://127.0.0.1:8501. The seven tabs expose ingestion and quality accounting,
detection inventory, ATT&CK reasons, correlation links, bounded graphs and temporal
path search, sequence forecasts, evidence, reports, analyst history and optional
Sarvam tasks. Select **Only incidents after model training cutoff** to demonstrate
eligible forecasts. Earlier incidents intentionally cannot use that model.

The app reads saved results without restarting ingestion on widget interactions.
During processing it shows progress. `scripts/demo.ps1` builds/rebuilds the full
results and models; use it before presenting or after changing pipeline behavior.
The two UI launchers can run independently; Streamlit does not require the FastAPI
server. The Sarvam key stays in the ignored root `.env`.

```powershell
.\scripts\setup.ps1
.\scripts\demo.ps1
.\.venv\Scripts\python.exe -m tracekc serve --out out/firex-full-demo --port 8001
```

The default source is the complete local file
`C:\Users\bhara\OneDrive\Desktop\miti\firex-10G.log`. Supply another path with
`-LogPath "FULL_PATH"`. No sample extraction or Git LFS download is required for
the full-file demo. The source stays outside the repository.

Open http://127.0.0.1:8001. The script runs all seven
stages, performs a causal network interaction experiment, exports inferred incident
histories, benchmarks technique models, then reuses ingestion caches to attach
sequence hypotheses only to incidents after the model's training cutoff.

## What to demonstrate

1. Input-quality counters: complete input byte size, valid normalized events,
   rejected physical-line fragments and rejected bytes. A malformed/binary suffix
   is excluded and accounted for; it is not converted into invented events.
2. A real incident timeline: inspect its supporting event IDs and mapping reasons.
3. Graph connections: open an edge, inspect observed/inferred status, and use a
   depth-limited neighborhood, weighted shortest path, or time-respecting path.
   The temporal search uses recorded observations in order and excludes future,
   untimed, inferred and hypothesis edges. These searches do not prove causality.
4. Predict: choose an incident after the trained model's cutoff to see bounded
   technique-sequence hypotheses. Earlier incidents correctly show unavailable.
   Exported histories are explicitly `trace_predictions_unreviewed`; this is a
   demonstration of the forecasting machinery, not independently proven accuracy.
5. Temporal network experiment: show the selected baseline, candidate protocol,
   held-out MRR, and coverage. High accuracy with easy negatives is not credible;
   use the default degree-matched protocol and inspect cold-destination exclusions.
6. For a known six-step ground-truth attack, run the separate planted-chain loop:

```powershell
.\.venv\Scripts\python.exe scripts/validate_loop.py
.\.venv\Scripts\python.exe -m tracekc serve --out out/sample-loop/planted --port 8002
```

Label that demonstration synthetic. Never claim the planted attack was found in
the real firewall file.

## Individual ML commands

```powershell
.\.venv\Scripts\python.exe -m tracekc temporal-benchmark --events out/firex-full-demo/work/events.parquet --out out/firex-full-demo --max-events 100000 --negative-mode degree_matched --seed 17
.\.venv\Scripts\python.exe -m tracekc forecast-benchmark --input reviewed-histories.json --out out/reviewed/forecast-comparison.json --model-out out/reviewed/forecast-model.json
.\.venv\Scripts\python.exe -m tracekc predict-sequence --model out/reviewed/forecast-model.json --history T1110 T1059.001 --as-of 2026-10-31T00:00:00Z --depth 3 --top-n 5 --beam-width 20
```

The last command needs a real fitted model whose training cutoff precedes the
specified incident start. Technique IDs in the command are an example, not a
claim about the real sample. Use reviewed histories for meaningful attack metrics.

## Limits and measurements

The pipeline uses the entire file; the optional temporal ML experiment still has
an explicit interaction cap to keep local training bounded. Neither establishes
coverage of all attacks.
Keep source hashes, seeds, cutoffs, rule inventory, candidate counts, data quality,
peak RSS, and per-stage timings with results. Compare cold and cached runs separately.
Changing correlation thresholds can change incident membership even when detection
counts agree. Test attack-chain recall and false merges with independent annotations.

See [research and model decisions](TEMPORAL_RESEARCH.md). TGN is a researched future
challenger, not a model claimed implemented or trained in this revision.
