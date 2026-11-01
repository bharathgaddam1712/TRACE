# Reproducible real-log demo

Use Python 3.12+ for the pinned optional temporal ML dependencies. The core package
retains its separate Python requirement. No Neo4j, GPU, Sarvam key or Docker is
required for this demo.

## Next.js console (latest master UI)

Install/build once, then launch the API and console together:

```powershell
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python.exe scripts/start_web.py
```

Open http://127.0.0.1:3000. The API is at http://127.0.0.1:8001. The launcher uses
the optimized local results by default, binds both servers to localhost, and writes
logs/PIDs under the output folder. Use `--out FULL_PATH` for another completed run.
The server proxy keeps API credentials out of browser code. Ports must be free.
The API loads incident details on request and retains a bounded cache of 16
incidents/graphs; every incident remains available in the complete queue.

## Build full-file results

Install the optional ML dependencies once:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[temporal]"
```

The Next.js console reads saved results through the API. Run the pipeline before
presenting or after changing pipeline behavior. The Sarvam key stays in the
ignored root `.env`.

```powershell
.\scripts\setup.ps1
.\scripts\demo.ps1
.\.venv\Scripts\python.exe scripts/start_web.py
```

The default source is the complete local file
`C:\Users\bhara\OneDrive\Desktop\miti\firex-10G.log`. Supply another path with
`-LogPath "FULL_PATH"`. No sample extraction or Git LFS download is required for
the full-file demo. The source stays outside the repository.

Results, chunk caches and DuckDB spill files now default to `%LOCALAPPDATA%\TRACE`,
outside OneDrive. `-Threads` defaults to four workers; `-Memory` defaults
to a 1536 MB DuckDB buffer limit. The process can use more memory than that buffer.
Spill is capped at the smaller of 120 GB or 60% of currently free output-drive space;
this cap does not preallocate or fill the drive. Benchmark thread counts on the demo
machine because more workers can increase paging.

The optional FortiGate lexer builds locally with `gcc` or `clang` on PATH. Without
either compiler, TRACE retains the portable DuckDB regex reader. The C source is
included in the package; generated executables stay in the output cache. Each chunk
keeps its original line for event IDs, and malformed chunks use the existing byte
quarantine path. No downloaded binary or raw-log upload is required.

`demo_timings.json` records the complete pipeline, forecast fit/evaluation, model
attachment and optional network ML experiment. Its `under_seven_minutes` field is a
measured outcome, not a runtime guarantee. `forecast-comparison.json` also records
initial and final fitting time separately. The temporal experiment remains capped
at `-MaxTemporalEvents` (100,000 by default); reading, detection and incident assembly
process the complete input.

Open http://127.0.0.1:3000. The pipeline script runs all seven
stages, performs a causal network interaction experiment, exports inferred incident
histories, benchmarks technique models, then attaches
sequence hypotheses only to incidents after the model's training cutoff. Model
attachment publishes a fingerprint-checked forecast sidecar; it does not repeat ingestion or detection.

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
