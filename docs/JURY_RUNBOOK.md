# Jury rehearsal

Run PowerShell from the TRACE repository. Keep secrets in `.env`; do not put them in the deck, command output or browser. Sarvam is optional for the deterministic pipeline.

## Current validation

- After structured Markdown reporting was added, all 100 Python tests passed in 173.10 seconds; run log: `out/report-final-tests.txt` (one existing Starlette/httpx deprecation warning). TypeScript and production frontend build also passed; browser visual QA was unavailable because local browser use was disabled.
- TypeScript checking and the production Next.js build passed.
- Sample API/UI checked: observed-access candidates and a one-hop Time-ordered path.
- Protected reachability/path code is unchanged. The next-technique experiment has been removed.
- The new 30 GB test has not run. Saved older large-file timing is historical, not a new performance claim.
- Final sample run: 10,000 events / 8,377,169 source bytes, 24.785 seconds, 52 incidents and 0.276 GiB sampled peak RSS. It ran while other validation work was active; it is not a large-file throughput estimate. All 52 incidents retained lookahead/reachable and excluded the retired next-technique result.
- Simulated sample labels: 505/505 found across all signals, 443/505 in promoted incidents (87.72%). This is pseudo ground truth from demo labels, not independent real-file accuracy. See `out/jury-final/label-evaluation.json`.

## Commands

```powershell
.venv\Scripts\python.exe -m pytest -q
Push-Location frontend
npx tsc --noEmit
npm run build
Pop-Location

.venv\Scripts\python.exe -m tracekc run --input data/sample --out out/demo
.venv\Scripts\python.exe scripts/demo_smoke.py --out out/demo
.venv\Scripts\python.exe -m tracekc eval --out out/demo --gt-from-labels data/sample/edr_events.json --save out/demo/label-evaluation.json

# Use unused ports if these are already occupied; do not stop unrelated apps.
.venv\Scripts\python.exe scripts/start_web.py --out out/demo --port 3002 --api-port 8003
```

Current demo URL: http://127.0.0.1:3002 . The start command is for a fresh launch; it will fail if an existing server owns that port.

## Five-minute talk track

1. **Problem (30 seconds):** large logs need a fast investigation that preserves evidence, accounts for rejected input and does not invent attack progression.
2. **Seven stages (45 seconds):** use slide 2. Distinguish detection, ATT&CK mapping, incident linking, graph construction and next-asset reachability.
3. **Working incident (two minutes):** open incident 1; show timeline and cited evidence. Open Attack graph, choose `User: vreddy` to `Host: WS-HR-013`, select Time-ordered and Find path. Explain why observation order matters. Open Where next; show candidate paths and evidence.
4. **Engineering (one minute):** show bounded ingestion, quarantine accounting and the new removal of redundant event copies. State that wider concurrency is measured before adoption.
5. **Validation and limits (45 seconds):** distinguish test success from real-file recall. The new file is pending; give no unmeasured 30 GB runtime or false-positive promise. Optional Sarvam triage is advisory and outside the deterministic runtime claim.

If a new file has no access edges, an empty reachable list is valid. Explain missing evidence instead of manufacturing candidates.

## New-file rehearsal after the file is supplied

Use a new output directory for every cold run. Replace the placeholder with the actual source path.

```powershell
.venv\Scripts\python.exe scripts/run_optimized_demo.py --input "C:\logs\NEW-30GB.log" --out "$env:LOCALAPPDATA\TRACE\jury-30gb-run1" --threads 4 --memory 1536MB
.venv\Scripts\python.exe scripts/demo_smoke.py --out "$env:LOCALAPPDATA\TRACE\jury-30gb-run1"
.venv\Scripts\python.exe scripts/start_web.py --out "$env:LOCALAPPDATA\TRACE\jury-30gb-run1" --port 3003 --api-port 8004

# Plan only. Executing the grid can take many full runs and substantial disk space.
.venv\Scripts\python.exe scripts/sweep_engine.py --input "C:\logs\NEW-30GB.log" --out out/engine-sweep
# Add --execute only for a deliberate benchmark session; unsafe resource configurations are skipped.
```

Capture `run_metrics.json`, `demo_timings.json`, `query_timings.json`, input-quality reports and quarantine ledgers. Review available RAM/disk first. The sweep uses an 8 GiB process-tree watchdog by default, stricter than the suggested 12 GB ceiling, and reserves RAM headroom. A disk estimate is a guard, not a guarantee. Checkpoints remain available if a trial fails. No default tuning is chosen from skipped or failed trials.

With reviewed ground truth, use `tracekc eval --out <output> --gt <labels.json> --save <evaluation.json>` and inspect matching policy and units. Without labels, report evidence consistency and coverage, not real-data precision/recall.

Review `LIVE_MODE.md` before any incremental implementation and `ACCURACY_AUDIT.md` before changing parser acceptance or promotion.
