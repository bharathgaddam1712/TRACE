# Reproducible local reachability demo

Use Python 3.10+ and Node.js 20+. No Neo4j, GPU, AI key or Docker is required.

## Install and build once

```powershell
.\scripts\setup.ps1
cd frontend
npm ci
npm run build
cd ..
```

## Process the complete local file

```powershell
.\scripts\demo.ps1
.\.venv\Scripts\python.exe scripts/start_web.py
```

The default source is `C:\Users\bhara\OneDrive\Desktop\miti\firex-10G.log`.
Supply a new file with `-LogPath "FULL_PATH"` and a fresh `-Output` directory.
No sample extraction or Git LFS download is needed. Results, caches and spill files
are local, outside OneDrive, under `%LOCALAPPDATA%\TRACE` by default.

The runner uses four workers, a 1536 MB DuckDB buffer budget and a 512 MB budget
while streaming incident graphs. The process can use more RAM than its DuckDB
buffer. Spill is capped at the smaller of 120 GB or 60% of free output-drive space;
that ceiling does not preallocate the disk. An optional GCC/Clang lexer accelerates
FortiGate input; without a compiler the portable reader retains its semantics.

Open http://127.0.0.1:3000. The API uses port 8001. For another completed run:

```powershell
.\.venv\Scripts\python.exe scripts/start_web.py --out "FULL_PATH" --port 3001 --api-port 8002
```

Ports must be free. API credentials remain in the ignored root `.env` and the
server-side proxy. Incident details load on demand with a bounded cache.

## Seven-stage demonstration

1. Read: input bytes, valid events, deduplication, rejected records/bytes and parser schemas.
2. Detect: loaded rules, observed hits, evidence and explicit telemetry limitations.
3. Map: ATT&CK labels, source technique, catalog version and mapping reasons.
4. Link: incident timeline, supporting entities, time windows and correlation reasons.
5. Graph: entity/evidence edges, bounded neighborhoods, weighted shortest paths
   and the PathFinder's **Time-ordered** mode. It uses observations before the
   cutoff and excludes untimed, inferred and hypothesis edges; it does not prove causality.
6. Where next: **Where the attacker could go next**, using `AccessGraph` historical
   logons, privileged access and administrative network observations. Open a
   candidate's evidence. Zero candidates means insufficient qualifying access
   evidence outside that incident, not proof that further attacks are impossible.
7. Show: evidence drill-down, narratives, case history, optional cited Sarvam
   investigation/triage and reports. AI is advisory and runs on demand.

## Synthetic validation loop

```powershell
.\.venv\Scripts\python.exe scripts/validate_loop.py
```

The planted chain is a synthetic test, not an attack claimed discovered in the
real firewall file. To inspect it, launch the UI with `--out out/sample-loop/planted`.

## Timing and quality

`demo_timings.json` measures the complete processing/publication wrapper;
`run_metrics.json` records stage times, sampled process-tree RSS, per-stage RSS and
accounting. The banner shows the saved run name and publication time, not page
refresh time. Historical benchmark JSON files retain their original measurements;
no revised large-file runtime is inferred from removing retired components.

Use the [new-log workflow](NEW_LOG_DEMO.md) for a jury-supplied file and
[performance notes](PERFORMANCE.md) for measurement limits. Supported schemas and
quality counts determine what can be concluded from the input; successful parsing
alone does not establish detection accuracy.
