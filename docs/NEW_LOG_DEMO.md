# Demo with a previously unseen log

Install dependencies and build the Next.js frontend before presenting. Keep GCC
or Clang on PATH for the optional fast FortiGate lexer; the portable fallback
retains the reader semantics but has a different runtime. Run from
the repository root. The existing UI can stay open while the new file processes.

```powershell
$JuryLog = 'C:\path\to\the-new-file.log'
$JuryOutput = Join-Path $env:LOCALAPPDATA ('TRACE\jury-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
.\scripts\demo.ps1 -LogPath $JuryLog -Output $JuryOutput -Threads 4 -Memory 1536MB
.\.venv\Scripts\python.exe scripts/start_web.py --out $JuryOutput --port 3001 --api-port 8002
```

Open http://127.0.0.1:3001/data. Confirm the banner shows the new `jury-...` run,
publication time and input size. A new output directory has no normalized
processing cache. The full file is read. The launcher requires completed results and
free ports; choose other ports if 3001 or 8002 is occupied.

Supported readers are FortiGate key/value, ECS JSON/NDJSON, supported CSV and
syslog layouts. A `.log` extension alone does not establish a supported schema.
Malformed records are accounted for; unsupported input fails visibly.  An empty next-asset panel means
that incident lacks qualifying historical access evidence.

The 1536 MB setting is a DuckDB buffer budget, not a total Python/process-tree cap.
Leave RAM headroom by closing unused applications before presenting. Keep scratch
output on the local SSD outside OneDrive. The validated default retains ZSTD Parquet. Optional
LZ4 trades more disk space for less compression CPU; a smaller CPU micro-test
does not establish a faster complete run. The spill ceiling does not reserve that
amount of disk space.

Compare fresh-file runtime separately from cached replays. Measurements on the
6.54 GB example do not establish a runtime guarantee for unknown 15–50 GB files.
