# Full-file latency engineering

The target is a measured complete local demo below 600 seconds on the supplied
`firex-10G.log`. Its actual size is 6,543,120,032 bytes. Results do not establish a
600-second bound for 15–50 GB files or different log formats.

## Changes

* A bounded C lexer handles FortiGate tokenization when GCC or Clang is available.
  It checks UTF-8 and duplicate keys, preserves the original line for the existing
  MD5 identity, and writes typed-reader input using buffered I/O. SQL still applies
  the same FortiGate mapping and normalized schema. Unsupported lexer cases fall
  back to SQL; supported malformed-input failures use the existing quarantine path.
  Executables are compiled from the included source into the local output cache.
* Valid FortiGate chunks pass directly from a bounded source byte range through
  the native lexer into sparse, explicitly typed JSON files. One disk-backed
  chunk is prefetched while DuckDB normalizes the current chunk. Only the ingest
  thread commits checkpoints, and unconsumed prefetch files are cleaned on exit.
  The optional RAM handoff remains available; it is not the default. Malformed
  chunks are materialized only when byte quarantine requires them.
* Global deduplication retains the original earliest-timestamp policy. Its sort
  has four workers and a 2 GB buffer budget in the optimized launcher. The same
  configurable cap applies to each stage; whole-process memory can exceed it.
* Large datasets resolve process lifetimes and IP/host ownership once into Parquet.
  Detection and access-graph queries reuse that result instead of repeating ASOF
  and IP joins. The existing temporal conditions and ambiguous-owner policy remain.
  An empty process-launch relation bypasses the process ASOF join entirely.
* Outbound-volume analysis retains all groups for its host/fleet median and MAD
  baseline. It collects/sorts evidence IDs only after groups pass the original
  thresholds. Groups failing the threshold still contribute to the baseline.
* Signal sessionization sorts row references and temporal/entity keys, then joins
  evidence payloads back after the windows. This preserves session boundaries
  while keeping JSON, lists and mapping text out of the window spill.
* Destination populations are materialized before address classification, so IP
  parsing runs on distinct destinations instead of every network record. The
  volume precheck skips MAD work only when no group can meet the existing minimum.
* ATT&CK parent fallback uses a conditional equality join, retaining its semantics
  while allowing a hash join. Catalog rows are inserted in one bulk statement.
* Graph publication reuses parsed evidence and bounded timestamp formatting,
  computes capped evidence unions from capped inputs, and omits the search
  adjacency index until an API search actually needs it. All saved edges remain.
* The optimized launcher uses four workers for scans, reads and blocking queries
  based on local comparisons. It uses a configurable DuckDB buffer limit (2 GB default), and scratch storage outside OneDrive. Disk spill is
  bounded by available space: at most 120 GB and at most 60% of currently free
  space. Other applications and filesystem caching affect results; maximum thread
  count is not a universal optimum. Whole-process memory can exceed the buffer cap.
* The API/static incident list returns all matches by default. Explicit limit/offset
  parameters remain available to clients. The Next.js queue requests all incidents. Graph depth, graph rendering bounds,
  evidence sample caps and the saved isolated-finding preview are separate controls;
  complete isolated signals remain in `signals.parquet`.
* The Next.js console from master uses the same API. Incident details and graph
  indexes load on request with a bounded 16-entry cache, avoiding eager loading of
  every graph at startup. Fingerprints are checked on load; unpublished mismatches
  return a retryable 503 instead of exposing a different incident under an old ID.

## Run and measure

Install dependencies once with `scripts/setup.ps1` or
`python -m pip install -e ".[temporal,dev]"`. Ensure `gcc --version` or
`clang --version` succeeds for the faster FortiGate lexer.

```powershell
.\scripts\demo.ps1
.\.venv\Scripts\python.exe scripts/start_web.py
```

For explicit arguments:

```powershell
.\.venv\Scripts\python.exe scripts/run_optimized_demo.py --input "C:\Users\bhara\OneDrive\Desktop\miti\firex-10G.log" --threads 4 --memory 2GB
```

The default output is `%LOCALAPPDATA%\TRACE\firex-full-optimized`. Use a fresh
`--out` directory to measure first processing; cached reruns are a separate result.
The wrapper reads the entire input, fits/evaluates the historical technique model,
attaches forecasts and runs the existing optional 100,000-interaction temporal
experiment. `--temporal-events 0` disables only that experiment. The ML interaction
cap is disclosed in its report; it does not sample ingestion or detection.

Inspect:

* `run_metrics.json`: pipeline time, per-stage time, peak RSS and complete counters.
* `ingest.timings`: segment copying, native lexer work, SQL normalization/writes,
  quarantine, deduplication and entity-resolution time. With prefetch enabled,
  `native_tokenize_seconds` records foreground tokenization/wait time; background
  lexer work overlaps normalization, so stage subtotals are not separate CPU times.
* `demo_timings.json`: total including history export, forecast fitting/evaluation,
  forecast attachment and optional temporal ML; `under_ten_minutes` and
  `under_seven_minutes` are measured outcomes, not guarantees. Forecasts are
  published through a fingerprint-checked sidecar without rewriting all graphs.
  The optional network ML experiment overlaps detection/correlation and completes
  before the total timer stops. Windows runs request temporary idle-sleep prevention
  and restore the previous state on exit; saved power-plan settings are unchanged.
* `forecast-comparison.json`: initial/final fitting seconds, chronological split,
  evaluation support and weak-label warnings. Runtime does not establish accuracy.
* `query_timings.json`: redacted query-shape wall times, including result draining.
  These are not individual operator CPU measurements.

## Quality comparison

```powershell
.\.venv\Scripts\python.exe scripts/compare_runs.py --reference "$env:LOCALAPPDATA\TRACE\firex-full-optimized" --candidate "$env:LOCALAPPDATA\TRACE\firex-under-ten"
```

This compares input accounting, valid/deduplicated events, rejected bytes/fragments,
per-rule detection totals, signal totals, incident totals and incident evidence
fingerprints. It also hashes every normalized row and compares count, sum and XOR:
a strong probabilistic multiset check, not a formal byte-by-byte comparison.
`quality_comparison.json` records each result. Unit/regression tests separately
exercise quoting, escapes, Unicode/BOM handling, malformed input, duplicate keys,
temporal entity identity and qualifying volume evidence.

The reference file contains malformed content: rejected bytes are reported and
the source is preserved. Matching the reference does not turn unparseable bytes
into events or provide independently reviewed attack ground truth.

## Measured full-file result (1 November 2026)

A fresh normalized-cache run processed all 6,543,120,032 source bytes in
**564.157 seconds (9 min 24 sec)**, including forecast fitting/publication and the
parallel 100,000-interaction temporal experiment. The prior complete run took
788.533 seconds: a 28.45% reduction. OS file caches were not flushed, and machine
load can change runtime; this is not a cold-disk or general 15–50 GB guarantee.

| Stage | Seconds |
|---|---:|
| Read / normalize / deduplicate / resolve | 289.644 |
| Detect | 116.699 |
| Map | 6.719 |
| Correlate | 58.605 |
| Graphs and outputs | 79.723 |
| Complete demo, including orchestration and models | 564.157 |

The run used four workers and a 2 GB DuckDB buffer cap. Peak process-tree RSS was
2.625 GiB. All 13 comparison checks passed against the preceding run, including
all-column normalized-row count/sum/XOR checks, detection totals by source and
rule, signal/output accounting and all 1,940 incident evidence fingerprints.
Checksums are probabilistic; matching this reference does not establish attack
accuracy against independent ground truth.

See [sanitized benchmark report](../data/benchmarks/local_firex_2026-11-01.json).
To open these measured results, use the actual output directory from the runner:

```powershell
.\.venv\Scripts\python.exe scripts/start_web.py --out "$env:LOCALAPPDATA\TRACE\firex-under-ten"
```

The Next.js banner displays this run's saved duration and publication time. The
Data page and Predict tab show the fitted model, its training cutoff, provenance,
warnings, a JSON download, and a link to an eligible incident.
