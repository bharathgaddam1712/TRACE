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
  has four workers and a 1536 MB buffer budget in the optimized launcher. The same
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
  based on local comparisons. It uses a configurable DuckDB buffer limit (1536 MB default), and scratch storage outside OneDrive. Disk spill is
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
.\.venv\Scripts\python.exe scripts/run_optimized_demo.py --input "C:\Users\bhara\OneDrive\Desktop\miti\firex-10G.log" --threads 4 --memory 1536MB
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

## Memory and unseen-file demo work

The UI's processing peak is a saved process-tree RSS measurement, not live browser
or API usage. DuckDB's buffer limit excludes some reader, Python and worker memory;
Windows paging can also reduce resident memory while increasing runtime. A lower
RSS number alone does not establish a faster implementation.

Graph publication now fetches ordered signal payloads in batches and retains one
incident's full payload at a time, plus the existing 2,000-finding preview. It does
not retain every promoted signal's full evidence in Python. Complete signals and
evidence remain in the saved Parquet files, and assignment order is checked.
A separate 512 MB graph-phase DuckDB budget releases scan/sort buffers during
Python graph generation; the preceding budget is restored before final exports.
The metrics report and Data page include sampled peak RSS for each stage.

An LZ4 intermediate-codec trial passed all 13 parity checks but took 714.429 seconds
with 1.696 GiB sampled peak RSS. Despite a faster small COPY micro-test, it did not
beat the complete 564.157-second ZSTD baseline. ZSTD therefore remains the default;
`--parquet-codec lz4_raw` is an explicit experiment, not a promised speedup.
Measurements were taken under different available-RAM conditions, not a controlled
hardware comparison. Do not attribute every timing or RSS difference to the codec.

For an authentication-only input, insufficient temporal network interactions now
produce an explicit unavailable report for that optional experiment, while genuine
configuration/provider/programming errors still fail. This does not manufacture
forecasts or skip the main full-file detection pipeline.

Use a new output directory when judging unseen-file speed. See
[fresh-file demo instructions](NEW_LOG_DEMO.md). The fastest verified historical
full-file result remains the recorded benchmark above until a faster complete
run is measured and checked.

## Selected balanced profile (1 November 2026)

The final fresh-processing run took **519.734 seconds (8 min 40 sec)** with
**1.453 GiB sampled peak RSS**, using four workers, a **1536 MB DuckDB buffer**,
ZSTD intermediate Parquet and streamed graph publication with its 512 MB budget.
It processed all 6,543,120,032 bytes and reused zero input files. The existing
100,000-interaction temporal experiment was included and ran in parallel.
All 13 parity checks passed against the 564.157-second reference, including all
normalized-row checksums and all 1,940 incident evidence fingerprints.

| Profile | Complete seconds | Sampled peak RSS (GiB) |
|---|---:|---:|
| Prior 2 GB ZSTD baseline | 564.157 | 2.625 |
| Rejected 2 GB LZ4 trial with streamed graphs | 714.429 | 1.696 |
| Selected 1536 MB ZSTD profile with streamed graphs | 519.734 | 1.453 |

The selected run measured 7.87% less time and 44.65% lower sampled peak RSS than
the preceding best run. These are observed run differences, not isolated causal
estimates: available RAM and background load differed between measurements.
The 1536 MB setting is now the demo and core configuration default. The old
8 min/9 min/11 min values are historical measurements with their recorded settings;
they do not describe live dashboard memory or a guarantee for new file sizes.

See [sanitized profile comparison](../data/benchmarks/memory_profiles_2026-11-01.json).
The selected results are in the runner's `firex-balanced-fresh` output directory.
Use the [new-log workflow](NEW_LOG_DEMO.md) for a jury-supplied input instead of
replaying saved results as a fresh-processing measurement.
