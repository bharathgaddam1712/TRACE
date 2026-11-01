# Full-file latency and memory engineering

## Current pipeline

The full input passes through read/normalize, detection, ATT&CK mapping,
correlation, evidence graphs, next-asset reachability and UI publication. No
learned next-action sequence model or separate network ML experiment runs.

- The optional bounded C FortiGate lexer validates UTF-8/duplicate keys and
  preserves original lines for stable IDs. Typed sparse JSON feeds DuckDB.
  One disk-backed chunk is prefetched while the current chunk is normalized;
  only the ingest thread commits checkpoints. The portable reader remains available.
- Global deduplication retains the earliest-timestamp policy. Large datasets resolve
  process lifetimes and conservative IP ownership once into Parquet. Ambiguous
  ownership is not guessed; an empty process-launch relation avoids an ASOF sort.
- Volume detection classifies distinct destinations after population aggregation.
  All groups still contribute to the host/fleet median/MAD baseline; evidence IDs
  are collected after the original thresholds qualify a group.
- Signal sessionization sorts narrow references, keys and timestamps before joining
  evidence payloads back. Parent-technique fallback uses a conditional equality join.
- Graph publication converts ordered payloads in batches and retains one incident's
  full payload at a time, plus the existing 2,000-finding preview. Complete signals
  and evidence remain in Parquet. Assignment order is checked.
- The selected local configuration uses four workers, 1536 MB DuckDB buffers,
  ZSTD intermediate Parquet and a 512 MB graph-generation buffer restored before
  final exports. Extra threads or less memory can increase spill or paging.
- RSS is sampled for the processing tree and each stage. It includes Python and
  readers, not just DuckDB buffers. Lower resident memory can also reflect Windows
  paging; RSS alone does not establish a faster implementation. It is a historical
  run measurement, not live dashboard memory or a hard whole-process cap.
- The Next.js queue requests all incidents. Details and graph indexes load on demand
  with a 16-entry cache. Publication fingerprints guard against inconsistent loads.
  Bounded BFS, depth-constrained Dijkstra and time-ordered paths remain available.

## Run and measure

Install once with `scripts/setup.ps1` or `python -m pip install -e ".[dev]"`.
Build `frontend/` before presenting. GCC/Clang enables the fast FortiGate lexer.

```powershell
.\scripts\demo.ps1
.\.venv\Scripts\python.exe scripts/start_web.py
```

For explicit settings:

```powershell
.\.venv\Scripts\python.exe scripts/run_optimized_demo.py --input "C:\path\to\new.log" --out "$env:LOCALAPPDATA\TRACE\jury-new" --threads 4 --memory 1536MB
```

Use a fresh output directory for unseen-file measurements. Cache identity includes
source metadata and reader/schema settings; cached replays are a separate result.
Spill is limited by available space and does not reserve that capacity.

Inspect `run_metrics.json` for stage times, sampled RSS and accounting;
`demo_timings.json` for the complete wrapper time; `ingest.timings` for read
substeps; and `query_timings.json` for redacted query-shape wall times. Prefetch
foreground wait time overlaps background work, so substeps are not CPU totals.

## Quality comparison

```powershell
.\.venv\Scripts\python.exe scripts/compare_runs.py --reference "REFERENCE_OUTPUT" --candidate "CANDIDATE_OUTPUT"
```

The comparison checks valid/deduplicated events, rejected bytes/fragments, per-rule
and per-source detection totals, signals, output counts, incident fingerprints and
all-column normalized-row count/sum/XOR hashes, and complete parsed incident JSON
payloads (including graph identities and evidence). The hash comparison is probabilistic,
not a formal byte-for-byte proof. Tests separately check quoting, Unicode/BOM,
malformed data, duplicate keys, entity identity, qualifying volume evidence,
reachability and time-ordered path constraints. No known parser can identify all
attacks without appropriate telemetry and independent validation.

## Historical benchmark records

### Rejected detection trial — 1 November 2026

Same 8,377,169-byte sample, separate fresh output directories, two DuckDB threads,
768 MB buffer/blocking limits, forced resolved Parquet. The reference used the
existing detection function; the trial reused resolved Parquet with narrowed scope
columns. Both used the current reachability-only pipeline. One serial pair is
not a statistically reliable performance estimate.

| Stage | Reference seconds | Trial seconds |
|---|---:|---:|
| Read | 0.435 | 0.451 |
| Detect | 15.502 | 16.855 |
| Map | 0.363 | 0.282 |
| Correlate | 0.301 | 0.232 |
| Materialize, including graph and reachability | 0.812 | 0.594 |
| Total wall, including setup | 21.634 | 18.935 |
| Peak process-tree RSS, bytes | 283,840,512 | 334,876,672 |

Stage sums exclude setup. Read noise and initialization/cache effects prevent
attributing the lower total to the changed detection code. Rule counts, signal
counts, normalized-row checksums and incident fingerprints matched. However,
21/52 complete incident payloads differed, including evidence/process identities.
**Trial reverted; no accepted speedup.** The comparison script now fails such a
trial. Reports: local `out/jury-reference` and `out/jury-candidate`.

Sample-label evaluation of the trial found 505/505 labeled steps across all
findings and 443/505 inside promoted incidents (87.72%). This is simulated-label
evaluation, not real-file accuracy, and is not a reason to retain the trial.


The JSON files below remain unchanged as records of older pipeline versions.
Their complete-run totals include components that have since been retired, so
these numbers are not new measurements of the current pipeline.

| Historical profile on the 6.54 GB input | Complete seconds | Sampled peak RSS (GiB) |
|---|---:|---:|
| Prior 2 GB ZSTD | 564.157 | 2.625 |
| Rejected 2 GB LZ4 trial | 714.429 | 1.696 |
| Selected 1536 MB ZSTD | 519.734 | 1.453 |

See [original local benchmark](../data/benchmarks/local_firex_2026-11-01.json) and
[profile comparison](../data/benchmarks/memory_profiles_2026-11-01.json). Each used
fresh normalized caches, but OS caches were not flushed and background load/RAM
availability differed. No causal speedup or unknown 15–50 GB runtime guarantee is
established by these individual runs. ZSTD remains the default because the complete
LZ4 trial did not beat it, despite a favorable small compression micro-test.

Use the [fresh-file demo workflow](NEW_LOG_DEMO.md) for new jury data. An empty
next-asset panel is valid when no qualifying historical access evidence exists;
it should never be filled with invented hosts or future observations.
