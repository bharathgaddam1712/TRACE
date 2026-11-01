# DuckDB and parser engineering review

## Corrections to the supplied article

The recommendations were checked against the installed DuckDB 2.0.0 and its
official documentation. `CREATE MATERIALIZED VIEW` raises `ParserException`, and
`PRAGMA disable_optimizer=0` raises `CatalogException`. Use explicit tables or
Parquet caches for reusable results. Do not disable production optimizers.

DuckDB already supports ART indexes. They can benefit selective lookups but do
not generally accelerate joins, sorts or aggregations. A persistent database does
not preserve all process-local warm caches across closing and reopening it.
Parquet partitioning is useful when actual predicates prune partitions; partitioning
by every host/IP risks many small files. More threads can increase memory and
slow workloads. Settings must be measured on the workload.

Sources: [workload tuning](https://duckdb.org/docs/2.0/guides/performance/how_to_tune_workloads),
[indexes](https://duckdb.org/docs/2.0/guides/performance/indexing),
[views](https://duckdb.org/docs/2.0/sql/statements/create_view),
[profiling/settings](https://duckdb.org/docs/2.0/configuration/pragmas).

## What TRACE uses

- Native DuckDB parsing for explicitly typed ECS JSON and FortiGate key/value
  records; bounded streaming adapters for CSV and timestamped syslog.
- Closed, large uncompressed files: 256 MiB newline-aligned resumable chunks and
  compressed Parquet shards. Full-file source size/mtime changes invalidate snapshots.
- Deduplication and normalization in SQL; insertion order disabled to reduce
  unnecessary buffering. Events have explicit ordering where chronology matters.
- Conservative automatic thread count (up to four), configurable DuckDB memory
  and a 20 GB spill cap by default. Whole-process memory can exceed the buffer cap.
- One connection per pipeline; explicit scoped temporary tables when many rule
  batches would otherwise repeat expensive process/IP joins. Small rule sets retain
  a direct scan to avoid paying unnecessary materialization cost.
- Missing-field counters calculated in one aggregate instead of separate scans.
- Optional `engine.profile_queries=true` writes `query_timings.json` with query
  shape IDs, redacted previews, call counts and total wall times. This is an
  application timer including result draining, not an operator CPU profiler. Native
  `EXPLAIN ANALYZE` remains the tool for investigating a particular query plan.
- SQL string quoting for spill paths, including paths containing apostrophes.

## Parser schemas and noise accounting

Run `python -m tracekc parser-schemas`. Every run writes `parser_contracts.json`.
This records the explicit ECS projection (including merged Active Directory
fields), each supported parser's source/timestamp/host contract, and noise policy.
It describes supported contracts, not a promise of every vendor format.

All normalized events require a usable timestamp and host. Parsed rows missing
them go to `quarantine.parquet`. CSV conversion errors and malformed/oversized
syslog lines have row diagnostics. ECS JSON is strict by default. FortiGate's
supported reader-error fallback records source byte ranges, SHA-256, bounded
previews and rejected physical-line counts while leaving original bytes intact.

`reader_rejected_bytes` and `reader_rejected_records` measure different things:
binary garbage may contain millions of newline fragments that were never valid
security events. `valid_events`, duplicates, parsed quarantine and adapter/reader
rejections remain separate. Required-field counts do not imply that an optional
field such as username must exist on every firewall event.

Repeated alerts remain findings under recurrence controls; unsupported/noisy
telemetry is not deleted by an LLM. No implementation can claim to identify all
noise automatically. Inspect quality counters before presenting conclusions.

## Full-file local demo

`scripts/demo.ps1` defaults to the complete local `firex-10G.log` and an output
folder under `%LOCALAPPDATA%\TRACE`. It does not create another raw-data sample.
Neo4j remains optional; local adjacency indexes handle graph queries. Next-asset
hypotheses and time-ordered paths use recorded access evidence.
See [demo instructions](DEMO.md).
