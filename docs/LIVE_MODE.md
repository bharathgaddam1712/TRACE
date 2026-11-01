# Incremental live mode — design for review, not implemented

The current watch command reruns the complete authoritative pipeline. This proposal must be reviewed before incremental code replaces that behavior.

## Input and storage ownership

One writer owns DuckDB and publishes immutable result generations. Identify a source by canonical path plus file identity and fingerprint; persist byte offsets only after the corresponding normalized chunk commits. Detect truncation, replacement and mutation. On Windows, readers use the last published generation rather than opening a database owned by another writer. Publish the generation manifest atomically after all referenced files exist.

## Time and affected state

Use event time, ingestion time and a persisted watermark separately. Allowed lateness must be an explicit configuration chosen from observed input disorder; do not silently discard late events. Each rule's correlation window, incident join window and access-edge validity define its affected interval. Replay the union of these intervals plus predecessor state. A late event can merge or split components and invalidate previously published reachability or paths.

Global rarity, volume and recurrent-signal baselines can change old classifications. Until bounded sufficient statistics and retraction semantics are proven equivalent, those stages require a full rebuild. Updating only the latest incident is not correct.

## Identity, retractions and convergence

Use stable event identities and deterministic component lineage. Publish supersession links for merged/split incidents and tombstones for removed edges; never leave stale candidates attached to an old incident. Restore checkpoints and watermarks together after a crash. Avoid two independent writers to the same cache or database.

## Acceptance before adoption

Compare complete canonical output with a fresh full run for append-only input, duplicate replay, out-of-order arrival, late events across every rule/window boundary, recurrence changes, source replacement, crash recovery and component merges/splits. Check signal membership, evidence, graph edges, observation times and reachable candidates, not just counts. Measure memory and p95 end-to-publication delay on a specified arrival rate. A proposed ten-second latency on a 1 GB stream is a target requiring measurement, not a guarantee.

Until these checks pass and the design is approved, the full-run path stays the reference and live incrementality stays unimplemented.
