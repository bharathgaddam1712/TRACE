# Optimization decisions for the jury rehearsal

## Implemented safely

- Retain chunked ingestion, byte-offset quarantine, source checks, resumable checkpoints and normalized Parquet. A rejected source span remains accountable.
- Strengthen the comparison gate to compare complete incident JSON payloads, including evidence and graph identities. Matching counts and incident fingerprints alone is insufficient.
- Remove retired next-technique experiments and their full-pipeline work. Keep observed-access reachability, time-ordered paths and Sarvam's other advisory features.
- Provide an opt-in engine sweep with fresh outputs and a memory watchdog. It produces measurements; it does not change production defaults.

## Detection experiment rejected

A trial reused resolved Parquet and narrowed scope columns. Direct per-rule hit tests passed, as did the existing count/checksum gate. But complete payload comparison found differences in 21 of 52 incident files, including evidence fields and process graph identities. The experiment was reverted. Existing non-deterministic representative selection may contribute; no causal accuracy claim is made. Detection took 15.502 seconds in the reference and 16.855 seconds in the trial, so it also showed no stage speed benefit. Keep the current detection implementation until representative selection and complete-output parity are addressed explicitly.

## Deferred with reasons

| Suggestion | Decision |
|---|---|
| Raise memory to 6–8 GB | Measure only when free host RAM permits. DuckDB buffer limit is not total process RSS. The current laptop does not have 13 GB idle RAM. |
| Three native lexer workers by default | Keep the bounded one-chunk prefetch default. More workers compete for disk and increase intermediate data; benchmark before adding concurrency. |
| Narrow earliest-event deduplication | Equal timestamps currently lack a total winner order. Approve a deterministic tie policy before changing winners. |
| Remove recurrent signals before window operations | Could change saved signals, summaries and evidence. Requires full-output parity or an explicit behavior change. |
| Eight graph worker processes | DuckDB connection ownership and duplicated Python memory make this unsafe as a default on the demo host. |
| Incremental live recomputation | Design is in LIVE_MODE.md. Implementation waits for review; current watch behavior remains authoritative. |
| Relax corrupted input or restrict vendor promotion | Investigation does not support an automatic change. See ACCURACY_AUDIT.md. |

## Claims and acceptance

Keep the original protected reachability and path implementations. Validate Python, TypeScript, production build, sample pipeline, API and the actual UI. Test the new 30 GB source only after it is supplied. Record source bytes (not filename), cold versus warm cache, hardware, wall time, stage time, RSS, spill/disk use and rejection accounting.

PRD targets to test: under one hour for the supplied 15/30/50 GB sizes, peak RSS below 8 GB, planted recall above 90%, false-alarm incidents below 10% against reviewed labels, and incident opening below 500 ms. The user's under-ten-minute preference is a stretch target, not an achieved result for a new file. No linear extrapolation or historical result should be presented as a current measured run.
