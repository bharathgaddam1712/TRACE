# Operations, evidence and optional AI

## API key and model

Put `SARVAM_API_KEY` in the local repository-root `.env` file (copy `.env.example` first). Restart the API after editing it. Never put the key in frontend code or commit `.env`.

`SARVAM_MODEL=glm5.3` selects the strongest generally available reasoning option listed by Sarvam on 2026-10-31. This is a provider recommendation, not a measured security benchmark. `sarvam-105b` is the multilingual Sarvam model; `glm5.3-flash` is a lower-cost option. Availability and credits depend on the account. No live Sarvam call has been claimed without a configured key.

The Assistant offers incident explanations, evidence questions, investigation checks, ATT&CK suggestions, Sigma drafts, and multilingual reports. Each call sends bounded incident context, preserves evidence IDs, redacts common credential patterns, validates structured output and citations, and caches the result. Redaction is best effort: review the source telemetry before enabling external AI on sensitive data. Read the provider's current data-handling terms for your deployment. AI output is advisory; it cannot enable a rule, alter a detection, dismiss a case, or perform containment.

`SARVAM_DAILY_REQUEST_LIMIT` and `SARVAM_DAILY_TOKEN_LIMIT` enforce local reservations before requests. Input reservations use serialized UTF-8 bytes as a conservative estimate; output reservations include the configured reasoning/output cap. These are local controls, not a statement of the provider's bill. Failed calls and retries consume reservations. Cached results do not. Usage and audit hashes are stored in `out/<dataset>/analyst.sqlite3` by UTC date.

## Read optimization and malformed data

The native FortiGate reader parses `date=... time=... key=value` records in DuckDB, avoiding Python JSON conversion for every line. Network endpoint IPs remain distinct host identities; the firewall device is used for device authentication events. Direction, sent bytes, outcomes, signatures and source files are retained. A blocked attempt does not prove successful compromise.

Closed large ECS/FortiGate files use 256 MiB newline-aligned, resumable Parquet chunks (`ingest.chunk_bytes`). Cache identity includes source metadata and reader/schema configuration. Unchanged inputs avoid reparsing raw logs. Source modifications invalidate the corresponding snapshot. Detection and correlation still rerun globally.

Explicit append-only streams can use `--set ingest.append_only=true`: only complete newly appended lines are parsed, with incomplete tails deferred. This assumes earlier bytes are immutable. File identity and boundary anchors detect common replacement/truncation cases; they are not a cryptographic proof that an arbitrary middle section was never rewritten. Do not enable append-only mode for rewritable files. Gzip, CSV and syslog use whole-file caching.

The native FortiGate reader quarantines malformed UTF-8/format/duplicate-key byte-line fragments when needed. Compact `ingest_cache/*.quarantine.jsonl` ledgers record exact original byte offsets, lengths, hashes and bounded previews; original source bytes remain in the unchanged input file. A binary tail is not treated as security events. `reader_rejected_records` counts physical newline fragments, which need not be meaningful log records. `records_before_deduplication`, `duplicates_removed`, `events` and reader/adapter rejection counters distinguish the outcomes. `input_quality=partially_quarantined` means analysis covers only valid records. Set `--set ingest.quarantine_invalid_utf8=false` to fail instead.

Malformed ECS JSON fails by default. CSV/syslog adapter rejects retain source/line/reason diagnostics. `quarantine.parquet` retains parsed rows without usable timestamps or hosts. Treat the quality counters as part of every result.

One pipeline may write an output directory at a time. If a process was forcibly terminated, verify no writer remains before removing that output's `.pipeline.lock`. Never use an output directory inside its input directory.

## Detection coverage

The shipped pack contains 31 TRACE rules plus 1,175 compiler-compatible stable/test SigmaHQ rules from commit `05d1031f537e830b76da53bae2400c5814c89165`. The import inventory records 1,740 unsupported rules and 246 excluded statuses. Upstream authors and licensing are retained. The inventory is `rules/community/manifest.json`.

Rules are evaluated in bounded SQL batches (`detection.rules_sql_batch_size`, default 16), with declared logsource action/OS pruning. This avoids building one unbounded SQL plan. The runtime report distinguishes loaded rules from applicable rules evaluated on the input. Windows process detections cannot be evaluated meaningfully from firewall-only telemetry. Unsupported modifiers, fields and log sources are explicitly reported; loading a ruleset is not proof that every attack can be detected.

To refresh from a separately reviewed SigmaHQ checkout, import into a fresh directory:

```powershell
.\.venv\Scripts\python.exe -m tracekc rules-import --source path/to/sigma --dest rules/community-next
.\.venv\Scripts\python.exe -m tracekc rules-check
```

Do not leave overlapping old/new packs enabled together. Review the inventory, telemetry requirements, false positives and attribution before switching packs.

## Mapping and related incidents

`configs/attack_mapping.yaml` contains all 706 active Enterprise ATT&CK v20 techniques/sub-techniques and canonical replacements for revoked techniques from the official STIX bundle. Mapping output retains source technique, canonical technique, catalog version and the reason the tactic was selected. Unverified mappings remain identified as such.

Related incidents use the user's chosen policy: shared ATT&CK techniques **plus entities plus time**. Original incidents remain separate. Candidate pairs come from shared-entity indexes with hub/candidate caps, not an unrestricted all-pairs scan. Default similarity is:

`0.45 × technique Jaccard + 0.40 × entity Jaccard + 0.15 × time proximity`

An edge also requires technique overlap >= 0.30, weighted score >= 0.60 and a time gap <= 86,400 seconds. These defaults are configurable under `relationships`. Every relationship reports shared entities/techniques, component scores, threshold and reason. This is a relationship hypothesis, not proof of common attacker attribution.

Signal linking uses weighted Jaccard for weak pivots (`correlation.similarity_threshold=0.3`) while retaining specific process-identity/lateral-logon evidence. Oversized components have hard signal/host bounds. There is no fabricated time-adjacency edge when supporting links are absent.

## Graph, depth and Neo4j

The UI shows entity associations **and every materialized correlation edge**. Graph clicks expose event references, relation, evidence type, similarity and cost. Related incidents have a separate graph view. Depth-limited neighborhoods avoid loading an entire connected region unnecessarily; capped results are marked truncated. The default full incident view retains all materialized edges.

`graph.default_depth=2`, `graph.max_depth=6`, and bounded API limits control traversal. Depth-constrained Dijkstra minimizes positive evidence cost: observed associations cost 1, inferred correlation costs depend on similarity, and access hypotheses cost more. Hypothesis edges are excluded from shortest-path search by default. Dijkstra selects a low-cost route through supplied edges; it cannot establish that those edges describe the true attack.

Local adjacency indexes work without a database. For optional Neo4j:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[graph]"
# Set NEO4J_PASSWORD and NEO4J_URI in .env first.
docker compose -f docker-compose.graph.yml --profile graph up -d neo4j
.\.venv\Scripts\python.exe -m tracekc graph-sync --out out/firex-real
```

Set `TRACE_GRAPH_BACKEND=neo4j` and restart the API to use it for indexed graph retrieval and neighborhoods. URI for a local Python process is normally `bolt://127.0.0.1:7687`; for the API container sharing the Compose network it is `bolt://neo4j:7687`. The server password stays in `.env`. Synchronize again after a pipeline run changes graphs.

Synchronization uses parameterized queries, composite uniqueness constraints, 500-row batches and a dataset namespace derived from the output directory. A new generation is published only after import completes; prior generations remain available in the database. No arbitrary user-provided Cypher is executed. Weighted Dijkstra runs on the retrieved graph without requiring a separately licensed GDS plugin. Neo4j is optional; large-graph speed improvements must be benchmarked rather than assumed.

A portable Neo4j Community 5.26.32 instance with Java 21 was used for live integration testing on this machine because its Docker engine was unavailable. Its runtime files are under Git-ignored `out/runtime`, and it binds to localhost. The shipped Compose setup is the reproducible deployment path.

## Validation

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/validate_loop.py
.\.venv\Scripts\python.exe -m tracekc attack-verify --stix attack/enterprise-attack-20.0.json
```

Unit/synthetic tests verify behavior and leakage boundaries. Real-data processing validates parsing and execution, not detection accuracy without independent labels. A partially quarantined file must be reported as such.
