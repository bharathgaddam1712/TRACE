# TRACE v2: Final Implementation Plan
Mitigata CyberForge · PRD "Kill Chain and Attack Path Analysis" (30 Oct 2026) · Revised 31 Oct 2026

**Goal:** Find the planted attack steps, label them with ATT&CK, link them into ordered paths, and show what the attacker can reach next. It must be correct first, then fast, and must never exceed the memory cap.

**Decision (changed from v1):** Use one DuckDB streaming pass (Spark is dropped). It cuts the raw logs down to a small "signal set". Run Sigma-format rules, first-seen/rarity detectors and volume detectors on that set. Then build an entity-and-time graph and link alerts in ATT&CK order to form incidents. Look ahead with a BloodHound-style privilege graph. Precompute all incident JSON. No ML model sits on the critical path.

---

## 0. What the PRD actually optimises for, and what follows from it

| PRD fact | Consequence for the design |
|---|---|
| The same planted attack sequences appear at 15, 30 and 50 GB | Extra volume is benign noise. The attack is a constant handful of lines, so the job is a **funnel**: scan everything once and keep only what could matter. |
| 50 GB in under 1 hour (Great) needs only ~14 MB/s | Raw throughput is not the hard problem. A columnar engine reading from SSD has a large margin. **Accuracy is the bottleneck**, so spend the time there. |
| The accuracy gate applies to higher tiers, and Extreme scores 1.6× | If the funnel works, the pipeline is identical at every tier. **Target Extreme (50 GB)** after a 15 GB baseline passes. |
| False alarms are counted **per incident**, not per event | Detect liberally at event level (recall) and be strict when promoting to an incident (precision). |
| "Right steps in the right order" | Ordering and step-boundary correctness is scored separately. It needs timestamp normalisation, skew tolerance and a tie-break policy. |
| Peak memory under 8 GB (Great) | Use a hard engine memory cap with spill-to-disk. A JVM plus Python plus OS on a 16 GB laptop makes this harder to guarantee, which is one reason Spark was dropped. |
| Investigation under 500 ms | Serve precomputed JSON. No query runs on page load. |
| The PRD suggests DuckDB, NetworkX and Sigma | These choices match what the judges expect, which simplifies "must run easily". |

---

## 1. Architecture

```
raw logs (15/30/50 GB, mixed formats)
   │  PASS 1: DuckDB, multi-threaded, memory_limit=5GB, temp_directory on SSD
   │   ├─ format router (per file: JSON / CSV / syslog / key=value / Windows XML …)
   │   ├─ typed normalisation → events (projected columns only)
   │   ├─ entity resolution keys (host, user, ip canonical forms)
   │   ├─ write: events.parquet  (partitioned by date/source, zstd)
   │   └─ write: entity_edges.parquet (user→host logons, ip→host, group membership, flows)
   ▼
PASS 2: DuckDB SQL over Parquet (still out-of-core)
   ├─ Sigma single-event rules → SQL WHERE
   ├─ Sigma correlation rules (event_count / value_count / temporal_ordered) → window SQL
   ├─ first-seen / rarity detectors (per entity baseline)
   ├─ volume detectors (bytes out vs. host's own baseline)
   └─ write: detections.parquet   ← usually KBs–MBs, not GBs
   ▼
PASS 3: in-memory Python (detections + entity graph fit in RAM)
   ├─ ATT&CK labelling (pinned STIX v20.0)
   ├─ correlation graph → incidents (kill-chain-consistent linking)
   ├─ FP gate + incident scoring (B-1) + merged-alert counts (B-3)
   ├─ look-ahead on privilege graph (FR-6)
   └─ materialise incidents/*.json + index.json + narrative (B-2)
   ▼
FastAPI (reads JSON into memory at start-up) + static page (Cytoscape.js)
```

**Why DuckDB over PySpark (main change):** single-node workload; vectorised out-of-core joins, aggregations and windows; `ASOF JOIN` for "nearest previous event"; native Parquet; one `pip install`; no JVM, so peak RSS is predictable through `SET memory_limit`. Spark's strength is the cluster, which the PRD does not require. **Fallback:** if DuckDB misses the 1-hour target on 50 GB in the Phase 3 benchmark, partition the input by file and run N DuckDB processes, or try Polars streaming. Do not switch to Spark unless measured.

**Never on the hot path:** per-line Python parsing (~20–50 MB/s per core makes 50 GB take 20–40+ min on one core), `.fetchall()` of raw data, Python UDFs.

---

## 2. Technology choices (verified 31 Oct 2026)

| Component | Choice | Notes |
|---|---|---|
| Bulk engine | **DuckDB** (pin version) | `memory_limit`, `threads`, `temp_directory`, `preserve_insertion_order=false` for less memory on large writes |
| Storage | Parquet (zstd), partitioned by date/source | Keep a `raw_ref` (file, byte offset or line number) for drill-down |
| Unknown formats | **Drain3** template mining **on the 100 MB sample only** | Compile the mined templates into regexes that DuckDB runs at scale. Drain3 is too slow to run on 50 GB in Python. |
| Rules | **Sigma YAML** (v2 spec, including **correlation rules**) → own small compiler to DuckDB SQL | No DuckDB pySigma backend exists. Copy the design of `pySigma-backend-sqlite`, which implements `event_count`, `value_count`, `temporal`, `temporal_ordered` with backward-inclusive windows. Use pySigma only for parsing and validation. This delivers **B-4** directly. |
| ATT&CK | Enterprise **v20.0** STIX (released 13 Oct 2026), pinned by file hash | Store technique ↔ tactic(s) mapping and keep sub-technique IDs |
| Graph | NetworkX (in-memory, small) | No Neo4j: the graph is detections plus entities, not raw logs |
| API / UI | FastAPI + static HTML + Cytoscape.js | Docker Compose for one-command start (a PRD plus) |
| Narrative (B-2) | Deterministic templates over incident JSON; optional LLM rewrite behind a flag | The text may only cite fields in the incident JSON |
| **Removed** | Spark, DataFusion Comet, MiniLM, LogFormer, ONNX, Wazuh | See §9 |

Licensing: Sigma rules use DRL-1.1, so show rule author attribution in the UI and the JSON. Check the licence of every pinned dependency.

---

## 3. Stage-by-stage build and exact deliverables

### Stage 0: Data contract (first half-day, blocks everything)
- From the 100 MB sample: list the files and formats, field inventory per source, timestamp formats and time zones, identity forms (`DOMAIN\user`, `user@dom`, `USER`), host forms (FQDN vs. short name, case), IP↔host mappings (DHCP/DNS), and **ground-truth format** (event IDs? line numbers? technique granularity: `T1110` or `T1110.001`? stage taxonomy: ATT&CK tactic or Lockheed kill chain?).
- Deliverable: `docs/data_contract.md` and `fixtures/` (gold attack lines plus tricky benign lines).
- **Build the scorer now** (`eval/score.py`), implementing the PRD's four accuracy metrics exactly (see §6). Every later change is judged by it.

### Stage 1: Ingest and normalise (PASS 1)
- Route by file and format. Use DuckDB `read_json` / `read_csv` with explicit schemas; for syslog and other text use `read_text`/`read_csv(sep=...)` + `regexp_extract` built from the Drain3 templates.
- Normalise: `ts` (UTC, keep `ts_raw` and `ts_source_tz`), `event_id` (stable hash of file+offset), `source`, `event_type`, `host`, `user`, `src_ip`, `dst_ip`, `session_id?`, `process?`, `status?`, `bytes_out?`, `raw_ref`.
- Quarantine unparseable lines into `bad_rows.parquet` with counts per file. They are counted, never silently dropped.
- **Entity resolution (new):** lowercase, strip the domain from users into `user_canon` (keep `user_raw`); map FQDN to a short host name; map IP to host **by time interval** from DHCP/DNS or logon events (`ASOF JOIN`). Linking across sources without this step is the most common cause of broken paths.
- Deduplicate on `event_id` and on exact duplicate ingest records.

### Stage 2: Detect (PASS 2), three detector families
1. **Sigma rules** (single-event and correlation). Start with the PRD's own examples and whatever the sample shows:
   - brute force then success: `event_count` failures ≥ N by (user | src_ip) in W, then `temporal_ordered` success → **T1110** (sub-technique by pattern: many passwords against one user = `.001`, one password against many users = `.003`).
   - new local/domain admin or group change → **T1098** / **T1136**, only when the operation field supports it.
   - remote service logon (RDP/SMB/WinRM/SSH, by logon type or port) → **T1021.x**.
   - discovery bursts, credential dumping, persistence, and so on, **only if the telemetry contains them**.
   - large or unusual outbound transfer to an external IP → **T1048 / T1041 candidate** (labelled "possible exfiltration" unless corroborated).
2. **First-seen / rarity (NoDoze idea).** Flag the first time this user logs on to this host, the first admin action by this account, the first contact from this host with this external IP, and a process or command rare across the fleet. This catches planted steps that no hand rule anticipated, and the planted attacks are by construction rare among benign noise. The detector returns a rarity score, not a verdict.
3. **Volume anomalies.** `bytes_out` per host per window compared with that host's own median/MAD baseline. Computed with SQL windows.

Output `detections`: `det_id, rule_id, rule_source(sigma/rarity/volume), event_ids[], ts_first, ts_last, entities{user,host,src_ip,dst_ip}, severity, rarity, evidence{fields}`.

### Stage 3: Label
- `rule_id → technique_id(s)` comes from the rule's `tags: attack.tXXXX` (the Sigma convention). Look up the tactic(s) in the pinned v20 STIX, and resolve techniques with several tactics by context (for example T1078 Valid Accounts maps to Initial Access when the source is external and to Persistence or Privilege Escalation otherwise).
- Keep **both** `attack_tactic` and `kill_chain_stage` until the expected taxonomy is confirmed. Default `kill_chain_stage` = ATT&CK tactic, which matches the PRD example "→ Credential Access".
- Emit the **sub-technique and the parent** so the scorer can match either convention. Set `technique = null` when the evidence is weak. Do not force a label.

### Stage 4: Correlate into incidents (core of FR-4 and path order)
1. **Candidate edges** between detections a→b when all hold:
   - **Entity continuity:** the same `user_canon`, **or** b's host = a's destination host (the attacker moved there), **or** the same session ID. A shared IP counts only if that IP is not a NAT, proxy or high-fan-in IP (computed: the number of distinct users or hosts behind it).
   - **Time:** `0 ≤ ts_b − ts_a ≤ Δmax` (configurable; skew tolerance ±ε for cross-host events).
   - **Kill-chain plausibility (HOLMES / RapSheet idea):** b's tactic index ≥ a's − 1 (it allows small backtracking, such as discovery after lateral movement, but not exfiltration → initial access).
2. **Incidents** = weakly connected components of this graph, then split any component that has a time gap > G.
3. **Path order:** sort by `ts`; break ties by tactic order and then event sequence number. Mark each edge `observed` (shared session or concrete logon) or `inferred` (time and entity only), with a `link_reason`.
4. **Host path for FR-5:** derive `HR-07 → FS-02 → DC-01` from the lateral-movement and logon edges inside the incident.

### Stage 5: FP gate and scoring (precision lever, and B-1 and B-3)
- **Incident score** = Σ severity × rarity, plus a bonus for each distinct tactic covered, plus a bonus for a monotonic tactic progression (the longest kill-chain-ordered subsequence, as in RapSheet).
- **Promote to incident** only if it covers ≥ 2 distinct tactics **or** it has one critical detection (for example a confirmed admin creation followed by external transfer). Everything else becomes `isolated_findings`, which is still visible and auditable but is **not counted as an incident**.
- Suppress with recorded reasons: known service accounts (verified in the data), duplicate signals, scheduled-job patterns (the same action every day at the same time).
- `merged_alert_count` = raw detections folded into each incident (**B-3**). Sort incidents by score (**B-1**).

### Stage 6: Look ahead (FR-6), BloodHound-style privilege graph
- Build edges **only from observed data**: `User –AdminTo→ Host` (from successful admin or privileged logons and group membership), `User –HasSession→ Host` (interactive logons, where credentials may be exposed), `User –MemberOf→ Group`, `Host –CanReach→ Host:port` (from successful network flows).
- Start from the compromised principals and hosts in the incident and BFS ≤ k hops. The output is a ranked list: `{asset, via_path, evidence_event_ids, confidence}`.
- Example output: "svc-backup has admin on FS-03, FS-04, DC-01 (from logons on …)". If no permission data exists, return `next_hop: unknown` and give the reason.

### Stage 7: Materialise and serve (FR-5, FR-7)
- Write `out/index.json` (sorted incident list) and `out/incidents/{id}.json` (timeline, nodes, edges, techniques, look-ahead, narrative, raw-event pointers).
- FastAPI loads everything into memory at start-up: `GET /incidents`, `GET /incidents/{id}`, `GET /incidents/{id}/path`, `GET /events/{event_id}` (drill-down reads `raw_ref` with a byte-offset seek), `GET /health`. Expected p95 is well under 50 ms; measure it.
- Static page: an incident list, a timeline and a Cytoscape graph of hosts and users, with edges coloured observed or inferred.

### Stage 8: Validate and benchmark
- Run `eval/score.py` on every change. Freeze the thresholds before running the full tiers.
- `benchmarks/results.json`: per-stage seconds, total wall time, **peak process-tree RSS** (sampled with `psutil` every 0.5 s), spill GB, API p95, plus the four accuracy metrics, the ruleset hash and the STIX hash. Record cold and warm runs and the machine spec.

---

## 4. Bonus features (build after FR-1 to FR-7 pass)
| ID | How | Cost |
|---|---|---|
| B-1 risk score | Stage 5 score | ~free |
| B-3 merged count | Stage 5 | ~free |
| B-4 Sigma config | Stage 2 compiler: drop a YAML into `rules/` and re-run | ~free by design |
| B-2 report | Template narrative from incident JSON; optional LLM polish behind a flag, given only the JSON and told to cite event IDs | low |
| B-5 live mode | Tail new files every N s, run PASS 1–2 on the micro-batch only (detections are incremental), re-run PASS 3 (it is small, so this takes seconds) and push over SSE. Rarity baselines come from the batch run. | medium; do last |

---

## 5. False-positive controls (concrete)
- **Event level:** thresholds come from the sample's benign distribution (for example the 99.9th percentile of failures per user per 10 min), not from intuition. "40 failed logins" alone is an isolated finding, not an incident.
- **Linking:** shared NAT/proxy IPs, "same hour" and the same popular server are **not** links. High-fan-in entities are down-weighted automatically.
- **Promotion:** at least 2 tactics or 1 critical detection (Stage 5).
- **Negative fixtures** in `tests/`: a benign brute-force-like password-expiry storm, a shared NAT IP between two unrelated users, an out-of-order timestamp across hosts, a backup job's large upload, and a service account logging on everywhere.
- **Calibration discipline:** tune on the dev sample, freeze the thresholds, and only then run the full tiers. Track missed steps, false detections, false joins and wrong labels **separately**.

---

## 6. Scorer: implement the PRD metrics exactly
- **Step match:** a planted step counts as detected if a detection contains its event ID. If the ground truth has no IDs, match on (host, user, ts ± tolerance, event type).
- **Detection** = matched planted steps / all planted steps.
- **Labels** = matched steps whose technique is correct / matched steps (report both strict sub-technique and parent-level matching).
- **Path** = planted attacks whose steps all fall in **one** predicted incident **in the correct order** / all planted attacks.
- **False alarms** = predicted incidents that overlap no planted attack / all predicted incidents.
- Watch the trade-off: over-splitting one attack into 3 incidents hurts the path metric. Over-merging two attacks hurts order and labels. Log both cases.

---

## 7. Performance plan (measured, not assumed)
- **Budget sketch for 50 GB** (validate on real hardware): SSD read at ~1–2 GB/s; DuckDB parse and normalise is the dominant cost; PASS 2 runs over compact Parquet; PASS 3 takes seconds. Target ≤ 30 min end-to-end on an 8-core laptop, leaving headroom under the 1-hour Great target.
- **Memory:** `SET memory_limit='5GB'`, `SET threads=<cores>`, `temp_directory` on SSD. Peak RSS target ≤ 7 GB for the whole process tree.
- **Levers, in order of expected payoff:** project only the needed columns at read time; push the rule pre-filters into PASS 1 (a cheap `WHERE event_type IN (…)` before regex); avoid wide string columns (dictionary-encode `event_type`, `host`, `user`); run one file per thread to stay parallel; and if PASS 1 is the bottleneck, skip writing full `events.parquet` and write only `signal_events` (candidate rows) plus aggregates. This is a benchmark decision, because it costs replayability.
- **Disk:** 50 GB raw, plus ~5–15 GB Parquet, plus spill. Check free SSD space before choosing the tier.

---

## 8. Repo layout
```
trace/
├── configs/            # thresholds.yaml, stage_policy.yaml, entity_rules.yaml (NAT/service accounts)
├── rules/              # Sigma YAML (single + correlation), with author attribution
├── attack/             # pinned enterprise-attack-20.0.json + sha256
├── src/trace/
│   ├── ingest.py       # PASS 1: format router, normalisation, entity resolution
│   ├── sigma_sql.py    # Sigma (incl. correlation) → DuckDB SQL
│   ├── detect.py       # PASS 2: sigma + rarity + volume
│   ├── label.py        # ATT&CK STIX lookup + stage policy
│   ├── correlate.py    # edge rules, components, ordering
│   ├── score.py        # FP gate, incident score, merged counts
│   ├── reach.py        # privilege graph + BFS look-ahead
│   ├── narrate.py      # template report (+ optional LLM flag)
│   ├── materialize.py  # JSON outputs
│   ├── api.py          # FastAPI
│   └── run.py          # orchestration, per-stage timings, RSS sampler
├── eval/score.py       # PRD metrics vs ground truth
├── tests/              # positive + negative fixtures
├── benchmarks/         # results.json per tier
├── web/                # index.html + Cytoscape
├── docker-compose.yml
├── requirements.lock
└── README.md           # one-command run: `docker compose up` or `make run TIER=15`
```

---

## 9. Changes from v1, and why

| v1 | v2 | Reason |
|---|---|---|
| PySpark local mode | **DuckDB** | Single node; predictable RSS (no JVM); simpler setup for judges; recommended by the PRD; the needed throughput is low |
| Comet acceleration trial | Dropped | It only speeds up Spark, which is gone |
| MiniLM / LogFormer / ONNX A/B track | **Dropped from the plan** | Sentence-embedding similarity is not a detector and the dataset has too few labelled windows. "Sometimes Simpler is Better" (USENIX Sec 2025) supports simple baselines. Use the time on rules and correlation instead. |
| Rules only | Rules + **first-seen/rarity** + volume | The planted steps are rare by construction. Rarity catches what no rule anticipated, which raises recall. |
| Hand-coded Sigma "inspiration" | **Sigma v2 correlation rules → DuckDB SQL** | One mechanism for FR-2 (count-then-success) and B-4 |
| No entity resolution | **Explicit entity resolution stage** | Cross-source linking fails without canonical users, hosts and IP→host mapping |
| Generic temporal joins | **Kill-chain-consistent edges + longest-progression score** (HOLMES / RapSheet) | Improves path order and gives a principled promotion rule that lowers false incidents |
| "Reachability where present" | **BloodHound-style AdminTo/HasSession/MemberOf graph from observed events** | A concrete, evidenced answer to the PRD's "admin rights on 3 more servers" |
| Scorer late (Stage 8) | **Scorer in Stage 0** | Every tuning decision needs the metric |
| Tier undecided | **Baseline at 15 GB → commit to 50 GB** if the gate holds | The same attacks appear at every tier, so 1.6× is cheap if the funnel holds |
| Wazuh references | Dropped | Sigma already covers this and avoids a second rule dialect |

**Research used, as ideas and not as implementations:** TAPAS (USENIX Sec 2025) is confirmed to be about online APT detection on *process provenance graphs*. It needs audit-level process telemetry this dataset likely lacks, so we borrow only "graph the backbone, not every line". HOLMES and RapSheet supply kill-chain-ordered alert graphs and tactic-progression scoring. NoDoze supplies rarity-based alert triage. Recent LLM-guided investigation work (ANANKE 2025; TTP-guided reconstruction, ICCS 2026) structures reasoning by kill-chain phase. We use the same phase structure deterministically and keep any LLM to the narrative only.

---

## 10. Delivery order (each phase ends green on the scorer)
1. **Phase 1, skeleton end-to-end on the 100 MB sample:** data contract → scorer → PASS 1 for the main formats → 2 rules (brute force → success; new admin) → labels → 1 incident JSON → API → page. *Gate: one planted attack is visible end-to-end.*
2. **Phase 2, accuracy on the sample:** all observed-telemetry rules, rarity and volume detectors, entity resolution, correlation, FP gate, negative tests, look-ahead. *Gate: the sample hits the Great accuracy targets with frozen thresholds.*
3. **Phase 3, scale:** 15 GB run with RSS/time profiling; fix the largest stage; then 30 and 50 GB. *Gate: accuracy unchanged across tiers, ≤ 1 h, ≤ 8 GB.*
4. **Phase 4, bonuses and packaging:** B-1, B-3 and B-4 come almost free; then B-2, Docker Compose and the README; B-5 last.

**Unknowns until the data arrives (never assume them):** formats and encodings, the ground-truth format and label granularity, the stage taxonomy, whether permission or group data exists, clock skew between sources, and the free SSD space on the judging machine.

**Final rule:** the winner is the evidenced, correctly ordered reconstruction that finishes in time on 50 GB, not the most sophisticated stack. Every component must earn its place on the scorer.
