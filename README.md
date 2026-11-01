# TRACE: evidence-backed attack investigation

The local UI is the Next.js console at http://127.0.0.1:3000. Build results with
`scripts/demo.ps1`, build the frontend with `cd frontend; npm ci; npm run build`,
then return to the repository root and run:

```powershell
.\.venv\Scripts\python.exe scripts/start_web.py
```

The launcher starts the API and console together. SOC triage is available in an
incident's **Respond** tab. See [triage architecture](docs/TRIAGE.md).

For a previously unseen jury log, use the [fresh-file demo workflow](docs/NEW_LOG_DEMO.md).

For the full-file local demo, bounded attacker-technique sequences,
and causal temporal ML experiments, see [demo commands](docs/DEMO.md) and
[research / evaluation design](docs/TEMPORAL_RESEARCH.md). The large demo input is
stored with Git LFS as an optional earlier benchmark; the default demo uses the
complete local log. Temporal interaction scores are not attack-prediction accuracy.

TRACE reads security logs, detects suspicious behavior, maps it to MITRE ATT&CK, links related signals into incidents, builds an evidence graph, estimates possible next access, and serves an investigation UI.

The detection pipeline works offline. Optional Sarvam analysis adds explanations, investigation chat, mapping suggestions, compiler-validated Sigma drafts, and multilingual reports. AI suggestions never silently change detections, enable rules, dismiss incidents or perform containment.

## Quick start on Windows

Python 3.10+ is required. Run from the repository root:

```powershell
.\scripts\setup.ps1
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\validate_loop.py
.\.venv\Scripts\python.exe scripts/start_web.py --out out/sample-loop/planted
```

Build the Next.js frontend first (`cd frontend; npm ci; npm run build`), return to
the repository root, then use the launcher above and open http://127.0.0.1:3000. The sample loop exercises the shipped sample, a time-spread replay with a planted six-step attack, scoring, API, and cited evidence. It does not spend Sarvam credits.

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install --no-deps -e .
cp .env.example .env
.venv/bin/python scripts/validate_loop.py
.venv/bin/python scripts/start_web.py --out out/sample-loop/planted
```

## Web console (Next.js)

A web investigation console lives in `frontend/` (Node.js 20+). It reads the results of a pipeline run
through the API, so start the API first, then the console:

```bash
# 1. Results: the data ships in the repo (data/sample/edr_events.json, 10,000 EDR events)
.venv/bin/tracekc run --input data/sample --out out/web       # or: scripts/validate_loop.py -> out/sample-loop/planted
# 2. API on :8000
.venv/bin/tracekc serve --out out/web
# 3. Console on :3000 (second terminal)
make web
```

Windows (PowerShell): the same steps with `.\.venv\Scripts\python.exe -m tracekc run --input data/sample --out out/web`,
`.\.venv\Scripts\python.exe -m tracekc serve --out out/web`, then `cd frontend; npm ci; npm run build; npm run start`.
To analyse other logs, point `--input` at a folder of your own files. See [frontend/README.md](frontend/README.md).

## Where to put the Sarvam API key

Create **`.env` in this repository root**, beside `pyproject.toml`. Setup creates a blank template automatically. Edit:

```dotenv
SARVAM_API_KEY=your_real_key_here
SARVAM_MODEL=glm5.3
SARVAM_REASONING_EFFORT=high
SARVAM_MAX_TOKENS=8192
SARVAM_DAILY_REQUEST_LIMIT=50
SARVAM_DAILY_TOKEN_LIMIT=500000
```

Restart the API, open an incident, select **Assistant**, choose a task and click **Ask Sarvam**. The key is loaded on the server; do not put it in JavaScript, YAML, a URL, chat, or a Git commit. `.env` is Git-ignored and excluded from Docker build context. Existing environment variables take precedence over `.env`.

Default model: **`glm5.3`**, Sarvam's strongest generally available reasoning choice in its catalog as checked on 2026-10-31. This is a provider recommendation, not a TRACE security benchmark. Set `SARVAM_MODEL=sarvam-105b` for Sarvam's own multilingual model, or `glm5.3-flash` for lower cost. Beta models require separate access; TRACE does not assume it. See [Sarvam's current model catalog](https://docs.sarvam.ai/api/token-factory/models) and [Chat Completion V2](https://docs.sarvam.ai/api-reference/chat/chat-completions-v2).

Without a key, detection, graphs, prediction, reports and analyst notes still work; the Assistant explains how to enable AI. See [operations and AI behavior](docs/OPERATIONS.md).

## The seven stages

| Stage | Implementation | Current behavior |
|---|---|---|
| Read | `ingest.py`, `adapters.py` | DuckDB, explicit ECS schema, compressed Parquet, native FortiGate `.log`, ECS/NDJSON/gzip, CSV and timestamped syslog; normalization, deduplication, quality metrics and quarantine; unchanged-file and resumable chunk caches |
| Detect | `sigma.py`, `detect.py`, `rules/` | 48 TRACE rules (17 for Active Directory) + 1,175 compatible SigmaHQ rules, vendor alerts, lateral logons, host/fleet volume baselines, rare process lineage; suppressions and recurrence controls |
| Map | `label.py`, `configs/attack_mapping.yaml` | ATT&CK v20 mapping, parent fallback, tactic validation, multiple technique IDs retained; official STIX verification |
| Link | `correlate.py` | Account/host/IP/time pivots, stable process entities and lateral-logon edges, hub guards, over-merge guards, actual link provenance |
| Graph | `materialize.py` | Hosts, users, IPs, processes, events, domains, files and registry entities; event IDs on edges; server-side entity/time filters |
| Predict | `reach.py`, `forecast.py` | Access evidence restricted to incident time, evidence/session expiry, next-target hypotheses; optional historical next-technique baseline with chronological holdout |
| Show | FastAPI, `web/` | Search/filter, timeline, clickable evidence graph, next-target view, analyst status/notes/history, reports, findings and optional Sarvam assistant |

## Process your own logs

```powershell
.\.venv\Scripts\python.exe -m tracekc run --input "C:\Users\bhara\Downloads\Firex Logs\firex-10G.log" --out out/firex10 --set engine.memory_limit=5GB
.\.venv\Scripts\python.exe -m tracekc serve --out out/firex10
```

A directory is searched recursively for `.log`, `.json`, `.ndjson`, `.jsonl`, `.csv`, `.syslog` and configured gzip forms. The native reader recognizes FortiGate key=value records and reports malformed/binary spans explicitly. Only complete downloaded files should be processed; `.part` files are not discovered. The extension does not establish the format.

CSV accepts dotted ECS column names plus aliases such as `timestamp`, `host`, `user`, `action`, `src_ip`, `dst_ip`, `dst_port`, `bytes`, `process_name` and `command_line`. Array values can be JSON arrays or semicolon-delimited. For detection, map actions to the ECS contract (e.g. `process_created`, `network_connection`, `user_logon`). Syslog requires an explicit ISO8601 timestamp and host; generic syslog messages are preserved but are not automatically parsed into Windows/process/network actions. Legacy yearless RFC3164 is rejected rather than assigned an invented date.

Domain controller logs in Winlogbeat ECS form (`winlog.event_id`, `winlog.event_data.*`) feed the Active Directory rules in `rules/active_directory.yml`: Kerberoasting, krbtgt weak-encryption (golden ticket), password spraying via 4771/4776/4625, DCSync and replication-rights grants, DCShadow, Tier-0 and privileged group additions, AdminSDHolder, SPN and delegation changes, GPO/SYSVOL changes and sensitive or bulk LDAP searches. Enable DC auditing for Kerberos Service Ticket Operations, Kerberos Authentication Service, Credential Validation, Security Group Management, Directory Service Access and Directory Service Changes; LDAP rules also need Directory Service event 1644 (field engineering logging). Records without `event.id` are de-duplicated with `winlog.record_id`. Azure AD Connect `MSOL_*` accounts replicate legitimately and belong in `configs/suppressions.yaml`.

Malformed ECS JSON fails by default. `--set ingest.ignore_errors=true` permits DuckDB's tolerant reader, with invalid/missing-time/host rows quarantined when represented by the reader. Adapter rejections retain source/line/reason diagnostics. Inspect metrics before trusting a run.

Unchanged inputs reuse normalized Parquet. Large closed files use resumable chunks; explicitly append-only ECS/FortiGate streams can read only newly completed lines. Changed files outside append-only mode are reprocessed, and detection/correlation still rerun globally. See the assumptions and limits in [operations](docs/OPERATIONS.md). Cache storage persists under the output directory. Use a separate output directory for each dataset; output must not sit inside its input directory.

## Outputs and investigation API

| Output | Purpose |
|---|---|
| `index.json`, `incidents/<id>.json` | Ranked incidents, timeline, evidence graph, correlation links, lookahead, forecast, report and stable fingerprint |
| `evidence.parquet` | Normalized events referenced by signals/access hypotheses for drill-down |
| `signals.parquet`, `step_index.parquet` | Full signal/incident audit trail |
| `findings.json`, `suppressed.json` | Isolated signals and audited suppressions |
| `quarantine.parquet`, `ingest_manifest.json`, `ingest_cache/` | Data quality, source manifest and reusable ingestion cache |
| `progress.json`, `run_metrics.json` | Current stage, errors, timings, memory and counts |
| `analyst.sqlite3` | Local analyst history, AI cache, usage reservations and AI audit hashes |

Endpoints: `GET /health`, `/progress`, `/metrics`, `/findings`, `/incidents?q=&min_score=&status=&tactic=&limit=&offset=`, `/incidents/{id}`, `/incidents/{id}/path`, `/incidents/{id}/graph?entity=&start=&end=`, `/incidents/{id}/evidence/{event_id}`, `/incidents/{id}/report`, `/ai/status`. Writes: `POST /incidents/{id}/case` and `/incidents/{id}/ai`. Schemas are at `/docs`.

The server binds to localhost by default. When explicitly sharing it, configure `TRACE_API_TOKEN` and use the UI's API connection field. Analyst notes use optimistic version checks and persist by incident fingerprint. This is a local single-team investigation tool, not a multi-tenant SOC platform.

## Prediction and evaluation

A reachable asset is **not confirmed compromised**. Access confidence is evidence strength; incident scores are priority heuristics, not probabilities. Observed shared entities do not prove causation. The graph and report preserve these distinctions.

Next-technique forecasting is disabled until you supply dated historical incident sequences. No model is trained on the sample and represented as production-ready. `tracekc train-forecast` produces an auditable transition baseline with a strict time split, held-out coverage/accuracy, source hash, and a training cutoff checked against each incident. See [operations](docs/OPERATIONS.md#historical-next-technique-model).

```bash
tracekc rules-check
python scripts/fetch_attack.py --version 20.0
tracekc attack-verify --stix attack/enterprise-attack-20.0.json
tracekc eval --out out/firex10 --gt path/to/ground_truth.json --save out/firex10/eval.json
```

Small sample and synthetic replay results do not establish accuracy or performance on the 6–30 GB Firex tiers. Measure the full input's memory, timings, false positives and ground-truth scores separately. Whole-process RSS can exceed DuckDB's buffer cap because Python graphs and signals also use memory.

## Docker

```bash
docker compose run --rm pipeline
docker compose up api
```

Place logs in `data/raw/`. For optional AI, pass `SARVAM_API_KEY` and other variables through your deployment environment (Compose forwards them); `.env` is never baked into the image. The Compose API uses an explicitly configured container bind address.

## References and licenses

The implementation retains TRACE's focused DuckDB pipeline. CERT-Shield informed the idea of structured/bilingual reporting; Vigil informed investigation/case UX. No code was copied from either project. Cytoscape.js is vendored for offline use with its MIT license in `web/vendor/CYTOSCAPE-LICENSE.txt`. Project rules retain their authors; preserve author/license attribution when adding third-party Sigma rules.
