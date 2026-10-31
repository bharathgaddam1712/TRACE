# TRACE: kill chain and attack path reconstruction

TRACE reads a large pile of security logs and finds the attacks hidden in them. It labels each step
with MITRE ATT&CK (v20.0) and links the steps into ordered incidents across hosts, accounts, IPs and
time. For each incident it serves a timeline, a host/user graph, a plain-English report and a list of
what the attacker could reach next. This is the implementation of `docs/TRACE_PLAN_v2.md`.

```
raw NDJSON ──PASS 1 (DuckDB, streaming, memory-capped)──> events.parquet + IP->host map
           ──PASS 2──> detections: Sigma rules (1 scan) + Sigma correlations + EDR alerts + lateral/volume/rarity
           ──label──> ATT&CK technique -> tactic -> kill-chain stage (pinned v20.0, STIX-verified)
           ──correlate──> signals (deduped) -> pivot sessions -> incidents -> FP gate + risk score
           ──materialize──> out/index.json, out/incidents/<id>.json  ──> FastAPI + web page
```

## 1. Requirements
- Python 3.10 or newer (tested on 3.14.4, Linux x86_64). Or Docker with Compose.
- RAM: DuckDB is capped by `engine.memory_limit` (default 5 GB) and spills to disk beyond it.
  Peak RSS for the whole process is recorded in `out/run_metrics.json`.
- Disk: an SSD with free space of about 1.5× the input size for Parquet and spill files.
- Internet access only for `pip install`, the Cytoscape script on the web page and the optional
  ATT&CK download. The pipeline itself runs offline.

## 2. Quick start (local)
```bash
unzip trace.zip && cd trace
make setup                 # creates .venv, installs pinned deps (+ pytest)
make test                  # 18 tests, ~5 s: Sigma compiler + end-to-end on sample and planted chains
make demo                  # sample + planted attack -> out/demo, prints the score
.venv/bin/tracekc serve --out out/demo     # http://localhost:8000
```
Without `make`:
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt && .venv/bin/pip install --no-deps -e .
.venv/bin/tracekc run --input data/sample --out out/sample
.venv/bin/tracekc serve --out out/sample
```

## 3. Running on the real tiers
```bash
# logs anywhere under data/raw/ (*.json, *.ndjson, *.jsonl, optionally .gz), searched recursively
.venv/bin/tracekc run --input data/raw --out out/core15 --set engine.memory_limit=6GB
.venv/bin/tracekc serve --out out/core15
.venv/bin/tracekc eval --out out/core15 --gt path/to/ground_truth.json --save out/core15/eval.json
```
For a 16 GB laptop, `memory_limit` of 5–6 GB leaves room for the OS and Python. For the "Great" 8 GB
target, keep it at 5 GB. `tracekc run` prints per-stage seconds and peak RSS, and writes everything
to `out/<run>/run_metrics.json`.

### Docker Compose
```bash
mkdir -p data/raw out work && cp /path/to/logs/*.json data/raw/
docker compose run --rm pipeline        # writes ./out
docker compose up api                   # http://localhost:8000
```

## 4. Outputs and API
| Path | Content |
|---|---|
| `out/index.json` | incidents sorted by risk score (B-1) |
| `out/incidents/<id>.json` | timeline (ATT&CK technique, tactic, kill-chain stage, Lockheed phase, evidence, event ids, why each step is linked: observed or inferred), host path, graph, look-ahead, narrative (B-2), `merged_alert_count` (B-3), Sigma author attribution |
| `out/findings.json` | isolated findings that were not promoted; kept, never dropped |
| `out/suppressed.json` | audited suppressions from `configs/suppressions.yaml` |
| `out/signals.parquet`, `out/step_index.parquet` | every signal and every event-to-signal-to-incident mapping (audit, scoring) |
| `out/run_metrics.json` | stage timings, peak RSS, counts, ruleset hash, ATT&CK version, machine |

| Endpoint | |
|---|---|
| `GET /health` | status and incident count |
| `GET /incidents?min_score=&limit=` | list (B-1 order) |
| `GET /incidents/{id}` | full incident |
| `GET /incidents/{id}/path` | timeline + host path + graph + look-ahead (FR-7 example route) |
| `GET /incidents/{id}/report` | plain-English report (B-2) |
| `GET /findings`, `GET /metrics` | isolated findings, run metrics |
| `GET /` | web page: incident list, Cytoscape graph, timeline, look-ahead, report |

Everything is served from memory, built once from the JSON files, so opening an incident path takes
about 3 ms in tests. The API reloads automatically when `index.json` changes.

## 5. How it works (and where)
| Stage | File | What it does |
|---|---|---|
| Ingest | `src/tracekc/ingest.py` | `read_json` with an explicit ECS schema (no inference pass), multi-threaded, gzip-aware; normalises time to UTC epoch ms, accounts (`CORP\Bob`, `bob@corp` -> `bob`) and hosts (FQDN -> short upper-case); stable event ids; deduplicates; quarantines rows with no time or host; builds the IP -> host map for entity resolution |
| Rules | `src/tracekc/sigma.py`, `rules/*.yml` | own Sigma -> DuckDB SQL compiler. Single-event rules (contains/startswith/endswith/all/re/cidr/gt/gte/lt/lte, `1 of`/`all of`/`not`/parentheses) and Sigma v2 **correlation rules** (`event_count`, `value_count`, `temporal_ordered`). All single-event rules run in one scan |
| Detect | `src/tracekc/detect.py` | Sigma + correlations; EDR `kind=alert` rows our rules didn't cover; built-ins: first-seen lateral logon (only from a host or account that already shows medium+ activity), unusually large outbound volume to a rare external destination (median + k·MAD, hourly), rare parent->child process |
| Label | `src/tracekc/label.py`, `configs/attack_mapping.yaml` | technique -> valid tactics (rule tag picks among several) -> kill-chain stage + Lockheed phase; sub-technique falls back to its parent; `attack-verify` checks the table against MITRE STIX |
| Correlate | `src/tracekc/correlate.py` | collapse repeats into signals (B-3); recurrence filter; link via pivot sessions (user, host+account, host, external IP, host+process id) + lateral-logon ASOF edges; hub guards; union-find components; over-merge split; FP gate; risk score |
| Look ahead | `src/tracekc/reach.py` | BloodHound-style graph from observed logons (CanLogon), 4672 (AdminTo), interactive sessions (credential exposure, 2 hops) and admin-port flows (NetReach). "unknown" when there is no evidence |
| Materialize | `src/tracekc/materialize.py` | incident JSON, graph, grounded narrative, findings |
| API / UI | `src/tracekc/api.py`, `web/index.html` | FastAPI + one static page |
| Score | `src/tracekc/evaluate.py` | PRD metrics: detection, label (strict and parent), ordered path, false-incident rate |

### False-positive controls (precision levers)
1. **Duplicate signals collapse.** Identical alerts (same technique, entities and command line, registry
   key or file) with gaps under `dedupe_window_s` become one signal, and the merged count is kept. A signal
   never spans more than one recurrence bucket, so an attack step cannot disappear into hours of repeating noise.
2. **Recurrence.** An identical alert fingerprint (rule, host, account, addresses, command line, registry
   key, file) seen in at least `recurrence_min_buckets` separate hours (counted per detection) is treated as baseline noise or
   a scheduled job. It is still reported as a finding but cannot link steps or promote an incident.
3. **Hub guards.** A host or IP touched by more than `hub_max_users` accounts in a session, or an
   account active on more than `hub_max_hosts` hosts, is not used to link. Process-ID and lateral-logon
   links are specific, so they are never hub-guarded.
4. **Promotion.** An incident needs at least `min_tactics` distinct ATT&CK tactics from medium+,
   non-recurrent signals. A lone critical signal is promoted only when `promote_single_critical: true`.
5. **Audited suppressions.** Add entries to `configs/suppressions.yaml`. Every entry needs a reason,
   and suppressed signals go to `suppressed.json`.

## 6. Adding a detection without code (B-4)
Drop a Sigma YAML into `rules/`, then validate and re-run:
```yaml
title: Certutil download
id: my-certutil-download
logsource: {category: process_creation}
detection:
  sel: {process.name: certutil.exe, process.command_line|contains|all: ['-urlcache', 'http']}
  condition: sel
level: high
tags: [attack.command_and_control, attack.t1105]
```
```bash
.venv/bin/tracekc rules-check          # compiles every rule, prints errors
```
Add the technique to `configs/attack_mapping.yaml` if it is new. Field names are ECS (`process.name`)
or common Sigma aliases (`Image`, `CommandLine`, `TargetObject`, `EventID`, …); see `FIELD_MAP` in
`sigma.py`. Correlation rules follow the Sigma v2 spec. `trace: {always_emit: true}` is a TRACE extension
that lets a referenced correlation still raise its own alert.

## 7. ATT&CK version
`configs/attack_mapping.yaml` is pinned to **Enterprise ATT&CK v20.0** and verified against the official
bundle (sha256 `81113ba9…ce534352`) with 0 differences. Two v20 changes matter here:
- Defense Evasion was split into **Stealth (TA0005)** and **Defense Impairment (TA0112)**.
- T1070.001 (Clear Windows Event Logs) was revoked in favour of **T1685.005**.

To re-verify after an update: `make attack`, which downloads the bundle and runs `tracekc attack-verify`.

## 8. Testing and benchmarks
```bash
make test                         # unit + end-to-end
make bench GB=15                  # synthetic 15 GB tier (sample replayed + planted chain), timed + scored
```
`tracekc gen-scale` replays the sample with fresh event IDs, fresh process IDs and spread timestamps,
and plants one six-step attack (password guessing -> macro PowerShell -> Run key -> C2 -> RDP to the
file server -> 650 MB exfiltration), writing its ground truth next to the data. It is a load and
regression test, not a substitute for the organisers' ground truth.

### Results measured so far
Linux laptop: 8 cores, 6 GB RAM, NVMe. Python 3.14, DuckDB 2.0.0.

| Test | Result |
|---|---|
| Unit + end-to-end tests | 18/18 pass |
| Sample, vendor alerts off | TRACE's own rules re-detect **505/505** labelled alerts with the right technique and 0 extra matches |
| Sample + planted chain | chain rebuilt: detection 1.0, labels 1.0, ordered path 1.0 (plus about 17 noise incidents: see §9) |
| Synthetic 0.3 GB (38 replays over 8 h + planted chain) | 1 incident = the 6 planted steps in order; false-incident rate 0; 4.5 s; about 1 GB peak RSS |
| Synthetic **1.07 GB** (128 replays over 8 h + chain), `memory_limit=1GB` | **47 s** total (ingest 42 s, detect 2.8 s, correlate 1.0 s); **1.02 GB** peak RSS; 1 incident, detection/labels/path **1.0**, false-incident rate **0**; 64,654 detections -> 3,073 signals, 3,064 recurring and kept as findings |
| API, open incident path | about 3 ms |

Ingest is about 95% of the time, at roughly 23 MB/s with a 1 GB memory cap. A linear projection gives about
11 min for 15 GB and 35–40 min for 50 GB, but that is an estimate. Run `make bench GB=15` on the target
machine, with more memory and threads, and record the real number.

## 9. Known limitations
- **Input format.** Only ECS-style NDJSON (the SimEDR shape) is parsed. If the tiers contain other
  sources (syslog, CSV, firewall), add a reader in `ingest.py` that maps them to the same normalised
  columns. The rest of the pipeline does not change.
- **The 8 MB sample is not representative of time.** It spans 0.33 s, so recurrence and first-seen
  logic cannot separate noise from attack. On the sample plus a planted chain, the chain is rebuilt
  perfectly but around 17 noise incidents are also promoted. On time-spread data (gen-scale) the noise
  is filtered. Re-tune `session_gap_s`, `recurrence_*` and the hub limits on the real dev sample.
- **Recurrence assumes attack steps are not exact repeats of background alerts.** If the organisers'
  planted steps reuse exactly the same fingerprints as recurring noise, lower `recurrence_min_buckets`
  or switch the filter off (`--set correlation.recurrence_min_buckets=1000000`).
- **Unsupported Sigma features.** Keyword-list selections, `|base64*`, `|windash` and correlation type
  `temporal` (unordered) are rejected at load time with a clear message. `value_count` counts distinct
  values per burst session rather than per exact sliding window.
- **Look-ahead without admin telemetry.** If no 4672/group data exists, look-ahead reports observed
  logon ability, and says so in `assumptions`.
- **Live mode (`tracekc watch`) re-runs the whole pipeline on change.** That takes seconds for small
  inputs but is not incremental at 50 GB.

## 10. Notes against the plan (docs/TRACE_PLAN_v2.md)
Implemented as planned:
- DuckDB funnel
- Sigma (single + correlation) to SQL
- rarity, volume and lateral detectors
- entity resolution
- pinned ATT&CK labels with both tactic and stage
- entity/time incident graph with an FP gate, scoring, merged counts and isolated findings
- BloodHound-style look-ahead
- precomputed API and web page
- PRD scorer and the benchmark protocol fields

Changed after measuring:
- **Kill-chain order is used for scoring (longest progression), not as an edge filter.** Real chains go
  C2 -> persistence -> lateral, which breaks a strict order rule.
- **Two hub-proof link types were added:** same host + process ID, and ASOF-matched lateral logon edges.
  Session pivots alone break when hosts and accounts are busy with noise.
- **A recurrence filter was added** (the plan's "scheduled-job patterns" item). Without it, dense
  replayed noise produced 95 false incidents. With it, 0.
- **Single-critical promotion is off by default.** The sample has one critical alert per ~90 events,
  with no chain behind it.
- **The ATT&CK table was corrected for v20** (see §7).

## Licences
Rules in `rules/` are written for this project (author "TRACE team"). If you add rules from SigmaHQ,
keep their `author` field: it is shown in each incident under `attribution`, as DRL-1.1 requires.
Dependencies: DuckDB (MIT), FastAPI/Starlette (MIT), Pydantic (MIT), Uvicorn (BSD-3), PyYAML (MIT),
psutil (BSD-3), Cytoscape.js (MIT, loaded from cdnjs).
