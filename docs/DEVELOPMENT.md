# Development guide

Start with the root [README](../README.md) for the tested sample workflow and architecture. Work from a source checkout: configuration, rule packs and sample data live alongside the Python package.

## Install and run

Python 3.11+ is required by the pinned DuckDB dependency. Python 3.12 and Node 22 are the CI baselines. Create `.venv`, install `pip install -e ".[dev]"`, then run `npm ci` in `frontend/`. Use the matching virtual-environment executable in the commands below.

```bash
# Repository root, terminal 1
.venv/bin/python -m tracekc run --input data/sample --out out/demo
.venv/bin/python -m tracekc serve --out out/demo --port 8000

# Terminal 2
cd frontend
npm run dev
```

Windows uses `.venv\Scripts\python.exe`. For manual frontend startup with a custom API port, copy `frontend/.env.example` to `frontend/.env.local` and change `TRACE_API_URL`. The combined launcher sets it automatically and loads the root `.env`. Only backend processes need `SARVAM_API_KEY`.

## Find the right code

| Responsibility | Start here |
|---|---|
| Pipeline ordering, timings and locking | `src/tracekc/pipeline.py` |
| Runtime limits and SQL helpers | `src/tracekc/engine.py`, `configs/config.yaml` |
| Input schemas, adapters and resumable reads | `ingest.py`, `adapters.py`, `read_cache.py`, `native_reader.py` |
| Rules and ATT&CK labels | `sigma.py`, `detect.py`, `label.py`, `rules/` |
| Incident assembly and related-incident scoring | `correlate.py`, `relationships.py` |
| Evidence publication and graph traversal | `materialize.py`, `graph_algorithms.py` |
| Next-asset reachability | `reach.py` |
| HTTP, analyst actions and advisory AI | `api.py`, `triage.py`, `ai.py` |
| UI and server-side API proxy | `frontend/src/components/`, `frontend/src/app/` |
| Shared UTC parsing | `timeutil.py` |

Python filenames above are under `src/tracekc/`. Keep dependency direction simple: shared utilities must not depend on experiments or UI modules. Add a small function/docstring when it clarifies an invariant or evidence boundary; avoid comments that merely restate a line of code.

## Checks before a change is published

```bash
.venv/bin/python -m pytest -q
(cd frontend && npm run typecheck && npm run build)
.venv/bin/python -m tracekc run --input data/sample --out out/check
.venv/bin/python scripts/demo_smoke.py --out out/check
git diff --check
```

The GitHub Actions workflow runs backend tests and sample checks, frontend production checks, and a Docker Compose smoke job. A workflow definition is not evidence that a particular remote run passed; inspect the Actions result for the commit.

## Evidence and performance changes

- Keep source IDs, timestamps and rejected-byte accounting traceable. Do not turn an incomplete record into a complete connection by guessing fields.
- Do not load the complete raw event set into Python. Keep large scans/aggregations in DuckDB and use bounded output batches.
- Preserve lookahead/reachable results and Time-ordered paths. Reachability is based on observed access, not a learned next-technique model.
- Keep output outside input and give concurrent pipeline runs different output/cache/spill ownership.
- Benchmark into fresh output directories, record the source size and cache state, and compare full evidence before claiming unchanged results.

```bash
.venv/bin/python scripts/compare_runs.py --reference out/reference --candidate out/candidate
.venv/bin/python scripts/sweep_engine.py --input data/sample --out out/sweep
```

The sweep is plan-only unless `--execute` is supplied. Full comparison now includes parsed incident payloads because counts/fingerprints can match while representative evidence differs. It deliberately fails on such drift, even when array ordering or nondeterministic aggregation is responsible; investigate before relaxing the gate. Read [optimization decisions](OPTIMIZATION_REVIEW.md) and [live-mode design](LIVE_MODE.md) before pursuing deferred changes.

## Dependencies and repository hygiene

Update `pyproject.toml` and `requirements.txt` together for runtime pins; update dev pins in `requirements-dev.txt` when needed. Commit `frontend/package-lock.json` with JavaScript dependency changes and use `npm ci` in reproducible builds. Do not add libraries solely to claim an algorithm is present.

Keep generated outputs, source logs, `.env`, private notes and databases out of Git. Do not move public import paths or API routes without updating callers and regression checks. Preserve upstream rule authors, manifests and license files. See [dependency attribution](DEPENDENCIES.md).
