# TRACE web console (Next.js)

A web UI for the TRACE API: incident queue, attack timelines with raw evidence, an interactive attack graph
(users, hosts, IPs, and who connects to whom), path finding, reachability predictions, case handling and AI triage.

## Full-file local demo on Windows

From the repository root, run `scripts/demo.ps1` to generate results. Build the
console once, then start both local servers:

```powershell
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python.exe scripts/start_web.py
```

Open http://127.0.0.1:3000. The launcher uses the optimized output directory and
starts the API on port 8001. Use `--out "FULL_PATH"` to select a different completed
run. Both ports must be free. The root `.env` is loaded by the launcher; do not
put the Sarvam key in browser environment variables.

## Run a sample manually

```bash
# 1. From the repo root: build results from the bundled sample (data/sample/edr_events.json), then serve them
.venv/bin/python -m tracekc run --input data/sample --out out/web
.venv/bin/python -m tracekc serve --out out/web --port 8000

# 2. Web console
cd frontend
npm install
cp .env.example .env.local      # TRACE_API_URL (default http://127.0.0.1:8000), optional TRACE_API_TOKEN
npm run build && npm run start  # http://localhost:3000   (or `npm run dev` while editing)
```

The browser only talks to this app. `src/app/api/[...path]/route.ts` forwards requests to `TRACE_API_URL` on the
server, adding the bearer token there, so the token never reaches the browser and the API's same-origin POST rule holds.

## Pages

| Route | What it shows |
|---|---|
| `/` | Run summary: read → detect → map → link funnel, priority incidents, risk distribution, kill-chain coverage |
| `/incidents` | Searchable, filterable incident queue (risk, tactic, case status, sort) |
| `/incidents/[id]` | Story (timeline and evidence drawer), Attack graph (explorer and path finder), Predict (reachable assets, next technique), Respond (case, AI triage, ask, exports) |
| `/coverage` | Rules loaded, ATT&CK techniques covered, which rules fired |
| `/data` | Ingest quality, stage timings, live run progress, supported log formats |

Press <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>K</kbd> anywhere to jump to an incident, host or user.

## Graph explorer

- **Entities** view folds detection steps into direct links (user → host, host → IP/domain). **Full evidence** shows every signal node.
- Click a node to see all its connections, grouped into Users, Hosts and IP addresses, with techniques, steps and event counts. Click an edge to see its timing and evidence.
- Search, five layouts, filter by type, toggle hypothesis (could-reach) edges, full screen, PNG export.
- *Use in path finder* fills the path finder. Paths are highlighted in cyan.

## Fitted prediction model

The Data page and an incident's Predict tab show the selected algorithm, training
cutoff, training size, label provenance and evaluation warnings. Download the
fitted JSON there, or follow **Open an eligible prediction**. Incidents before the
training cutoff cannot use that model. Ranked techniques without historical-share
values display their rank, not an invented percentage. This is a historical
Markov model; neither TGN nor decision-tree forecasting is implemented here.

The shared run banner shows the saved end-to-end measurement, source bytes, run
name and publication time in the browser's local timezone. The timestamp comes
from the timing artifact, so refreshing the page does not make an old run look new.
