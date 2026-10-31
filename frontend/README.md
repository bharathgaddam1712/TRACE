# TRACE web console (Next.js)

A web UI for the TRACE API: incident queue, attack timelines with raw evidence, an interactive attack graph
(users, hosts, IPs, and who connects to whom), path finding, reachability predictions, case handling and AI triage.

## Run

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
