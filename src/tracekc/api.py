"""API for evidence-backed investigation, analyst cases and optional Sarvam assistance."""
from __future__ import annotations

import hmac
import json
import os
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from tracekc.ai import AIError, AIRequest, SarvamService
from tracekc.cases import Cases, CaseUpdate
from tracekc.config import PROJECT_ROOT, load_env, load_config
from tracekc.label import load_mapping
from tracekc.timeutil import timestamp
from tracekc.graph_algorithms import GraphIndex
from tracekc.triage import TriagePipeline,TriageRequest,TriageReview


class Store:
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.lock = threading.Lock()
        self.mtime = None
        self.index = []
        self.incidents = OrderedDict()
        self.by_id = {}
        self.cache_limit = 16
        self.findings = {}
        self.metrics = {}
        self.relationships = {}
        self.graph_indexes = OrderedDict()
        self.refresh()

    def _read(self, name: str, default):
        path = self.out_dir / name
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else default

    def refresh(self):
        index = self.out_dir / 'index.json'
        signature = (index.stat().st_mtime_ns, index.stat().st_size) if index.exists() else None
        if signature == self.mtime:
            return
        with self.lock:
            try:
                rows = self._read('index.json', [])
                if any(not (self.out_dir/f"incidents/{row['id']}.json").is_file() for row in rows):
                    return  # never expose a partially published run
                findings = self._read('findings.json', {})
                metrics = self._read('run_metrics.json', {})
                relationships = self._read('relationships.json', {'links':[]})
            except (OSError, ValueError):
                return  # retain the last complete snapshot while a writer publishes
            self.index, self.incidents = rows, OrderedDict()
            self.by_id = {int(row['id']):row for row in rows}
            self.findings, self.metrics, self.mtime = findings, metrics, signature
            self.relationships, self.graph_indexes = relationships, OrderedDict()

    def incident(self, inc_id):
        self.refresh()
        with self.lock:
            row=self.by_id.get(inc_id)
            if row is None:return None
            if inc_id not in self.incidents:
                value=self._read(f'incidents/{inc_id}.json',{})
                if not value or value.get('fingerprint')!=row.get('fingerprint'):
                    raise HTTPException(503,'Results are being published; retry after the pipeline completes')
                self.incidents[inc_id]=value
            self.incidents.move_to_end(inc_id)
            while len(self.incidents)>self.cache_limit:
                old,_=self.incidents.popitem(last=False)
                self.graph_indexes.pop(old,None)
            incident=self.incidents[inc_id]
            return incident


def create_app(out_dir: Path, ai_service=None) -> FastAPI:
    load_env()
    out_dir = out_dir.resolve()
    store = Store(out_dir)
    cases = Cases(out_dir)
    ai = ai_service or SarvamService(out_dir)
    triage = TriagePipeline(out_dir,ai)
    mapping = load_mapping(PROJECT_ROOT / 'configs' / 'attack_mapping.yaml')
    graph_settings=load_config().get('graph',{})
    max_depth=min(12,max(1,int(graph_settings.get('max_depth',6))))
    default_depth=min(max_depth,max(1,int(graph_settings.get('default_depth',2))))
    neo = None
    if os.environ.get('TRACE_GRAPH_BACKEND','local') == 'neo4j':
        from tracekc.neo4j_store import Neo4jStore
        neo = Neo4jStore(out_dir)
    token = os.environ.get('TRACE_API_TOKEN', '')
    app = FastAPI(title='TRACE security investigations', version='0.2.0')

    @app.middleware('http')
    async def protect(request: Request, call_next):
        if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            origin = request.headers.get('origin')
            if origin and urlparse(origin).netloc != request.headers.get('host'):
                return JSONResponse({'detail': 'Cross-origin writes are not allowed'}, status_code=403)
            if request.headers.get('content-type', '').split(';')[0] != 'application/json':
                return JSONResponse({'detail': 'JSON content type required'}, status_code=415)
        static = request.url.path in {'/', '/index.html', '/app.js', '/style.css', '/vendor/cytoscape.min.js', '/favicon.ico'}
        if token and not static and not hmac.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + token):
            return JSONResponse({'detail': 'API bearer token required'}, status_code=401)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        return response

    def get(inc_id):
        store.refresh()
        incident = store.incident(inc_id)
        if incident is None:
            raise HTTPException(404, 'Incident not found')
        return incident

    def fingerprint(incident):
        return incident.get('fingerprint', f"legacy:{incident['id']}:{incident['first_seen']}")

    @app.get('/health')
    def health():
        store.refresh()
        return {'status': 'ok', 'incidents': len(store.index), 'graph_backend':'neo4j' if neo else 'local',
                'graph_algorithms':['bounded_bfs','depth_constrained_dijkstra','bounded_earliest_arrival']}

    @app.get('/parser-schemas')
    def parser_schemas():
        from tracekc.parser_contracts import contracts
        return contracts()

    @app.get('/progress')
    def progress():
        return store._read('progress.json', {'state': 'idle', 'stage': 'waiting_for_run'})

    @app.get('/demo/timings')
    def demo_timings():
        path=out_dir/'demo_timings.json'
        if not path.exists():return {'status':'unavailable','run_name':out_dir.name}
        result=store._read('demo_timings.json',{})
        return {**result,'run_name':out_dir.name,
                'published_at':datetime.fromtimestamp(path.stat().st_mtime,timezone.utc).isoformat()}

    @app.get('/graph/config')
    def graph_config():
        return {'backend':'neo4j' if neo else 'local','max_depth':max_depth,'default_depth':default_depth}

    @app.get('/coverage')
    def coverage():
        store.refresh()
        return {'rules':store.metrics.get('rules',{}),'detection':store.metrics.get('detect',{}),
                'mapping':store.metrics.get('label',{}),'catalog_techniques':len(mapping['techniques']),
                'note':'Technique coverage measures rules present, not guaranteed attack detection. Source telemetry and unsupported rules limit coverage.'}

    @app.get('/incidents')
    def incidents(q: str = Query('', max_length=200), min_score: float = Query(0, ge=0, le=100),
                  tactic: str = '', status: str = '', limit: int | None = Query(None, ge=1), offset: int = Query(0, ge=0)):
        store.refresh()
        rows = []
        statuses = cases.statuses()
        for row in store.index:
            if row['score'] < min_score or (tactic and tactic not in row['tactics']):
                continue
            if q and q.lower() not in json.dumps(row).lower():
                continue
            case_status = statuses.get(row.get('fingerprint', ''), 'new')
            if status and case_status != status:
                continue
            rows.append({**row, 'status': case_status})
        return rows[offset:] if limit is None else rows[offset:offset + limit]

    @app.get('/incidents/{inc_id}')
    def incident(inc_id: int):
        result = get(inc_id)
        related=[link for link in store.relationships.get('links',[]) if inc_id in {link['source'],link['target']}]
        return {**result, 'case': cases.get(fingerprint(result)), 'related_incidents':related}

    def graph_index(inc_id):
        inc=get(inc_id)
        with store.lock:
            if inc_id not in store.graph_indexes:
                try:
                    store.graph_indexes[inc_id]=GraphIndex(neo.load_graph(inc['fingerprint']) if neo else inc['graph'])
                except Exception:
                    raise HTTPException(503,'Neo4j graph unavailable; verify connectivity and run graph-sync') from None
            store.graph_indexes.move_to_end(inc_id)
            while len(store.graph_indexes)>store.cache_limit:
                store.graph_indexes.popitem(last=False)
            return store.graph_indexes[inc_id]

    @app.get('/incidents/{inc_id}/neighborhood')
    def neighborhood(inc_id:int, entity:str, depth:int=Query(default_depth,ge=0,le=max_depth), limit:int=Query(500,ge=1,le=2000)):
        try:
            return neo.neighborhood(get(inc_id)['fingerprint'],entity,depth,limit) if neo else graph_index(inc_id).neighborhood(entity,depth,limit)
        except KeyError:
            raise HTTPException(404,'Graph entity not found') from None
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503,'Neo4j neighborhood unavailable; verify synchronization') from None

    @app.get('/incidents/{inc_id}/shortest-path')
    def shortest(inc_id:int, source:str, target:str, depth:int=Query(max_depth,ge=1,le=max_depth), directed:bool=True, include_hypotheses:bool=False):
        try:
            return graph_index(inc_id).shortest_path(source,target,depth,directed,include_hypotheses)
        except KeyError:
            raise HTTPException(404,'Graph source or target not found') from None

    @app.get('/relationships')
    def relationships(incident_id:int|None=None,depth:int=Query(2,ge=0,le=6)):
        store.refresh()
        graph={'nodes':[{'id':f"incident:{row['id']}",'label':row['title'],'type':'incident','incident_id':row['id']} for row in store.index],
               'edges':[{**link,'source':f"incident:{link['source']}",'target':f"incident:{link['target']}",
                         'kind':'related_incident','evidence_kind':'inferred','cost':1/max(link['score'],0.05)}
                        for link in store.relationships.get('links',[])]}
        if incident_id is not None:
            get(incident_id)
            graph=GraphIndex(graph).neighborhood(f'incident:{incident_id}',depth)
        return {**store.relationships,'graph':graph}

    @app.get('/incidents/{inc_id}/temporal-path')
    def temporal_path(inc_id:int,source:str,target:str,depth:int=Query(max_depth,ge=1,le=max_depth),start:str='',end:str=''):
        inc=get(inc_id)
        try:
            start_ms=int(timestamp(start or inc['first_seen']).timestamp()*1000)
            cutoff=min(int(timestamp(end or inc['last_seen']).timestamp()*1000),
                       int(timestamp(inc['last_seen']).timestamp()*1000))
            return graph_index(inc_id).temporal_path(source,target,start_ms,cutoff,depth)
        except KeyError:
            raise HTTPException(404,'Graph source or target not found') from None
        except ValueError as exc:
            raise HTTPException(422,str(exc)) from None

    @app.get('/incidents/{inc_id}/path')
    def path(inc_id: int):
        inc = get(inc_id)
        return {key: inc.get(key) for key in ('id', 'title', 'score', 'host_path', 'host_path_text', 'tactics',
                                             'timeline', 'graph', 'lookahead', 'correlation_links')}

    @app.get('/incidents/{inc_id}/graph')
    def graph(inc_id: int, entity: str = '', start: str = '', end: str = ''):
        inc = get(inc_id)
        try:
            start_time, end_time = timestamp(start) if start else None, timestamp(end) if end else None
            if start_time and end_time and start_time > end_time:
                raise ValueError('Start is after end')
        except ValueError:
            raise HTTPException(422, 'Use ordered ISO8601 timestamps with a timezone') from None
        selected = {step['step'] for step in inc['timeline']
                    if (not start_time or timestamp(step.get('ts_last') or step['ts']) >= start_time)
                    and (not end_time or timestamp(step['ts']) <= end_time)}
        edges = [edge for edge in inc['graph']['edges']
                 if (not start and not end or set(edge.get('steps', [])) & selected)]
        if entity:
            edges = [edge for edge in edges if entity in {edge['source'], edge['target']}]
        ids = {value for edge in edges for value in (edge['source'], edge['target'])}
        return {'nodes': [node for node in inc['graph']['nodes'] if node['id'] in ids], 'edges': edges}

    @app.get('/incidents/{inc_id}/evidence/{event_id}')
    def evidence(inc_id: int, event_id: str):
        inc = get(inc_id)
        allowed = {eid for step in inc['timeline'] for eid in step['event_ids']}
        allowed.update(eid for item in inc['lookahead']['reachable'] for eid in item['evidence'].get('event_ids', [item['evidence'].get('sample_event_id')]))
        if event_id not in allowed:
            raise HTTPException(404, 'Event is not cited by this incident')
        import duckdb
        from tracekc.engine import dicts
        if not (out_dir / 'evidence.parquet').exists():
            raise HTTPException(404, 'Re-run the pipeline to materialize evidence')
        with duckdb.connect() as con:
            rows = dicts(con, 'SELECT * FROM read_parquet(?) WHERE event_id=? LIMIT 1', [str(out_dir / 'evidence.parquet'), event_id])
        if not rows:
            raise HTTPException(404, 'Evidence event not found')
        return rows[0]

    @app.get('/incidents/{inc_id}/report', response_class=PlainTextResponse)
    def report(inc_id: int):
        return get(inc_id)['narrative']

    @app.post('/incidents/{inc_id}/case')
    def update_case(inc_id: int, update: CaseUpdate):
        try:
            return cases.update(fingerprint(get(inc_id)), update)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get('/ai/status')
    def ai_status():
        return ai.status()

    @app.get('/incidents/{inc_id}/triage')
    def get_triage(inc_id:int):
        return triage.latest(fingerprint(get(inc_id)))

    @app.post('/incidents/{inc_id}/triage')
    def run_triage(inc_id:int,request:TriageRequest):
        return triage.run(get(inc_id),request,mapping)

    @app.post('/incidents/{inc_id}/triage/review')
    def review_triage(inc_id:int,review:TriageReview):
        try:return triage.review(fingerprint(get(inc_id)),review)
        except ValueError as exc:raise HTTPException(409,str(exc)) from None

    @app.post('/incidents/{inc_id}/ai')
    def analyze(inc_id: int, request: AIRequest):
        try:
            return ai.analyze(get(inc_id), request, mapping)
        except AIError as exc:
            raise HTTPException(exc.status, str(exc)) from None

    @app.get('/findings')
    def findings(limit: int | None = Query(None, ge=1)):
        store.refresh()
        return {**store.findings, 'findings': store.findings.get('findings', [])[:limit]}

    @app.get('/metrics')
    def metrics():
        store.refresh()
        return store.metrics

    app.mount('/', StaticFiles(directory=PROJECT_ROOT / 'web', html=True), name='web')
    return app
