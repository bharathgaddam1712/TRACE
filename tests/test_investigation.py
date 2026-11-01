"""Regression checks for ingestion quality, provenance, temporal leakage, cases and AI boundaries."""
import json
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pytest
from fastapi.testclient import TestClient

from conftest import SAMPLE
from tracekc.ai import AIError, AIRequest, SarvamService
from tracekc.api import create_app
from tracekc.config import load_config
from tracekc.engine import connect
from tracekc.ingest import ingest
from tracekc.pipeline import run_pipeline
from tracekc.reach import AccessGraph
from tracekc.synth import scale_up


def event(eid='one', time='2026-10-31T09:00:00Z', **values):
    return {'@timestamp': time, 'host': {'name': 'WS-01', 'ip': ['10.0.0.1']},
            'event': {'id': eid, 'action': 'process_created', 'kind': 'event'}, **values}


def read_events(tmp_path, source, settings=None):
    cfg = load_config(overrides=['engine.threads=2', 'engine.memory_limit=1GB'])
    cfg['ingest'].update(settings or {})
    work = tmp_path / 'out' / 'work'
    work.mkdir(parents=True, exist_ok=True)
    con = connect(cfg, work / 'test.duckdb', work / 'spill')
    stats = ingest(con, cfg, source, work)
    return con, stats, cfg


def test_log_discovery_cache_quality_and_changed_file(tmp_path):
    source = tmp_path / 'input'; source.mkdir()
    path = source / 'events.log'
    records = [event(), event(), event('bad', time='invalid')]
    path.write_text('\n'.join(json.dumps(e) for e in records), encoding='utf-8')
    con, stats, cfg = read_events(tmp_path, source)
    assert stats['duplicates_removed'] == 1
    assert stats['quarantined_rows'] == stats['missing_timestamp'] == 1
    assert con.execute('SELECT count(*) FROM events').fetchone()[0] == 1
    con.close()
    con, second, cfg = read_events(tmp_path, source)
    assert second['reused_files'] == 1
    con.close()
    with path.open('a', encoding='utf-8') as f:
        f.write('\n' + json.dumps(event('two')))
    con, third, cfg = read_events(tmp_path, source)
    assert third['reused_files'] == 0 and third['events'] == 3
    con.close()
    with duckdb.connect() as con:
        assert con.execute('SELECT quarantine_reason FROM read_parquet(?)', [str(tmp_path / 'out/quarantine.parquet')]).fetchone()[0] == 'missing_time'


def test_csv_and_syslog_adapters(tmp_path):
    source = tmp_path / 'input'; source.mkdir()
    (source / 'firewall.csv').write_text('timestamp,host,action,src_ip,dst_ip,dst_port\n2026-10-31T09:00:00Z,FW-01,network_connection,10.0.0.1,8.8.8.8,443\n2026-10-31T09:00:00Z,FW-01,network_connection,10.0.0.1,8.8.8.8,bad\n', encoding='utf-8')
    (source / 'system.log').write_text('<34>1 2026-10-31T09:00:00Z LINUX-01 sshd 123 ID - User logged in\nnot valid syslog\n', encoding='utf-8')
    con, stats, cfg = read_events(tmp_path, source)
    assert stats['events'] == 2 and stats['adapter_rejected_records'] == 2
    assert stats['formats'] == {'csv': 1, 'syslog': 1}
    assert con.execute("SELECT message FROM events WHERE host='LINUX-01'").fetchone()[0].endswith('User logged in')
    con.close()


def test_malformed_json_fails_instead_of_disappearing(tmp_path):
    path = tmp_path / 'broken.log'
    path.write_text(json.dumps(event()) + '\n{bad json}\n', encoding='utf-8')
    with pytest.raises(duckdb.Error):
        read_events(tmp_path, path)


def test_process_recycling_and_ambiguous_ip_resolution(tmp_path):
    records = [event('first', process={'pid': 42, 'entity_id': 'p1'}),
               event('second', time='2026-10-31T09:01:00Z', process={'pid': 42, 'entity_id': 'p2'}),
               event('third', time='2026-10-31T09:02:00Z', process={'pid': 42}, event={'id':'third','action':'network_connection'}),
               event('other', host={'name':'WS-02','ip':['10.0.0.1']})]
    path = tmp_path / 'input.log'; path.write_text('\n'.join(json.dumps(r) for r in records), encoding='utf-8')
    con, stats, cfg = read_events(tmp_path, path)
    assert con.execute("SELECT proc_entity_id FROM ev WHERE event_id='third'").fetchone()[0] == 'p2'
    assert con.execute("SELECT count(*) FROM ip_host WHERE ip='10.0.0.1'").fetchone()[0] == 0
    con.close()


def test_predictions_do_not_leak_future_logons_or_failed_connections(tmp_path):
    before = event('past', event={'id':'past','action':'user_logon','outcome':'success'}, host={'name':'PAST'}, user={'name':'ravi'}, winlog={'logon':{'type':'RemoteInteractive'}})
    future = event('future', time='2026-10-31T11:00:00Z', event={'id':'future','action':'user_logon','outcome':'success'}, host={'name':'FUTURE'}, user={'name':'ravi'})
    failure = event('failed', event={'id':'failed','action':'network_connection','outcome':'failure'}, destination={'ip':'10.0.0.2','port':445})
    target = event('target', host={'name':'TARGET','ip':['10.0.0.2']})
    path = tmp_path / 'input.log'; path.write_text('\n'.join(json.dumps(r) for r in [before,future,failure,target]), encoding='utf-8')
    con, stats, cfg = read_events(tmp_path, path)
    graph = AccessGraph(con, cfg)
    cutoff = int(datetime(2026,10,31,10,tzinfo=timezone.utc).timestamp()*1000)
    result = graph.lookahead({'ravi'}, {'WS-01'}, cutoff)
    assert [r['asset'] for r in result['reachable']] == ['PAST']
    assert all(ts <= cutoff for r in result['reachable'] for ts in r['evidence']['observed_at_ms'])
    expired = graph.lookahead({'ravi'}, {'WS-01'}, cutoff + 8*86400000)
    assert expired['status'] == 'unknown'
    con.close()


@pytest.fixture(scope='module')
def investigation(tmp_path_factory):
    root = tmp_path_factory.mktemp('investigation')
    scale_up(SAMPLE, root / 'input', target_gb=0.02)
    cfg = load_config(overrides=['engine.threads=2','engine.memory_limit=1GB'])
    report = run_pipeline(cfg, root/'input', root/'out')
    incidents = json.loads((root/'out/index.json').read_text(encoding='utf-8'))
    assert incidents
    inc = json.loads((root/'out/incidents/1.json').read_text(encoding='utf-8'))
    return root, inc, report


def test_api_search_evidence_case_history_and_graph(investigation):
    root, inc, report = investigation
    client = TestClient(create_app(root/'out'))
    assert client.get('/incidents?min_score=101').status_code == 422
    assert client.get('/incidents?offset=-1').status_code == 422
    assert client.get('/incidents?q=this-host-does-not-exist').json() == []
    eid = inc['timeline'][0]['event_ids'][0]
    assert client.get(f'/incidents/1/evidence/{eid}').json()['event_id'] == eid
    assert client.get('/incidents/1/evidence/not-cited').status_code == 404
    payload={'status':'investigating','note':'Verified the source log.','version':0}
    assert client.post('/incidents/1/case',json=payload).json()['version'] == 1
    assert client.post('/incidents/1/case',json=payload).status_code == 409
    assert client.get('/incidents/1').json()['case']['history'][0]['note'] == payload['note']
    graph = client.get('/incidents/1/graph?entity=host:WS-HR-012').json()
    assert graph['edges'] and all('host:WS-HR-012' in {e['source'],e['target']} for e in graph['edges'])
    assert client.post('/incidents/1/case',json=payload,headers={'Origin':'https://evil.example'}).status_code == 403
    assert client.get('/progress').json()['state'] == 'complete'
    assert client.get('/vendor/cytoscape.min.js').status_code == 200


def test_api_auth_and_missing_key(investigation, monkeypatch):
    root, inc, report = investigation
    monkeypatch.setenv('TRACE_API_TOKEN','test-token')
    monkeypatch.setenv('SARVAM_API_KEY','')
    client = TestClient(create_app(root/'out'))
    assert client.get('/').status_code == 200
    assert client.get('/incidents').status_code == 401
    headers={'Authorization':'Bearer test-token'}
    assert client.get('/incidents',headers=headers).status_code == 200
    result=client.post('/incidents/1/ai',headers=headers,json={'task':'summary'})
    assert result.status_code == 503 and 'SARVAM_API_KEY' in result.json()['detail']


def ai_result(eid, **changes):
    result={'answer':'Suspicious execution needs investigation.','citations':[eid], 'hypotheses':[], 'next_checks':['Inspect the parent process.'], 'suggested_mappings':[], 'sigma_yaml':None, **changes}
    return {'choices':[{'finish_reason':'stop','message':{'content':json.dumps(result)}}], 'usage':{'prompt_tokens':120,'completion_tokens':60}}


def test_ai_evidence_validation_caching_and_redaction(tmp_path, investigation, monkeypatch):
    root, inc, report = investigation
    monkeypatch.setenv('SARVAM_API_KEY','test-only-key')
    calls=[]
    eid=inc['timeline'][0]['event_ids'][0]
    def transport(payload):
        calls.append(payload)
        return ai_result(eid)
    service=SarvamService(tmp_path,transport)
    from tracekc.label import load_mapping
    from tracekc.config import PROJECT_ROOT
    mapping=load_mapping(PROJECT_ROOT/'configs/attack_mapping.yaml')
    data=json.loads(json.dumps(inc));data['timeline'][0]['evidence']['cmd']='tool --password super-secret'
    first=service.analyze(data,AIRequest(),mapping)
    second=service.analyze(data,AIRequest(),mapping)
    assert not first['cached'] and second['cached'] and len(calls)==1
    assert first['report_markdown'].startswith('# TRACE AI Investigation Report')
    assert second['report_markdown']==first['report_markdown'] and eid in first['report_markdown']
    assert 'super-secret' not in json.dumps(calls)
    assert 'test-only-key' not in json.dumps(first)
    assert service.status()['requests_today']==1
    service.transport=lambda payload: ai_result('invented-event')
    with pytest.raises(AIError,match='outside the supplied'):
        service.analyze(data,AIRequest(question='different prompt'),mapping)


def test_ai_budget_and_incomplete_response(tmp_path, investigation, monkeypatch):
    root, inc, report = investigation
    monkeypatch.setenv('SARVAM_API_KEY','test-only-key')
    monkeypatch.setenv('SARVAM_DAILY_REQUEST_LIMIT','1')
    service=SarvamService(tmp_path,lambda payload:{'choices':[{'finish_reason':'length'}]})
    with pytest.raises(AIError,match='incomplete'):
        service.analyze(inc,AIRequest(),{'techniques':{}})
    with pytest.raises(AIError,match='daily'):
        service.analyze(inc,AIRequest(question='retry'),{'techniques':{}})
