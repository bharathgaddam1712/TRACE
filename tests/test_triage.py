import json
import sqlite3
from pathlib import Path

import duckdb
import pytest

from tracekc.ai import SarvamService
from tracekc.triage import TriagePipeline,TriageRequest,TriageReview


def incident():
    return {'id':1,'title':'Blocked authentication attempts','fingerprint':'case-one','first_seen':'2026-10-20T10:00:00Z',
            'last_seen':'2026-10-20T11:00:00Z','score':45,'tactics':['Credential Access'],
            'techniques':[{'id':'T1110'}],'entities':{'hosts':['HOST'],'users':['alice']},
            'timeline':[{'step':i,'ts':'2026-10-20T10:00:00Z','title':'blocked attempt',
                         'host':'HOST','user':'alice','technique':'T1110','severity':75,
                         'event_ids':[f'event-{i}'],'evidence':{'outcome':'failure'}} for i in range(1,61)],
            'lookahead':{'reachable':[]}}


def verdict(event='event-60',assessment='attack_suspected'):
    return {'assessment':assessment,'priority':'P2','severity':'high','rationale':'Repeated blocked attempts need review.',
            'citations':[event],'contradictory_evidence':['Connections were blocked.'],
            'missing_evidence':['No successful authentication demonstrated.'],'next_checks':['Inspect authentication events.']}


@pytest.fixture
def setup(tmp_path,monkeypatch):
    monkeypatch.setenv('SARVAM_API_KEY','test-triage-key')
    monkeypatch.setenv('SARVAM_DAILY_TOKEN_LIMIT','500000')
    monkeypatch.setenv('SARVAM_DAILY_REQUEST_LIMIT','50')
    work=tmp_path/'work';work.mkdir()
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events(host VARCHAR,action VARCHAR,outcome VARCHAR,ts_ms BIGINT)')
        from tracekc.forecast import timestamp
        before=int(timestamp('2026-10-20T09:00:00Z').timestamp()*1000)
        con.executemany('INSERT INTO events VALUES (?,?,?,?)',[
            ('HOST','user_logon','failure',before),('HOST','user_logon','success',before+7200000)])
        con.execute('COPY events TO ? (FORMAT parquet)',[str(work/'events.parquet')])
    (tmp_path/'index.json').write_text(json.dumps([
        {'id':2,'fingerprint':'prior','hosts':['HOST'],'users':[],'last_seen':'2026-10-20T09:00:00Z'},
        {'id':3,'fingerprint':'future','hosts':['HOST'],'users':[],'last_seen':'2026-10-20T12:00:00Z'}]))
    calls=[]
    def transport(payload):
        calls.append(payload)
        return {'choices':[{'finish_reason':'stop','message':{'content':json.dumps(verdict())}}]}
    service=SarvamService(tmp_path,transport)
    return tmp_path,TriagePipeline(tmp_path,service),calls


def test_whole_incident_context_uses_past_and_includes_late_evidence(setup):
    _,triage,_=setup
    context=triage.context(incident())
    assert 'event-60' in [event for step in context['steps'] for event in step['event_ids']]
    assert len(context['steps'])<=40 and context['campaign']['total_steps']==60
    assert context['entity_history']['rows'][0]['events']==1
    assert context['entity_history']['rows'][0]['outcome']=='failure'
    assert [row['incident_id'] for row in context['duplicate_candidates']]==[2]


def test_triage_cache_citations_and_explicit_review(setup):
    root,triage,calls=setup
    first=triage.run(incident(),TriageRequest(),{'techniques':{}})
    second=triage.run(incident(),TriageRequest(),{'techniques':{}})
    assert first['status']=='PENDING_ANALYST_REVIEW' and not first['automatic_case_change']
    assert second['cached'] and len(calls)==1
    assert 'test-triage-key' not in json.dumps(calls)
    record=triage.review('case-one',TriageReview(context_hash=first['context_hash'],decision='monitor',note='Reviewed the blocked attempts.'))
    assert record['reviews'][0]['decision']=='monitor'
    with pytest.raises(ValueError,match='does not belong'):
        triage.review('different-case',TriageReview(context_hash=first['context_hash'],decision='escalate',note='review'))


def test_invalid_model_output_is_never_dismissed_or_cached(setup):
    _,triage,calls=setup
    triage.ai.transport=lambda p:{'choices':[{'finish_reason':'stop','message':{'content':json.dumps(verdict('invented'))}}]}
    result=triage.run(incident(),TriageRequest(),{'techniques':{}})
    assert result['status']=='NEEDS_REVIEW' and result['verdict']['assessment']=='insufficient_evidence'
    assert triage.latest('case-one')['result'] is None
    triage.ai.transport=lambda p:{'choices':[{'finish_reason':'stop','message':{'content':json.dumps(verdict())}}]}
    assert triage.run(incident(),TriageRequest(),{'techniques':{}})['status']=='PENDING_ANALYST_REVIEW'


def test_missing_history_does_not_establish_benign_and_no_key_retains_case(setup):
    root,triage,_=setup
    (root/'work/events.parquet').unlink()
    triage.ai.transport=lambda p:{'choices':[{'finish_reason':'stop','message':{'content':json.dumps(verdict(assessment='likely_benign'))}}]}
    result=triage.run(incident(),TriageRequest(),{'techniques':{}})
    assert result['status']=='NEEDS_REVIEW'
    triage.ai.key=''
    changed=incident();changed['timeline'][0]['title']='new evidence'
    assert triage.run(changed,TriageRequest(),{'techniques':{}})['status']=='NEEDS_REVIEW'


def test_optional_investigation_shares_incident_and_validates_evidence(setup):
    _,triage,calls=setup
    def transport(payload):
        calls.append(payload)
        if payload['response_format']['json_schema']['name']=='trace_triage':
            data=verdict()
        else:
            data={'answer':'Inspect blocked attempts.','citations':['event-1'],'hypotheses':[],
                  'next_checks':['Review authentication'],'suggested_mappings':[],'sigma_yaml':None}
        return {'choices':[{'finish_reason':'stop','message':{'content':json.dumps(data)}}]}
    triage.ai.transport=transport
    result=triage.run(incident(),TriageRequest(investigate=True),{'techniques':{}})
    assert result['investigation']['citations']==['event-1'] and len(calls)==2


def test_api_triage_review_is_bound_to_case(tmp_path,setup,monkeypatch):
    from fastapi.testclient import TestClient
    from tracekc.api import create_app
    _,triage,_=setup
    monkeypatch.setenv('TRACE_GRAPH_BACKEND','local');monkeypatch.setenv('TRACE_API_TOKEN','')
    row=incident();(triage.root/'incidents').mkdir()
    (triage.root/'incidents/1.json').write_text(json.dumps(row))
    (triage.root/'index.json').write_text(json.dumps([{'id':1,'fingerprint':row['fingerprint']}]))
    with TestClient(create_app(triage.root,ai_service=triage.ai)) as client:
        result=client.post('/incidents/1/triage',json={})
        assert result.status_code==200 and result.json()['advisory']
        assert client.get('/incidents/1/triage').json()['result']
        review={'context_hash':result.json()['context_hash'],'decision':'escalate','note':'Reviewed'}
        assert client.post('/incidents/1/triage/review',json=review).status_code==200
        assert client.post('/incidents/1/triage/review',json={**review,'context_hash':'0'*64}).status_code==409
