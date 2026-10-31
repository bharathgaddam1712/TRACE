import json
import pytest
from tracekc.graph_algorithms import GraphIndex


def test_temporal_path_rejects_reverse_chronology_and_future_evidence():
    graph = {'nodes':[{'id':n} for n in 'ABCD'], 'edges':[
        {'source':'A','target':'B','kind':'observed','observation_times_ms':[20]},
        {'source':'B','target':'D','kind':'observed','observation_times_ms':[10]},
        {'source':'A','target':'C','kind':'observed','observation_times_ms':[15]},
        {'source':'C','target':'D','kind':'observed','observation_times_ms':[30]}]}
    index=GraphIndex(graph)
    assert index.shortest_path('A','D')['status']=='found'
    assert index.temporal_path('A','D',0,25)['status']=='not_found'
    result=index.temporal_path('A','D',0,40)
    assert result['nodes']==['A','C','D'] and result['observation_times_ms']==[15,30]
    assert index.temporal_path('A','D',0,40,max_depth=1)['status']=='not_found'


def test_temporal_path_excludes_untimed_and_hypothesis_edges():
    graph={'nodes':[{'id':'A'},{'id':'B'}],
           'edges':[{'source':'A','target':'B','kind':'could_reach','observation_times_ms':[10]}]}
    assert GraphIndex(graph).temporal_path('A','B',0,20)['status']=='not_found'
    graph['edges'][0]={'source':'A','target':'B','kind':'observed'}
    assert GraphIndex(graph).temporal_path('A','B',0,20)['status']=='not_found'


def test_duckdb_paths_with_quotes_and_query_profile(tmp_path):
    from tracekc.config import load_config
    from tracekc.engine import connect,run,finish_query_profile
    root=tmp_path/"it's-local";root.mkdir()
    work=root/'work';work.mkdir()
    cfg=load_config(overrides=['engine.profile_queries=true'])
    con=connect(cfg,work/'test.duckdb',root/'spill')
    try:
        assert run(con,"SELECT 'never-store-this-literal'")==[('never-store-this-literal',)]
        finish_query_profile(con)
    finally:
        con.close()
    text=(root/'query_timings.json').read_text()
    assert 'never-store-this-literal' not in text
    assert json.loads(text)['queries'][0]['calls']>=1


def test_parser_contracts_include_ad_schema_and_noise_policies():
    from tracekc.parser_contracts import contracts
    data=contracts()
    assert set(data['formats'])=={'ecs','fortigate','csv','syslog'}
    assert 'winlog' in data['ecs_projection'] and data['normalized_required']==['ts_ms','host']
    assert 'recurrent_alerts' in data['noise_policy']


def test_atomic_publication_retries_transient_windows_watchers(tmp_path,monkeypatch):
    import tracekc.materialize as materialize
    original=materialize.os.replace;calls=[]
    def held_handle(source,target):
        calls.append(1)
        if len(calls)<3:
            raise PermissionError('temporary watcher handle')
        original(source,target)
    monkeypatch.setattr(materialize.os,'replace',held_handle)
    monkeypatch.setattr(materialize.time,'sleep',lambda duration:None)
    target=tmp_path/'incident.json'
    materialize.write_json(target,{'published':True})
    assert len(calls)==3 and json.loads(target.read_text())['published']
