import json
import pytest

from tracekc.temporal import TemporalMemory, examples, ranking_metrics, tree_scores
from tracekc.graph_algorithms import link_decision


def test_memory_rejects_future_and_evicts_old_edges():
    memory = TemporalMemory(max_edges=1,half_life_s=1)
    memory.update('a','b',1000)
    assert memory.features('a','b',2000)[1] == .5
    with pytest.raises(ValueError,match='leakage'):
        memory.features('a','b',1000)
    memory.update('a','c',2000)
    assert memory.features('a','b',3000)[0] == 0
    assert memory.evictions == 1


def test_same_timestamp_is_not_observed_and_future_does_not_change_prefix():
    rows = [(1,'x','b'),(2,'x','c'),(3,'a','b'),(3,'a','c'),(4,'z','b')]
    first = list(examples(rows,negatives=1))
    extended = list(examples(rows+[(5,'z','future')],negatives=1))
    assert first == [g for g in extended if g['ts'] <= 4]
    # At t=3 both known destinations are contemporaneous positives: neither
    # may be used as a negative for the other; no eligible candidates exist.
    assert not any(g['ts']==3 for g in first)
    at_four = next(g for g in first if g['ts']==4)
    assert at_four['features'][0][0] == 0


def test_ties_do_not_favor_positive_candidate_position():
    result = ranking_metrics([{'features':[[0],[0],[0]]}],lambda fs:[0]*len(fs))
    assert result['mrr'] == .5 and result['hits1'] == 0


def test_cross_host_relation_thresholds_do_not_require_lateral_logon():
    config = {'similarity_threshold':.3,'relation_thresholds':{'ip':.1,'user':.2}}
    a = {'host':'A','src_ip':'203.0.113.1'}
    b = {'host':'B','src_ip':'203.0.113.1'}
    assert link_decision(a,b,'ip',config)['accepted']
    a = {'host':'A','user_name':'alice','technique':'T1110'}
    b = {'host':'B','user_name':'alice','technique':'T1059'}
    assert link_decision(a,b,'user',config)['accepted']
    assert not link_decision({'host':'A'},{'host':'B'},'host',config)['accepted']


def test_temporal_benchmark_artifact_and_chronology(tmp_path):
    pytest.importorskip('sklearn')
    import duckdb
    from tracekc.temporal import benchmark
    path = tmp_path/'events.parquet'
    with duckdb.connect() as con:
        con.execute('CREATE TABLE events (ts_ms BIGINT, src_ip VARCHAR, dst_ip VARCHAR, action VARCHAR)')
        con.executemany('INSERT INTO events VALUES (?,?,?,?)',
                        [(i*1000,'s'+str(i%3),'d'+str(i%7),'network_connection') for i in range(200)])
        con.execute('COPY events TO ? (FORMAT parquet)',[str(path)])
    report = benchmark(path,tmp_path/'result',max_events=200,negatives=3)
    assert report['train_before_ms'] < report['test_after_ms']
    assert report['attack_accuracy'] is None
    assert all(report['split_queries'].values())
    assert report['selected_on_validation'] in report['validation']
    assert json.loads((tmp_path/'result/temporal-model.json').read_text())['training_before_ms'] == report['test_after_ms']


def test_json_tree_scoring_matches_sklearn():
    sklearn = pytest.importorskip('sklearn.tree')
    from tracekc.temporal import tree_artifact
    model = sklearn.DecisionTreeClassifier(criterion='entropy',max_depth=2,random_state=1)
    x,y = [[0],[1],[2],[3]],[0,0,1,1]
    model.fit(x,y)
    assert tree_scores(tree_artifact(model),x) == model.predict_proba(x)[:,1].tolist()


def test_scoped_detection_preserves_exact_rule_matches(tmp_path):
    from test_investigation import read_events, event
    from tracekc.detect import _rule_hits
    from tracekc.sigma import Rule
    source = tmp_path/'events.log'
    source.write_text('\n'.join(json.dumps(row) for row in [event('a'),
        event('b',event={'id':'b','action':'network_connection'})]),encoding='utf-8')
    con,_,_ = read_events(tmp_path,source)
    try:
        rules = {}
        for i in range(5):
            where = "action = 'process_created' AND proc_cmd IS NULL" if i%2 else "action = 'network_connection'"
            rules[str(i)] = Rule(str(i),'test','base','medium',50,[],None,'test','test',where=where,
                                 logsource={'category':'process_creation' if i%2 else 'network_connection'})
        def hits():
            return con.execute('SELECT event_id,list_sort(hits) FROM rule_hits ORDER BY event_id').fetchall()
        _rule_hits(con,rules,batch_size=16)
        direct = hits()
        _rule_hits(con,rules,batch_size=1)
        assert hits() == direct
    finally:
        con.close()


def test_temporal_api_is_explicitly_separate_from_attack_forecast(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from tracekc.api import create_app
    monkeypatch.setenv('TRACE_GRAPH_BACKEND','local')
    monkeypatch.setenv('TRACE_API_TOKEN','')
    (tmp_path/'temporal-benchmark.json').write_text(json.dumps({'task':'future_network_interaction_ranking','attack_accuracy':None}))
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/temporal/benchmark').json()['attack_accuracy'] is None
        assert client.get('/forecast/benchmark').json()['status'] == 'unavailable'


def test_beam_search_support_depth_and_forecast_cutoff():
    from tracekc.forecast import beam_sequences,predict
    fitted = {'overall':{'T1110':10,'T1059':10},'first_order':{'T1110':{'T1059':10},'T1059':{'T1110':10}},'second_order':{}}
    paths = beam_sequences(fitted,['T1110'],'markov1',depth=3)
    assert paths[0]['techniques'] == ['T1059','T1110','T1059']
    assert paths[0]['model_path_score'] == 1
    assert not beam_sequences(fitted,['T1110'],'markov1',min_support=11)
    with pytest.raises(ValueError):
        beam_sequences(fitted,['T1110'],'markov1',depth=20)
    model = {'fitted':fitted,'selected_model':'markov1','training_until':'2026-10-20T00:00:00Z'}
    assert predict(model,'T1110','2026-10-19T00:00:00Z')['status']=='unavailable'
    assert predict(model,'T1110','2026-10-21T00:00:00Z')['sequences'][0]['techniques']==paths[0]['techniques']


def test_recency_weighting_prefers_recent_historical_transitions():
    from tracekc.forecast import _fit,rank
    rows = [{'techniques':['T1110','T1059'],'ended_at':'2026-01-01T00:00:00Z'},
            {'techniques':['T1110','T1486'],'ended_at':'2026-10-01T00:00:00Z'}]
    artifact = _fit(rows,'2026-10-02T00:00:00Z')
    assert rank(artifact,['T1110'],'recency_markov1')[0]=='T1486'


def test_only_successful_logon_gets_specific_lateral_edge():
    import duckdb
    from tracekc.correlate import link_edges
    from tracekc.config import load_config
    from tracekc.engine import install_macros
    cfg = load_config()
    with duckdb.connect() as con:
        install_macros(con,cfg['internal_networks'])
        con.execute('''CREATE TABLE signals (signal_id BIGINT, host VARCHAR, src_host VARCHAR,
            dst_host VARCHAR, user_name VARCHAR, src_ip VARCHAR, dst_ip VARCHAR,
            technique VARCHAR, process_keys VARCHAR[], ts_first_ms BIGINT,
            suppressed_reason VARCHAR, recurrent BOOLEAN, severity INTEGER, evidence VARCHAR)''')
        con.execute("INSERT INTO signals VALUES (1,'A',NULL,NULL,'alice',NULL,NULL,'T1110',[],1000,NULL,false,75,'{}')")
        con.execute("INSERT INTO signals VALUES (2,'B','A',NULL,'alice',NULL,NULL,'T1059',[],2000,NULL,false,75,?)",
                    [json.dumps({'action':'network_connection','outcome':'success'})])
        assert not any(edge[2]=='lateral' for edge in link_edges(con,cfg))
        con.execute("UPDATE signals SET evidence=? WHERE signal_id=2",[json.dumps({'action':'user_logon','outcome':'success'})])
        assert (1,2,'lateral') in link_edges(con,cfg)
