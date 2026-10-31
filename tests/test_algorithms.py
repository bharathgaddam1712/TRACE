"""Algorithm, parser and forecasting leakage regression tests."""
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from tracekc.graph_algorithms import GraphIndex, weighted_jaccard
from tracekc.relationships import related_incidents
from tracekc.forecast import benchmark,predict
from test_investigation import read_events,event


def graph():
    return {'nodes':[{'id':n,'type':'host'} for n in 'ABCD'], 'edges':[
        {'source':'A','target':'C','kind':'direct','cost':10},
        {'source':'A','target':'B','kind':'step','cost':1},
        {'source':'B','target':'C','kind':'step','cost':1},
        {'source':'C','target':'D','kind':'could_reach','cost':1,'evidence_kind':'hypothesis'}]}


def test_depth_constrained_dijkstra_and_hypothesis_control():
    index=GraphIndex(graph())
    assert index.shortest_path('A','C',1)['total_cost']==10
    assert index.shortest_path('A','C',2)['nodes']==['A','B','C']
    assert index.shortest_path('A','D',3)['status']=='not_found'
    assert index.shortest_path('A','D',3,include_hypotheses=True)['total_cost']==3
    result=index.neighborhood('A',1,2)
    assert result['truncated'] and len(result['nodes'])==2
    present={n['id'] for n in result['nodes']}
    assert all(e['source'] in present and e['target'] in present for e in result['edges'])


def test_graph_rejects_invalid_cost_and_similarity_is_bounded():
    data=graph();data['edges'][0]['cost']=-1
    with pytest.raises(ValueError):GraphIndex(data)
    assert weighted_jaccard({'x':3},{'x':3})==1
    assert weighted_jaccard({'x':3},{'y':3})==0


def incident(i,hosts,techniques,start='2026-10-31T10:00:00Z'):
    return {'id':i,'entities':{'hosts':hosts,'users':['ravi'],'external_ips':[]},
            'timeline':[{'technique_ids':techniques}], 'first_seen':start,'last_seen':start}


def test_incident_relationship_thresholds_and_explanations():
    rows=[incident(1,['WS1'],['T1110','T1059.001']),incident(2,['WS1'],['T1110','T1059.001']),
          incident(3,['WS9'],['T1486']),incident(4,['WS1'],['T1110','T1059.001'],'2026-09-01T10:00:00Z')]
    result=related_incidents(rows,{'threshold':0.6,'technique_overlap':0.3,'time_window_s':3600})
    assert [(link['source'],link['target']) for link in result['links']]==[(1,2)]
    assert result['links'][0]['shared_techniques'] and result['links'][0]['reason']


def test_append_checkpoint_defers_partial_lines_and_resumes(tmp_path):
    path=tmp_path/'events.log'
    first=json.dumps(event('first'))+'\n';second=json.dumps(event('second'))
    path.write_text(first+second[:30],encoding='utf-8')
    con,stats,cfg=read_events(tmp_path,path,{'append_only':True})
    assert stats['events']==1 and stats['deferred_tail_bytes']==30
    con.close()
    with path.open('a',encoding='utf-8') as stream:stream.write(second[30:]+'\n')
    con,stats,cfg=read_events(tmp_path,path,{'append_only':True})
    expected=len((second+('\r\n' if __import__('os').name=='nt' else '\n')).encode())
    assert stats['events']==2 and stats['parsed_input_bytes']==expected
    con.close()


def test_fortigate_chunked_reader_preserves_network_semantics(tmp_path):
    path=tmp_path/'firewall.log'
    lines=[]
    for i in range(30):
        lines.append(f'date=2026-10-31 time=10:00:00 eventtime={1793440800000000000+i*1000000000} tz="+0530" devname="FW01" devid="FW01" type="utm" subtype="ips" level="alert" srcip=10.0.0.1 srcintfrole="lan" dstip=203.0.113.5 dstintfrole="wan" dstport=443 action="blocked" sentbyte=123 attack="Backdoor.Cobalt.Strike.Beacon"\n')
    path.write_text(''.join(lines),encoding='utf-8')
    con,stats,cfg=read_events(tmp_path,path,{'chunk_bytes':1500})
    assert stats['events']==30 and stats['normalized_shards']>1
    assert con.execute("SELECT distinct action,outcome,direction,net_bytes,host FROM events").fetchall()==[('network_connection','failure','outbound',123,'10.0.0.1')]
    con.close()
    con,cached,cfg=read_events(tmp_path,path,{'chunk_bytes':1500})
    assert cached['parsed_input_bytes']==0 and cached['events']==30
    con.close()


def test_chronological_model_selection_never_uses_test_for_training(tmp_path):
    rows=[]
    for i in range(1,16):
        day=f'2026-10-{i:02d}T10:00:00Z'
        rows.append({'id':str(i),'started_at':day,'ended_at':day,'techniques':['T1110','T1059.001','T1547.001']})
    path=tmp_path/'history.json';path.write_text(json.dumps({'label_source':'test_fixture','incidents':rows}),encoding='utf-8')
    report,model,test=benchmark(path,'2026-10-08T00:00:00Z','2026-10-12T00:00:00Z')
    assert report['counts']=={'train':7,'validation':4,'test':4,'crossing_excluded':0}
    assert report['test']['markov2']['top1']==1
    assert predict(model,'T1110','2026-10-10T10:00:00Z')['status']=='unavailable'
    assert predict(model,'T1110','2026-10-13T10:00:00Z',['T1110'])['status']=='estimated'
    # Poisoning only test labels cannot change the fitted model or selection.
    for row in rows[11:]:row['techniques']=['T1486','T1490']
    path.write_text(json.dumps({'incidents':rows}),encoding='utf-8')
    altered,new_model,_=benchmark(path,'2026-10-08T00:00:00Z','2026-10-12T00:00:00Z')
    assert new_model['fitted']==model['fitted'] and altered['selected_on_validation']==report['selected_on_validation']

def test_binary_tail_is_accounted_and_source_is_unchanged(tmp_path):
    first=b'date=2026-10-31 time=10:00:00 eventtime=1793440800000000000 tz="+0530" devname="FW01" type="traffic" subtype="forward" srcip=10.0.0.1 srcintfrole="lan" dstip=203.0.113.5 dstintfrole="wan" action="accept"\n'
    second=first.replace(b'1793440800000000000',b'1793440801000000000')
    raw=first+b'\xffbad\n'*300+second
    path=tmp_path/'binary-tail.log';path.write_bytes(raw)
    con,stats,cfg=read_events(tmp_path,path,{'chunk_bytes':1024})
    assert stats['events']==2 and stats['reader_rejected_records']==300
    assert path.read_bytes()==raw
    ledgers=list((tmp_path/'out/ingest_cache').glob('*.quarantine.jsonl'))
    records=[json.loads(line) for file in ledgers for line in file.read_text(encoding='utf-8').splitlines()]
    assert sum(row['bytes'] for row in records)==1500
    assert all(row['source_file']==str(path) and row['sha256'] for row in records)
    con.close()


def test_oversized_components_obey_hard_bounds_without_losing_signals():
    from tracekc.correlate import _split_oversized
    signals=[{'signal_id':i,'host':'HOST'+str(i%2),'user_name':None,'ts_first_ms':i} for i in range(600)]
    groups=_split_oversized(signals,{'max_incident_signals':50,'max_incident_hosts':1})
    assert all(len(group)<=50 and len({s['host'] for s in group})<=1 for group in groups)
    assert sorted(s['signal_id'] for group in groups for s in group)==list(range(600))


def test_revoked_mapping_keeps_original_and_explains_replacement():
    import duckdb
    from tracekc.detect import DETECTIONS_DDL
    from tracekc.label import label,load_mapping
    from tracekc.config import PROJECT_ROOT
    with duckdb.connect() as con:
        con.execute(DETECTIONS_DDL)
        con.execute("INSERT INTO detections (det_id,rule_id,technique,techniques,tactic_hint) VALUES ('d','legacy','T1070.001',['T1070.001'],'defense-evasion')")
        label(con,load_mapping(PROJECT_ROOT/'configs/attack_mapping.yaml'))
        actual=con.execute('SELECT technique,source_technique,mapping_reason FROM labeled').fetchone()
        assert actual[0]=='T1685.005' and actual[1]=='T1070.001' and 'Revoked technique' in actual[2]
