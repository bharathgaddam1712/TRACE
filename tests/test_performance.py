"""Semantic checks for latency optimizations: evidence and temporal entity identity."""
import json
import shutil

import pytest

from tracekc.config import load_config
from tracekc.detect import DETECTIONS_DDL, _volume
from tracekc.engine import connect
from tracekc.ingest import ingest


@pytest.mark.skipif(not (shutil.which('gcc') or shutil.which('clang')), reason='optional C compiler unavailable')
def test_native_fortigate_matches_regex_reader_and_quarantine(tmp_path):
    from tracekc.fortigate import raw_view
    from tracekc.ingest import ECS_COLUMNS, NORMALIZE_SQL
    from tracekc.native_reader import tokenize
    prefix = 'date=2026-10-31 time=01:02:03 tz="+0000" devname="FW" type=traffic subtype=forward srcip=10.0.0.1 dstip=8.8.8.8 '
    source = tmp_path/'events.log'
    variants = ['action=accept msg="hello world"', 'action=deny msg="" user="नमस्ते"',
                'action=accept msg="escaped \\"quote\\" and backslash \\\\"',
                'action=accept foo=bar=baz dstport=443', 'action=accept user="unterminated value',
                'action=accept filename="a,b.txt" srcport=0', 'action=accept msg="NULL"']
    source.write_text('\ufeff'+'\r\n'.join(prefix+v for v in variants),encoding='utf-8')
    cfg = load_config(overrides=['engine.threads=2','engine.memory_limit=512MB'])
    con = connect(cfg,tmp_path/'test.duckdb',tmp_path/'spill')
    try:
        raw_view(con,source,ECS_COLUMNS,16777216)
        con.execute('CREATE TABLE reference AS '+NORMALIZE_SQL)
        tokens = tokenize(source,tmp_path,16777216)
        assert tokens is not None
        raw_view(con,source,ECS_COLUMNS,16777216,token_source=tokens)
        # Physical token filename is not evidence provenance.
        sql = NORMALIZE_SQL.replace('filename AS src_file', "'reference' AS src_file")
        con.execute('CREATE TABLE candidate AS '+sql)
        assert con.execute('SELECT count(*) FROM ((SELECT * EXCLUDE(src_file) FROM reference EXCEPT ALL SELECT * EXCLUDE(src_file) FROM candidate) UNION ALL (SELECT * EXCLUDE(src_file) FROM candidate EXCEPT ALL SELECT * EXCLUDE(src_file) FROM reference))').fetchall()[0][0] == 0
        memory=tokenize(source,tmp_path,16777216,in_memory=True)
        raw_view(con,source,ECS_COLUMNS,16777216,token_source=memory)
        con.execute('CREATE TABLE memory_candidate AS '+sql)
        assert con.execute('SELECT count(*) FROM ((SELECT * EXCLUDE(src_file) FROM reference EXCEPT ALL SELECT * EXCLUDE(src_file) FROM memory_candidate) UNION ALL (SELECT * EXCLUDE(src_file) FROM memory_candidate EXCEPT ALL SELECT * EXCLUDE(src_file) FROM reference))').fetchall()[0][0] == 0
        con.execute('DROP VIEW raw');con.execute('DROP VIEW _trace_native_tokens');memory.close()
        for in_memory in (False,True):
            encoded=tokenize(source,tmp_path,16777216,in_memory=in_memory,format='json')
            raw_view(con,source,ECS_COLUMNS,16777216,token_source=encoded)
            con.execute('CREATE OR REPLACE TABLE json_candidate AS '+sql).fetchall()
            assert con.execute('SELECT count(*) FROM ((SELECT * EXCLUDE(src_file) FROM reference EXCEPT ALL SELECT * EXCLUDE(src_file) FROM json_candidate) UNION ALL (SELECT * EXCLUDE(src_file) FROM json_candidate EXCEPT ALL SELECT * EXCLUDE(src_file) FROM reference))').fetchall()[0][0]==0
            if in_memory:
                con.execute('DROP VIEW raw').fetchall();con.execute('DROP VIEW _trace_native_tokens').fetchall();encoded.close()
    finally:
        con.close()
    duplicate=tmp_path/'duplicate.log'
    duplicate.write_text(prefix+'user=alice user=bob\n',encoding='utf-8')
    with pytest.raises(ValueError,match='Map keys must be unique'):
        tokenize(duplicate,tmp_path,16777216)
    source.write_bytes((prefix+'action=accept\n').encode()+b'\xff\x00\n'+(prefix+'action=deny\n').encode())
    bounded=tokenize(source,tmp_path,16777216,in_memory=True,length=len((prefix+'action=accept\n').encode()))
    bounded.close()
    cfg['ingest']['chunk_bytes']=200
    work=tmp_path/'out'/'work';work.mkdir(parents=True)
    con=connect(cfg,work/'test.duckdb',work/'spill')
    try:
        stats=ingest(con,cfg,source,work)
        assert stats['valid_events']==2 and stats['reader_rejected_bytes']==3
    finally:
        con.close()


def test_volume_keeps_thresholds_counts_and_largest_evidence(tmp_path):
    cfg = load_config(overrides=['engine.threads=2', 'engine.memory_limit=512MB'])
    records = []
    # Six low-volume buckets establish the host median; the last bucket qualifies.
    for hour in range(7):
        for index, size in enumerate(([200000000, 100000000] if hour == 6 else [100, 200])):
            records.append({'@timestamp':f'2026-10-31T{hour:02d}:00:{index:02d}Z',
                'event':{'id':f'{hour}-{index}', 'action':'network_connection'},
                'host':{'name':'WS-01', 'ip':['10.0.0.1']},
                'source':{'ip':'10.0.0.1'}, 'destination':{'ip':'8.8.8.8'},
                'network':{'direction':'outbound', 'bytes':size}})
    source = tmp_path/'events.jsonl'
    source.write_text('\n'.join(map(json.dumps, records)), encoding='utf-8')
    work = tmp_path/'out'/'work'; work.mkdir(parents=True)
    con = connect(cfg, work/'test.duckdb', work/'spill')
    try:
        ingest(con, cfg, source, work)
        con.execute(DETECTIONS_DDL)
        _volume(con, cfg['detection']['volume'], 1)
        row = con.execute('SELECT event_count,event_ids,evidence FROM detections').fetchone()
        assert row[:2] == (2, ['6-0'])
        evidence = json.loads(row[2])
        assert evidence == {'bytes_total':300000000, 'connections':2,
                            'baseline_scope':'host', 'threshold_bytes':100000000.0}
    finally:
        con.close()


def test_resolved_materialization_preserves_entity_and_time_fields(tmp_path):
    cfg = load_config(overrides=['engine.threads=2','engine.memory_limit=512MB',
                                  'ingest.resolved_materialize_min_rows=1'])
    source = tmp_path/'events.jsonl'
    source.write_text(json.dumps({'@timestamp':'2026-10-31T00:00:00Z',
        'event':{'id':'a','action':'process_created'}, 'host':{'name':'WS-01','ip':['10.0.0.1']},
        'process':{'pid':42,'entity_id':'first'}, 'source':{'ip':'10.0.0.1'}}), encoding='utf-8')
    work = tmp_path/'out'/'work'; work.mkdir(parents=True)
    con = connect(cfg, work/'test.duckdb', work/'spill')
    try:
        stats = ingest(con, cfg, source, work)
        assert con.execute('SELECT event_id,proc_entity_id,src_host FROM ev').fetchone() == ('a','first','WS-01')
        assert stats['timings']['resolve_entities_once_seconds'] >= 0
        assert (work/'resolved_events.parquet').exists()
    finally:
        con.close()


def test_api_returns_every_incident_without_pagination_by_default(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from tracekc.api import create_app, Store
    monkeypatch.setenv('TRACE_API_TOKEN','')
    monkeypatch.setenv('TRACE_GRAPH_BACKEND','local')
    folder=tmp_path/'incidents';folder.mkdir()
    rows=[]
    for number in range(1,1006):
        row={'id':number,'fingerprint':f'case-{number}','score':50,'tactics':[], 'title':f'Incident {number}'}
        rows.append(row)
        (folder/f'{number}.json').write_text(json.dumps(row),encoding='utf-8')
    (tmp_path/'index.json').write_text(json.dumps(rows),encoding='utf-8')
    store=Store(tmp_path)
    assert len(store.incidents)==0
    for number in range(1,21):assert store.incident(number)['id']==number
    assert len(store.incidents)==16 and 1 not in store.incidents
    with TestClient(create_app(tmp_path)) as client:
        assert len(client.get('/incidents').json())==1005
        page=client.get('/incidents?offset=5&limit=10').json()
        assert len(page)==10 and page[0]['id']==6
        (folder/'1.json').write_text(json.dumps({**rows[0],'fingerprint':'unpublished'}),encoding='utf-8')
        assert client.get('/incidents/1').status_code==503


def test_deduplication_keeps_cross_chunk_duplicates_once(tmp_path):
    records=[{'@timestamp':'2026-10-31T00:00:00Z','host':{'name':'WS'},
              'event':{'id':str(i),'action':'network_connection'},'message':'payload '+str(i)} for i in range(100)]
    source=tmp_path/'events.jsonl';source.write_text('\n'.join(map(json.dumps,records+records)),encoding='utf-8')
    cfg=load_config(overrides=['engine.threads=2','engine.memory_limit=512MB',
        'ingest.chunk_bytes=10000'])
    work=tmp_path/'out'/'work';work.mkdir(parents=True)
    con=connect(cfg,work/'test.duckdb',work/'spill')
    try:
        stats=ingest(con,cfg,source,work)
        assert stats['valid_events']==100 and stats['duplicates_removed']==100
        assert con.execute('SELECT count(DISTINCT event_id),count(*) FROM events').fetchone()==(100,100)
        assert con.execute("SELECT message FROM events WHERE event_id='99'").fetchone()[0]=='payload 99'
    finally:
        con.close()


@pytest.mark.parametrize('dedupe',[True,False])
def test_rule_batch_preserves_match_sets_with_and_without_unique_event_ids(tmp_path,dedupe):
    from tracekc.detect import _rule_hits
    from tracekc.sigma import parse_rule
    source=tmp_path/'events.jsonl'
    record={'@timestamp':'2026-10-31T00:00:00Z','host':{'name':'WS'},
            'event':{'id':'a','action':'network_connection'},'source':{'ip':'10.0.0.1'}}
    source.write_text('\n'.join(map(json.dumps,[record,record,{**record,'event':{'id':'b','action':'network_connection'}}])),encoding='utf-8')
    cfg=load_config(overrides=['engine.threads=2','engine.memory_limit=512MB'])
    cfg['ingest']['dedupe_events']=dedupe
    work=tmp_path/'out'/'work';work.mkdir(parents=True)
    con=connect(cfg,work/'test.duckdb',work/'spill')
    try:
        ingest(con,cfg,source,work)
        rules={r.id:r for r in [parse_rule({'id':name,'title':name,'detection':{'sel':selection,'condition':'sel'}},'test.yml')
                               for name,selection in [('network',{'event.action':'network_connection'}),('source',{'source.ip':'10.0.0.1'})]]}
        assert _rule_hits(con,rules,16,unique_events=dedupe)==2
        assert con.execute('SELECT event_id,list_sort(hits) FROM rule_hits ORDER BY event_id').fetchall()==[('a',['network','source']),('b',['network','source'])]
    finally:
        con.close()


def test_graph_accumulation_retains_each_observation_and_full_time_extent():
    from tracekc.materialize import _graph, iso
    signals=[]
    for index,(first,last) in enumerate(((20,30),(10,50),(40,60)),1):
        signals.append({'signal_id':index,'host':'WS','user_name':'alice','src_host':None,'dst_host':None,
            'src_ip':'10.0.0.1','dst_ip':'8.8.8.8','dst_domain':None,'title':'test','evidence':None,
            'event_ids':['z',str(index)],'technique':'T1071','ts_first_ms':first,'ts_last_ms':last})
    graph=_graph(signals,{'8.8.8.8'},{'reachable':[]})
    edge=next(e for e in graph['edges'] if e['kind']=='outbound')
    assert edge['steps']==[1,2,3] and edge['event_ids']==['1','2','3','z']
    assert edge['first_seen']==iso(10) and edge['last_seen']==iso(60)
    assert edge['observation_times_ms']==[10,20,30,40,50,60]
    assert not any(key.startswith('_') for e in graph['edges'] for key in e)


@pytest.mark.parametrize('legacy',[True,False])
def test_forecast_attachment_preserves_current_graph_and_upgrades_legacy_times(tmp_path,legacy):
    from tracekc.forecast import attach_model, timestamp
    start='2026-10-31T00:00:00Z';end='2026-10-31T00:00:01Z'
    times=[int(timestamp(t).timestamp()*1000) for t in (start,end)]
    graph={'nodes':[{'id':'a'},{'id':'b'}],'edges':[{'source':'a','target':'b','kind':'observed_on','steps':[1]}]}
    if not legacy:
        graph['observation_schema_version']=2;graph['edges'][0]['observation_times_ms']=times
    incident={'id':1,'first_seen':start,'timeline':[{'step':1,'ts':start,'ts_last':end,'technique':'T1110'}],'graph':graph}
    folder=tmp_path/'incidents';folder.mkdir()
    (folder/'1.json').write_text(json.dumps(incident),encoding='utf-8')
    (tmp_path/'index.json').write_text('[{"id":1}]',encoding='utf-8')
    model={'method':'historical_first_order_transition_baseline','selected_model':'markov1',
           'training_until':'2026-10-30T00:00:00Z','transitions':{'T1110':{'T1071':3}}}
    path=tmp_path/'model.json';path.write_text(json.dumps(model),encoding='utf-8')
    result=attach_model(tmp_path,path)
    saved=json.loads((folder/'1.json').read_text(encoding='utf-8'))
    assert result['estimated']==1 and result['raw_reprocessing'] is False
    assert saved['graph']['edges'][0]['observation_times_ms']==times
    assert saved['graph']['observation_schema_version']==2
    assert saved['forecast']['candidates'][0]['technique']=='T1071'


def test_demo_awake_request_restores_previous_state_after_failure():
    from tracekc.runtime import keep_awake
    calls=[]
    def setter(flags):
        calls.append(flags);return 0x80000000
    with pytest.raises(RuntimeError):
        with keep_awake(setter) as enabled:
            assert enabled
            raise RuntimeError('example failure')
    assert calls==[0x80000003,0x80000000]


def test_forecast_sidecar_uses_published_history_without_rewriting_graphs(tmp_path,monkeypatch):
    import hashlib
    from tracekc.forecast import attach_model, export_history
    from tracekc.api import Store
    from tracekc.materialize import write_json
    index=[{'id':1,'fingerprint':'one','first_seen':'2026-10-31T00:00:00Z'}]
    incident={**index[0],'timeline':[{'technique':'T1110','step':1}], 'graph':{'nodes':[],'edges':[]}}
    folder=tmp_path/'incidents';folder.mkdir();write_json(folder/'1.json',incident);before=(folder/'1.json').read_bytes()
    write_json(tmp_path/'index.json',index)
    payload={'label_source':'analyst_reviewed','incidents':[{'id':'one','started_at':index[0]['first_seen'],
        'ended_at':index[0]['first_seen'],'techniques':['T1110']}]}
    write_json(tmp_path/'sequence_history.json',{'index_sha256':hashlib.sha256((tmp_path/'index.json').read_bytes()).hexdigest(),'history':payload})
    assert export_history(tmp_path,use_cache=True)==payload
    model={'method':'historical_first_order_transition_baseline','selected_model':'markov1',
           'training_until':'2026-10-30T00:00:00Z','transitions':{'T1110':{'T1071':3}}}
    path=tmp_path/'model.json';write_json(path,model)
    result=attach_model(tmp_path,path,sidecar=True)
    assert result['estimated']==1 and (folder/'1.json').read_bytes()==before
    assert Store(tmp_path).incident(1)['forecast']['candidates'][0]['technique']=='T1071'


def test_native_prefetch_reuses_one_result_and_cleans_unconsumed_files(tmp_path,monkeypatch):
    import threading
    from tracekc import native_reader
    source=tmp_path/'source.log';source.write_bytes(b'first\nsecond\nthird\n')
    calls=[];finished=threading.Event()
    def fake_tokenize(source,cache,maximum,**kwargs):
        calls.append((kwargs['offset'],kwargs['length']))
        target=kwargs['destination'];target.write_text('tokens')
        target.with_suffix('.meta.json').write_text('{}');finished.set();return target
    monkeypatch.setattr(native_reader,'tokenize',fake_tokenize)
    with native_reader.TokenPrefetch(True) as reader:
        reader.ahead(source,tmp_path,1024,6,source.stat().st_size,7,'json')
        assert finished.wait(5)
        result=reader.get(source,tmp_path,1024,offset=6,length=7)
        assert calls==[(6,7)] and result.read_text()=='tokens'
        result.unlink();result.with_suffix('.meta.json').unlink()
        finished.clear();reader.ahead(source,tmp_path,1024,13,source.stat().st_size,7,'json')
        assert finished.wait(5)
    assert not list(tmp_path.glob('prefetch-*'))


def test_graph_evidence_cap_matches_full_union_for_large_unordered_inputs():
    from tracekc.materialize import _graph
    records=[]
    for index in range(2):
        records.append({'signal_id':index,'host':'WS','user_name':None,'src_host':None,'dst_host':None,
            'src_ip':None,'dst_ip':'8.8.8.8','dst_domain':None,'title':'test','evidence':None,
            'event_ids':[str(n) for n in range(1200-index*30,-1,-1)],'technique':'T1071',
            'ts_first_ms':index,'ts_last_ms':index})
    edge=next(e for e in _graph(records,{'8.8.8.8'},{'reachable':[]})['edges'] if e['kind']=='outbound')
    assert edge['event_ids']==sorted({eid for record in records for eid in record['event_ids']})[:100]


def test_graph_publication_normalizes_edges_without_search_index():
    from tracekc.graph_algorithms import GraphIndex
    graph={'nodes':[{'id':'a'},{'id':'b'}], 'edges':[{'source':'a','target':'b','kind':'ran',
        'observation_times_ms':[20,10,20]}]}
    normal=GraphIndex(graph);publication=GraphIndex(graph,build_adjacency=False)
    assert normal.edges==publication.edges and normal.nodes==publication.nodes
    assert not publication.adjacency


def test_forecast_model_summary_download_and_eligible_incident(tmp_path,monkeypatch):
    import hashlib
    from fastapi.testclient import TestClient
    from tracekc.api import create_app
    from tracekc.materialize import write_json
    monkeypatch.setenv('TRACE_API_TOKEN','');monkeypatch.setenv('TRACE_GRAPH_BACKEND','local')
    row={'id':7,'fingerprint':'case-seven'};folder=tmp_path/'incidents';folder.mkdir()
    write_json(folder/'7.json',row);write_json(tmp_path/'index.json',[row])
    model={'method':'historical_transition_model_comparison','selected_model':'markov1',
           'training_until':'2026-10-30T00:00:00Z','training_incidents':10,'label_source':'trace_predictions_unreviewed',
           'benchmark':{'warnings':['Review labels'],'test':{'markov1':{'transitions':3,'top1':0.5}}}}
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/forecast/model').json()['status']=='unavailable'
        assert client.get('/forecast/model/download').status_code==404
    write_json(tmp_path/'forecast-model.json',model)
    write_json(tmp_path/'forecasts.json',{'index_sha256':hashlib.sha256((tmp_path/'index.json').read_bytes()).hexdigest(),
        'predictions':{'7':{'fingerprint':'case-seven','forecast':{'status':'estimated'}}}})
    with TestClient(create_app(tmp_path)) as client:
        summary=client.get('/forecast/model').json()
        assert summary['selected_model']=='markov1' and summary['training_incidents']==10
        assert summary['example_incident_id']==7 and summary['eligible_incidents']==1
        assert summary['warnings']==['Review labels']
        response=client.get('/forecast/model/download')
        assert response.json()==model and 'attachment' in response.headers['content-disposition']


def test_demo_timestamp_is_saved_artifact_publication_time(tmp_path,monkeypatch):
    from datetime import datetime,timezone
    from fastapi.testclient import TestClient
    from tracekc.api import create_app
    from tracekc.materialize import write_json
    monkeypatch.setenv('TRACE_API_TOKEN','');monkeypatch.setenv('TRACE_GRAPH_BACKEND','local')
    write_json(tmp_path/'demo_timings.json',{'complete_demo_seconds':400,'under_ten_minutes':True})
    expected=datetime.fromtimestamp((tmp_path/'demo_timings.json').stat().st_mtime,timezone.utc)
    with TestClient(create_app(tmp_path)) as client:
        response=client.get('/demo/timings').json()
        assert response['complete_demo_seconds']==400 and response['under_ten_minutes']
        assert datetime.fromisoformat(response['published_at'])==expected
        assert response['run_name']==tmp_path.name


def test_native_prefetch_failure_reaches_foreground_before_checkpoint(tmp_path,monkeypatch):
    from tracekc import native_reader
    source=tmp_path/'source.log';source.write_bytes(b'first\nsecond\n')
    def fail(*args,**kwargs):raise ValueError('Invalid unicode')
    monkeypatch.setattr(native_reader,'tokenize',fail)
    with native_reader.TokenPrefetch(True) as reader:
        reader.ahead(source,tmp_path,1024,6,source.stat().st_size,7,'json')
        with pytest.raises(ValueError,match='Invalid unicode'):
            reader.get(source,tmp_path,1024,offset=6,length=7)
    assert not list(tmp_path.glob('*.checkpoint.json'))


def test_streamed_dictionary_batches_drain_when_closed(tmp_path):
    import duckdb
    from tracekc.engine import iter_dicts,run
    con=duckdb.connect()
    try:
        rows=iter_dicts(con,'SELECT range AS n FROM range(10000)',batch_size=3)
        assert next(rows)=={'n':0}
        rows.close()
        assert run(con,'SELECT 42')==[(42,)]
        assert list(iter_dicts(con,'SELECT 1 AS n WHERE FALSE',batch_size=2))==[]
        with pytest.raises(ValueError):list(iter_dicts(con,'SELECT 1',batch_size=0))
    finally:con.close()


def test_stage_rss_tracks_peaks_separately(monkeypatch):
    from tracekc.pipeline import RssSampler
    sampler=RssSampler();values=iter([5,9,4,3,6,2])
    monkeypatch.setattr(sampler,'_rss',lambda:next(values))
    sampler.begin_stage('read');sampler.observe();sampler.end_stage()
    sampler.begin_stage('graph');sampler.observe();sampler.end_stage()
    assert sampler.peak==9 and sampler.stage_peaks=={'read':9,'graph':6}


def test_parquet_codec_is_explicit_and_rejects_sql_fragments():
    from tracekc.ingest import parquet_codec
    assert parquet_codec({})=='zstd'
    assert parquet_codec({'parquet_compression':'LZ4_RAW'})=='lz4_raw'
    with pytest.raises(ValueError,match='parquet_compression'):
        parquet_codec({'parquet_compression':"zstd); DROP TABLE events; --"})
