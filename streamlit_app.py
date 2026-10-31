"""Local seven-stage TRACE demo. Run: python -m streamlit run streamlit_app.py"""
from pathlib import Path
import json
import os

import streamlit as st

from tracekc.config import PROJECT_ROOT, load_env
from tracekc.graph_algorithms import GraphIndex
from tracekc.forecast import predict

load_env()
st.set_page_config(page_title='TRACE · Attack investigation',page_icon='🛡️',layout='wide')


@st.cache_data(max_entries=64,show_spinner=False)
def cached_json(path,mtime):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def read_json(path,default=None):
    path=Path(path)
    try:
        return cached_json(str(path),path.stat().st_mtime_ns)
    except (OSError,ValueError):
        return {} if default is None else default


def table(rows):
    if rows:
        st.dataframe(rows,width='stretch',hide_index=True)
    else:
        st.info('No results available for this view yet.')


def dot_graph(graph):
    colors={'host':'#bfdbfe','user':'#ddd6fe','external':'#fecaca','event':'#fef08a'}
    lines=['digraph TRACE { rankdir=LR; node [shape=box, style="rounded,filled", fontname="Arial"];']
    for node in graph['nodes']:
        lines.append(f'{json.dumps(node["id"])} [label={json.dumps(str(node.get("label",node["id"]))[:85])}, fillcolor="{colors.get(node.get("type"),"#e2e8f0")}"];')
    for edge in graph['edges']:
        style='dashed' if edge.get('evidence_kind') in {'hypothesis','inferred'} else 'solid'
        lines.append(f'{json.dumps(edge["source"])} -> {json.dumps(edge["target"])} [label={json.dumps(edge.get("relation",edge["kind"]))}, style="{style}"];')
    return '\n'.join(lines+['}'])


st.title('TRACE · Security investigation demo')
st.caption('Read → Detect → Map → Link → Graph → Predict → Show')
with st.sidebar:
    st.header('Demo source')
    output=Path(st.text_input('Results directory',value=os.environ.get('TRACE_DEMO_OUT',str(PROJECT_ROOT/'out/firex-full-demo'))))
    st.caption('Default: complete local firex-10G.log run. The app reads saved results; it does not reload raw logs on each click.')
    st.button('Refresh results')
    st.caption('Graph backend: local adjacency indexes · Event engine: DuckDB')


@st.fragment(run_every=3)
def progress_panel():
    progress=read_json(output/'progress.json',{'state':'waiting','stage':'start pipeline'})
    state,stage=progress.get('state','waiting'),progress.get('stage','unknown')
    st.caption(f'Pipeline: {state} · {stage}')
    if progress.get('source_bytes'):
        st.progress(min(1,progress.get('completed_bytes',0)/progress['source_bytes']),
                    text=f"{progress.get('completed_bytes',0)/1e9:.2f} / {progress['source_bytes']/1e9:.2f} GB · {progress.get('chunks',0)} chunks")
    if state=='failed':
        st.error(progress.get('error','Pipeline failed; inspect progress.json'))
    previous=st.session_state.get('pipeline_state')
    st.session_state.pipeline_state=state
    if previous not in {None,'complete'} and state=='complete':
        st.rerun()


progress_panel()
metrics=read_json(output/'run_metrics.json')
index=read_json(output/'index.json',[])
if not index:
    st.info('The complete log is processing. Results will appear when incident materialization completes. Progress updates automatically.')
    st.code('.\\scripts\\demo.ps1',language='powershell')
    st.stop()

with st.sidebar:
    query=st.text_input('Find incident by title / host / tactic')
    prediction_only=st.checkbox('Only incidents after model training cutoff',value=False)
    model=read_json(output/'forecast-model.json')
    rows=[r for r in index if query.lower() in json.dumps(r).lower()]
    if prediction_only and model:
        from tracekc.forecast import timestamp
        rows=[r for r in rows if timestamp(r['first_seen'])>timestamp(model['training_until'])]
    if not rows:
        st.warning('No matching incidents. Adjust the filters.');st.stop()
    selected=st.selectbox('Incident',rows,format_func=lambda r:f"#{r['id']} · {r['score']}/100 · {r['title'][:65]}")
incident=read_json(output/'incidents'/f"{selected['id']}.json")
if not incident:
    st.info('Incident is being published. Refresh in a moment.');st.stop()
timeline=incident.get('timeline',[])
quality=metrics.get('ingest',{})
cols=st.columns(4)
cols[0].metric('Valid normalized events',f"{quality.get('valid_events',quality.get('events',0)):,}")
cols[1].metric('Input size',f"{quality.get('input_bytes',0)/1e9:.2f} GB")
cols[2].metric('Candidate incidents',f'{len(index):,}')
cols[3].metric('Selected incident priority',f"{incident['score']}/100")
if metrics.get('input_quality')=='partially_quarantined':
    st.warning(f"Analysis covers valid records. Rejected physical-line fragments: {quality.get('reader_rejected_records',0):,}. See Read for byte accounting.")
st.subheader(f"Incident #{incident['id']} · {incident['title']}")
tabs=st.tabs(['1 · Read','2 · Detect','3 · Map','4 · Link','5 · Graph','6 · Predict','7 · Show'])

with tabs[0]:
    st.write('Complete input → bounded chunks → typed events → cached Parquet → deduplication.')
    manifest=read_json(output/'ingest_manifest.json',[])
    table(manifest)
    st.json({key:quality.get(key) for key in ('valid_events','events','duplicates_removed','quarantined_rows',
              'reader_rejected_records','reader_rejected_bytes','adapter_rejected_records','missing_timestamp','missing_host','missing_user')})
    with st.expander('Parser schemas and noise policy'):
        from tracekc.parser_contracts import contracts
        st.json(read_json(output/'parser_contracts.json',contracts()))
    with st.expander('Stage latency and DuckDB query timings'):
        table([{'stage':k,'seconds':v} for k,v in metrics.get('timings',{}).items()])
        table(read_json(output/'query_timings.json').get('queries',[])[:12])

with tabs[1]:
    rules=metrics.get('rules',{});detect=metrics.get('detect',{})
    st.write(f"{rules.get('loaded',0):,} rules loaded; {detect.get('base_rules_evaluated','unknown')} base rules applicable to this input.")
    st.caption('Rule coverage depends on telemetry. Vendor alerts and suspicious patterns do not establish successful compromise.')
    table([{'source':k,'detections':v} for k,v in detect.get('detections_by_source',{}).items()])
    table([{'rule':k,'detections':v} for k,v in sorted(detect.get('detections_by_rule',{}).items(),key=lambda r:-r[1])[:25]])

with tabs[2]:
    st.write('Rule-backed ATT&CK labels, catalog validation and mapping reasons.')
    table([{'step':s['step'],'technique':s.get('technique'),'name':s.get('technique_name'),
            'tactic':s.get('tactic'),'reason':s.get('mapping_reason')} for s in timeline])
    st.json(metrics.get('label',{}))

with tabs[3]:
    st.write('Related signals form candidate incidents using entities, time, relation-specific thresholds and hub guards.')
    st.caption('Association strengths are not probabilities or proof of common attribution.')
    table(incident.get('correlation_links',[]))
    relationships=read_json(output/'relationships.json').get('links',[])
    table([r for r in relationships if incident['id'] in (r['source'],r['target'])][:100])

with tabs[4]:
    graph=incident.get('graph',{'nodes':[],'edges':[]});graph_index=GraphIndex(graph)
    st.caption(f"{len(graph['nodes'])} nodes · {len(graph['edges'])} edges. Diagram is bounded; all incident edges remain in the evidence table.")
    if graph['nodes']:
        nodes={n['id']:n for n in graph['nodes']}
        root=st.selectbox('Focus entity',list(nodes),format_func=lambda key:nodes[key].get('label',key))
        depth=st.slider('Graph depth',1,6,2)
        view=graph_index.neighborhood(root,depth=depth,limit=100)
        st.graphviz_chart(dot_graph(view),width='stretch',height=500)
        if view['truncated']:st.info('Diagram capped at 100 nodes. Reduce depth or select another entity.')
        target=st.selectbox('Path target',list(nodes),format_func=lambda key:nodes[key].get('label',key),index=min(1,len(nodes)-1))
        algorithm=st.selectbox('Search algorithm',['Earliest arrival (observed timestamps)','Dijkstra (evidence cost)'])
        if st.button('Find path'):
            from tracekc.forecast import timestamp
            result=graph_index.temporal_path(root,target,int(timestamp(incident['first_seen']).timestamp()*1000),
                    int(timestamp(incident['last_seen']).timestamp()*1000),depth) if algorithm.startswith('Earliest') else graph_index.shortest_path(root,target,depth)
            st.json(result)
        with st.expander('Every incident edge and supporting evidence'):table(graph['edges'])

with tabs[5]:
    st.write('Historical technique sequences + bounded beam search. Reachable targets use time-bounded access evidence.')
    st.caption('Forecasts from TRACE-generated labels are exploratory. Network interaction ranking measures a separate task.')
    horizon=st.slider('Future technique depth',1,5,3)
    prefix=[s['technique'] for s in timeline if s.get('technique')]
    forecast=predict(model or None,prefix[-1] if prefix else None,incident['first_seen'],prefix,
                     {'sequence_depth':horizon,'top_n':5,'beam_width':20})
    st.write(f"Model: {forecast.get('method','unavailable')} · Status: {forecast['status']}")
    for warning in forecast.get('evaluation_warnings',[]):st.warning(warning)
    for n,path in enumerate(forecast.get('sequences',[]),1):
        st.markdown(f"**{n}. {' → '.join(path['techniques'])}**")
        st.caption(f"Empirical path score {path['model_path_score']:.3f}; not the probability of an actual attack.")
    if not forecast.get('sequences'):st.info(forecast.get('reason','No supported sequences available.'))
    table(incident.get('lookahead',{}).get('reachable',[]))
    for name,file in [('Attacker-technique comparison','forecast-comparison.json'),('Network interaction experiment','temporal-benchmark.json')]:
        with st.expander(name):st.json(read_json(output/file,{'status':'not run yet'}))

with tabs[6]:
    st.write('Timeline, raw evidence, analyst notes, reports and optional Sarvam assistance.')
    with st.expander('Isolated findings and audited suppressions'):
        findings=read_json(output/'findings.json',[])
        st.json(findings[:100] if isinstance(findings,list) else {k:v[:100] if isinstance(v,list) else v for k,v in findings.items()})
        suppressed=read_json(output/'suppressed.json',[])
        st.json(suppressed[:100] if isinstance(suppressed,list) else suppressed)
    table([{key:s.get(key) for key in ('step','ts','title','host','user','technique','severity')} for s in timeline])
    event_ids=sorted({e for s in timeline for e in s.get('event_ids',[])})
    if event_ids:
        event_id=st.selectbox('Cited event',event_ids)
        if st.button('Load original normalized evidence'):
            import duckdb
            from tracekc.engine import dicts
            with duckdb.connect() as con:
                st.json(dicts(con,'SELECT * FROM read_parquet(?) WHERE event_id=? LIMIT 1',[str(output/'evidence.parquet'),event_id]))
    st.download_button('Download incident JSON',json.dumps(incident,indent=2),file_name=f"incident-{incident['id']}.json",mime='application/json')
    st.download_button('Download report',incident.get('narrative',''),file_name=f"incident-{incident['id']}.txt")
    from tracekc.cases import Cases,CaseUpdate
    cases=Cases(output);case=cases.get(incident['fingerprint'])
    with st.form('case_update'):
        status=st.selectbox('Case status',['new','investigating','contained','closed'],index=['new','investigating','contained','closed'].index(case['status']))
        note=st.text_area('Analyst note',max_chars=10000)
        if st.form_submit_button('Save case update'):
            try:cases.update(incident['fingerprint'],CaseUpdate(status=status,note=note,version=case['version']));st.success('Saved')
            except ValueError as exc:st.error(str(exc))
    with st.expander('Case history'):st.json(cases.get(incident['fingerprint'])['history'])
    from tracekc.ai import SarvamService,AIRequest,AIError,LANGUAGES
    service=SarvamService(output)
    st.caption(f"Sarvam model: {service.model} · {'Key configured' if service.key else 'Add SARVAM_API_KEY to .env'}")
    task=st.selectbox('AI task',['summary','investigate','chat','map','rule','translate'])
    language=st.selectbox('Language',sorted(LANGUAGES))
    question=st.text_input('Question / investigation instruction',max_chars=2000)
    if st.button('Ask Sarvam',disabled=not bool(service.key)):
        from tracekc.label import load_mapping
        try:
            with st.spinner('Analyzing bounded incident evidence…'):
                result=service.analyze(incident,AIRequest(task=task,language=language,question=question),load_mapping(PROJECT_ROOT/'configs/attack_mapping.yaml'))
            st.json(result)
        except AIError as exc:st.error(str(exc))
