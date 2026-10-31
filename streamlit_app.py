"""Local seven-stage TRACE demo. Run: python -m streamlit run streamlit_app.py"""
from pathlib import Path
import html
import json
import os

import streamlit as st

from tracekc.config import PROJECT_ROOT, load_env
from tracekc.graph_algorithms import GraphIndex
from tracekc.forecast import predict
from tracekc import ui_graph

load_env()
st.set_page_config(page_title='TRACE · Attack investigation', page_icon='🛡️', layout='wide')

STYLE = """<style>
#MainMenu, footer, [data-testid="stDecoration"] {visibility:hidden;height:0}
[data-testid="stHeader"] {background:transparent}
.block-container {padding-top:1.4rem;padding-bottom:3rem;max-width:1500px}
.hero {display:flex;justify-content:space-between;align-items:center;gap:16px;padding:18px 22px;border:1px solid #22304d;
  border-radius:14px;background:linear-gradient(120deg,#0f1a33 0%,#111a2e 55%,#1a1530 100%);margin-bottom:16px}
.hero h1 {font-size:1.55rem;margin:0;letter-spacing:.01em}.hero p {margin:2px 0 0;color:#94a3b8;font-size:.92rem}
.pills {display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.pill {font-size:.78rem;padding:4px 10px;border-radius:999px;border:1px solid #22304d;background:#0b1220;color:#cbd5e1;white-space:nowrap}
.pill.ok {border-color:#14532d;color:#86efac}.pill.warn {border-color:#713f12;color:#fde68a}.pill.bad {border-color:#7f1d1d;color:#fca5a5}
.kpis {display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:4px 0 16px}
.kpi {border:1px solid #22304d;border-radius:12px;background:#111a2e;padding:14px 16px}
.kpi .l {font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8}
.kpi .v {font-size:1.6rem;font-weight:650;margin-top:2px}.kpi .s {font-size:.78rem;color:#64748b}
.inc {border:1px solid #22304d;border-radius:14px;background:#111a2e;padding:16px 20px;margin-bottom:10px}
.inc-top {display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
.inc h2 {font-size:1.15rem;margin:0 0 4px;line-height:1.35}.meta {color:#94a3b8;font-size:.85rem}
.score {min-width:92px;text-align:center;border-radius:12px;padding:8px 10px;font-weight:700;font-size:1.4rem}
.score small {display:block;font-size:.68rem;font-weight:500;letter-spacing:.06em;text-transform:uppercase;opacity:.85}
.chain {display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.stage {font-size:.78rem;padding:3px 10px;border-radius:6px;background:#16213a;border:1px solid #2a3a5e;color:#c7d2fe}
.arrow {color:#475569;align-self:center}
.stTabs [data-baseweb="tab-list"] {gap:4px;border-bottom:1px solid #22304d}
.stTabs [data-baseweb="tab"] {padding:8px 16px;border-radius:8px 8px 0 0;font-weight:500}
.stTabs [aria-selected="true"] {background:#111a2e}
.section {font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin:18px 0 6px}
[data-testid="stSidebar"] {border-right:1px solid #22304d}
</style>"""
st.markdown(STYLE, unsafe_allow_html=True)


@st.cache_data(max_entries=64, show_spinner=False)
def cached_json(path, mtime):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def read_json(path, default=None):
    path = Path(path)
    try:
        return cached_json(str(path), path.stat().st_mtime_ns)
    except (OSError, ValueError):
        return {} if default is None else default


def table(rows, **kwargs):
    if rows:
        st.dataframe(rows, width='stretch', hide_index=True, **kwargs)
    else:
        st.info('No results available for this view yet.')


def section(title):
    st.markdown(f'<div class="section">{html.escape(title)}</div>', unsafe_allow_html=True)


def severity_name(value):
    if isinstance(value, str):
        return value
    value = value or 0
    return 'critical' if value >= 90 else 'high' if value >= 70 else 'medium' if value >= 40 else 'low'


def score_colours(score):
    return ('#7f1d1d', '#fecaca') if score >= 80 else ('#78350f', '#fde68a') if score >= 60 else ('#1e3a8a', '#bfdbfe')


def kpis(cards):
    body = ''.join(f'<div class="kpi"><div class="l">{html.escape(l)}</div><div class="v">{html.escape(v)}</div>'
                   f'<div class="s">{html.escape(s)}</div></div>' for l, v, s in cards)
    st.markdown(f'<div class="kpis">{body}</div>', unsafe_allow_html=True)


def result_folders():
    found = []
    for base in (PROJECT_ROOT / 'out', Path('/tmp/trace-demo')):
        if base.exists():
            found += sorted((p.parent for p in base.glob('**/index.json')), key=lambda p: -p.stat().st_mtime)
    return [str(p) for p in dict.fromkeys(found)][:30]


# ------------------------------------------------------------------ sidebar: results source
with st.sidebar:
    st.markdown('### 🛡️ TRACE')
    st.caption('Attack-chain reconstruction from security logs')
    default = os.environ.get('TRACE_DEMO_OUT', str(PROJECT_ROOT / 'out/firex-full-demo'))
    options = list(dict.fromkeys([default] + result_folders()))
    choice = st.selectbox('Results folder', options + ['Other…'], format_func=lambda p: p if p == 'Other…' else
                          (Path(p).relative_to(PROJECT_ROOT).as_posix() if Path(p).is_relative_to(PROJECT_ROOT) else p))
    output = Path(st.text_input('Path to a TRACE results folder') if choice == 'Other…' else choice)
    st.button('↻ Refresh results', width='stretch')

ai_ready = bool(os.environ.get('SARVAM_API_KEY', '').strip())


@st.fragment(run_every=3)
def progress_panel():
    progress = read_json(output / 'progress.json', {'state': 'waiting', 'stage': 'start pipeline'})
    state, stage = progress.get('state', 'waiting'), progress.get('stage', 'unknown')
    if state != 'complete':
        st.caption(f'Pipeline: {state} · {stage}')
    if progress.get('source_bytes') and state != 'complete':
        st.progress(min(1, progress.get('completed_bytes', 0) / progress['source_bytes']),
                    text=f"{progress.get('completed_bytes', 0)/1e9:.2f} / {progress['source_bytes']/1e9:.2f} GB · {progress.get('chunks', 0)} chunks")
    if state == 'failed':
        st.error(progress.get('error', 'Pipeline failed; inspect progress.json'))
    previous = st.session_state.get('pipeline_state')
    st.session_state.pipeline_state = state
    if previous not in {None, 'complete'} and state == 'complete':
        st.rerun()


metrics = read_json(output / 'run_metrics.json')
index = read_json(output / 'index.json', [])
quality = metrics.get('ingest', {})
state = read_json(output / 'progress.json', {}).get('state', 'complete' if index else 'waiting')
pill_state = {'complete': 'ok', 'failed': 'bad'}.get(state, 'warn')
st.markdown(f"""<div class="hero"><div><h1>TRACE · Security investigation</h1>
<p>Read → Detect → Map to ATT&amp;CK → Link → Graph → Predict → Respond</p></div><div class="pills">
<span class="pill {pill_state}">Pipeline: {html.escape(state)}</span><span class="pill">Engine: DuckDB</span>
<span class="pill">Graph: local index</span><span class="pill {'ok' if ai_ready else ''}">Sarvam AI: {'ready' if ai_ready else 'not configured'}</span>
</div></div>""", unsafe_allow_html=True)
progress_panel()
if not index:
    st.info('No incidents in this folder yet. If a run is in progress, results appear when it finishes; progress updates automatically.')
    st.code(f'python -m tracekc run --input LOGFILE --out {output}', language='bash')
    st.stop()

signals = metrics.get('signals', {})
timings = metrics.get('timings', {})
kpis([('Input', f"{quality.get('input_bytes', 0)/1e9:.2f} GB", f"{quality.get('input_files', 0)} file(s)"),
      ('Valid events', f"{quality.get('valid_events', quality.get('events', 0)):,}", f"{quality.get('duplicates_removed', 0):,} duplicates removed"),
      ('Detections', f"{signals.get('signals', 0):,}", f"{signals.get('detections_merged', 0):,} merged alerts"),
      ('Incidents', f'{len(index):,}', f"{sum(1 for i in index if i.get('score', 0) >= 80):,} high priority (≥80)"),
      ('Processing time', f"{timings.get('total_wall_seconds', 0):.1f} s", f"peak {metrics.get('peak_process_tree_rss_gb', 0):.2f} GB RAM")])

with st.sidebar:
    st.divider()
    st.markdown('**Incident queue**')
    query = st.text_input('Search title / host / user / tactic', placeholder='e.g. SRV-DC-01')
    min_score = st.slider('Minimum risk score', 0, 100, 0, 5)
    prediction_only = st.checkbox('Only incidents after model training cutoff', value=False)
    model = read_json(output / 'forecast-model.json')
    rows = [r for r in index if query.lower() in json.dumps(r).lower() and r.get('score', 0) >= min_score]
    if prediction_only and model:
        from tracekc.forecast import timestamp
        rows = [r for r in rows if timestamp(r['first_seen']) > timestamp(model['training_until'])]
    rows.sort(key=lambda r: -r.get('score', 0))
    if not rows:
        st.warning('No matching incidents. Adjust the filters.')
        st.stop()
    st.caption(f'{len(rows):,} of {len(index):,} incidents')
    selected = st.selectbox('Incident', rows, format_func=lambda r: f"#{r['id']} · {r['score']:.0f} · {r['title'].replace(' -> ', ' → ')[:60]}")

incident = read_json(output / 'incidents' / f"{selected['id']}.json")
if not incident:
    st.info('Incident is being published. Refresh in a moment.')
    st.stop()
timeline = incident.get('timeline', [])
if metrics.get('input_quality') == 'partially_quarantined':
    st.warning(f"Analysis covers valid records. Rejected physical-line fragments: {quality.get('reader_rejected_records', 0):,}. See Read for byte accounting.")

background, foreground = score_colours(incident['score'])
entities = incident.get('entities') or {}
hosts, users = entities.get('hosts') or selected.get('hosts', []), entities.get('users') or selected.get('users', [])
chain = '<span class="arrow">›</span>'.join(f'<span class="stage">{html.escape(t)}</span>' for t in incident.get('tactics', []))
st.markdown(f"""<div class="inc"><div class="inc-top"><div><div class="meta">INCIDENT #{incident['id']}</div>
<h2>{html.escape(incident['title']).replace(' -&gt; ', ' → ')}</h2>
<div class="meta">{html.escape(incident['first_seen'])} → {html.escape(incident['last_seen'])} · {len(timeline)} steps ·
{incident.get('raw_event_count', 0):,} raw events · {len(hosts or [])} hosts · {len(users or [])} users</div></div>
<div class="score" style="background:{background};color:{foreground}">{incident['score']:.0f}<small>risk / 100</small></div></div>
<div class="chain">{chain}</div></div>""", unsafe_allow_html=True)
with st.expander('Narrative', expanded=False):
    st.write(incident.get('narrative', ''))

tabs = st.tabs(['① Read', '② Detect', '③ Map', '④ Link', '⑤ Graph', '⑥ Predict', '⑦ Respond'])

with tabs[0]:
    st.caption('Complete input → bounded chunks → typed events → cached Parquet → deduplication.')
    kpis([('Valid events', f"{quality.get('valid_events', quality.get('events', 0)):,}", 'normalized and usable'),
          ('Duplicates removed', f"{quality.get('duplicates_removed', 0):,}", 'same event seen twice'),
          ('Quarantined rows', f"{quality.get('quarantined_rows', 0):,}", 'missing time or host'),
          ('Rejected input', f"{quality.get('reader_rejected_bytes', 0)/1048576:.1f} MiB", f"{quality.get('reader_rejected_records', 0):,} line fragments")])
    section('Input files')
    table(read_json(output / 'ingest_manifest.json', []))
    section('Field completeness')
    table([{'field': k.replace('missing_', '').replace('_', ' '), 'events missing it': quality.get(k, 0)}
           for k in ('missing_timestamp', 'missing_host', 'missing_user', 'missing_action', 'missing_network_endpoints') if k in quality])
    with st.expander('Parser schemas and noise policy'):
        from tracekc.parser_contracts import contracts
        st.json(read_json(output / 'parser_contracts.json', contracts()))
    with st.expander('Stage latency and DuckDB query timings'):
        stage_times = {k.removesuffix('_seconds'): v for k, v in timings.items() if k != 'total_wall_seconds'}
        if stage_times:
            st.bar_chart(stage_times, horizontal=True, height=220)
        table(read_json(output / 'query_timings.json').get('queries', [])[:12])

with tabs[1]:
    rules = metrics.get('rules', {})
    detect = metrics.get('detect', {})
    kpis([('Rules loaded', f"{rules.get('loaded', 0):,}", f"{len(rules.get('covered_techniques', [])):,} ATT&CK techniques"),
          ('Rules applicable', f"{detect.get('base_rules_evaluated', 0):,}", 'for the log types present'),
          ('Detections', f"{signals.get('signals', 0):,}", 'after merging and suppression')])
    st.caption('Rule coverage depends on telemetry. Vendor alerts and suspicious patterns do not establish successful compromise.')
    left, right = st.columns([1, 2])
    with left:
        section('By source')
        table([{'source': k, 'detections': v} for k, v in detect.get('detections_by_source', {}).items()])
    with right:
        section('Top rules')
        top = sorted(detect.get('detections_by_rule', {}).items(), key=lambda r: -r[1])[:25]
        table([{'rule': k, 'detections': v} for k, v in top],
              column_config={'detections': st.column_config.ProgressColumn('detections', format='%d', min_value=0,
                                                                           max_value=max([v for _, v in top] or [1]))})

with tabs[2]:
    st.caption('Rule-backed ATT&CK labels, catalog validation and mapping reasons.')
    table([{'step': s['step'], 'time': s.get('ts'), 'technique': s.get('technique'), 'name': s.get('technique_name'),
            'tactic': s.get('tactic'), 'severity': severity_name(s.get('severity')), 'reason': s.get('mapping_reason')} for s in timeline])
    with st.expander('Mapping validation details'):
        st.json(metrics.get('label', {}))

with tabs[3]:
    st.caption('Related signals form candidate incidents using entities, time, relation-specific thresholds and hub guards. '
               'Association strengths are not probabilities or proof of common attribution.')
    section('Links inside this incident')
    table(incident.get('correlation_links', []))
    section('Related incidents')
    relationships = read_json(output / 'relationships.json').get('links', [])
    table([r for r in relationships if incident['id'] in (r['source'], r['target'])][:100])

with tabs[4]:
    graph = incident.get('graph', {'nodes': [], 'edges': []})
    graph_index = GraphIndex(graph)
    if not graph['nodes']:
        st.info('This incident has no graph.')
    else:
        controls = st.columns([2, 2, 3])
        mode = controls[0].segmented_control('View', ['Entities', 'Full evidence'], default='Entities',
                                             help='Entities: users, hosts, IPs and domains only. Full evidence adds detection steps, processes, files and registry keys.')
        view = ui_graph.entity_view(graph) if mode != 'Full evidence' else graph
        path_nodes = st.session_state.get(f"path-{incident['id']}")
        controls[2].caption(f"{len(view['nodes'])} nodes · {len(view['edges'])} relationships. Click a node to see who it connects to; "
                            'scroll to zoom, drag to pan. Red outline = suspected compromised, dashed = hypothesis.')
        if path_nodes and controls[1].button('Clear highlighted path'):
            st.session_state.pop(f"path-{incident['id']}")
            path_nodes = None
        st.iframe(ui_graph.render(view, path_nodes), height=680)

        section('Who connects to whom')
        connections = ui_graph.connections(view)
        filter_text = st.text_input('Filter relationships', placeholder='user, host, IP, technique…', key=f"cf-{incident['id']}")
        if filter_text:
            connections = [r for r in connections if filter_text.lower() in json.dumps(r).lower()]
        table(connections)

        section('Path search')
        nodes = {n['id']: n for n in graph['nodes']}
        ordered = sorted(nodes, key=lambda key: (ui_graph.node_type(nodes[key]) not in ui_graph.ENTITY_TYPES, str(nodes[key].get('label', key))))
        cols = st.columns([3, 3, 3, 1])
        root = cols[0].selectbox('From', ordered, format_func=lambda key: f"{nodes[key].get('label', key)} ({ui_graph.node_type(nodes[key])})")
        target = cols[1].selectbox('To', ordered, index=min(1, len(ordered) - 1),
                                   format_func=lambda key: f"{nodes[key].get('label', key)} ({ui_graph.node_type(nodes[key])})")
        algorithm = cols[2].selectbox('Algorithm', ['Earliest arrival (observed timestamps)', 'Dijkstra (evidence cost)'])
        depth = cols[3].number_input('Max hops', 1, 12, 6)
        if st.button('Find path', type='primary'):
            from tracekc.forecast import timestamp
            result = graph_index.temporal_path(root, target, int(timestamp(incident['first_seen']).timestamp() * 1000),
                                               int(timestamp(incident['last_seen']).timestamp() * 1000), depth) \
                if algorithm.startswith('Earliest') else graph_index.shortest_path(root, target, depth)
            if result.get('status') == 'found':
                st.session_state[f"path-{incident['id']}"] = result['nodes']
                st.success(' → '.join(str(nodes[n].get('label', n)) for n in result['nodes']) + f"  ·  {result.get('hops')} hops")
                st.caption(result.get('interpretation', ''))
                if mode == 'Full evidence' or all(n in {x['id'] for x in view['nodes']} for n in result['nodes']):
                    st.rerun()
                else:
                    st.caption('Switch to "Full evidence" to see this path highlighted; it passes through detection steps.')
            else:
                st.warning(result.get('reason', 'No path found within the depth limit.'))
            with st.expander('Raw result'):
                st.json(result)
        with st.expander('Every incident edge and supporting evidence'):
            table(graph['edges'])

with tabs[5]:
    st.caption('Historical technique sequences + bounded beam search. Reachable targets use time-bounded access evidence. '
               'Forecasts from TRACE-generated labels are exploratory.')
    left, right = st.columns([1, 1])
    with left:
        section('Next attacker techniques (forecast)')
        horizon = st.slider('Future technique depth', 1, 5, 3)
        prefix = [s['technique'] for s in timeline if s.get('technique')]
        forecast = predict(model or None, prefix[-1] if prefix else None, incident['first_seen'], prefix,
                           {'sequence_depth': horizon, 'top_n': 5, 'beam_width': 20})
        st.caption(f"Model: {forecast.get('method', 'unavailable')} · Status: {forecast['status']}")
        for warning in forecast.get('evaluation_warnings', []):
            st.warning(warning)
        for n, path in enumerate(forecast.get('sequences', []), 1):
            st.markdown(f"**{n}.** {' → '.join(f'`{t}`' for t in path['techniques'])}")
            st.caption(f"Empirical path score {path['model_path_score']:.3f}; not the probability of an actual attack.")
        if not forecast.get('sequences'):
            st.info(forecast.get('reason', 'No supported sequences available.'))
    with right:
        section('Assets reachable next')
        reachable = incident.get('lookahead', {}).get('reachable', [])
        table([{'asset': r['asset'], 'via': r.get('via'), 'relation': r.get('relation'), 'confidence': r.get('confidence'),
                'criticality': r.get('criticality'), 'hops': r.get('hops')} for r in reachable])
        if reachable:
            st.caption(reachable[0].get('interpretation', ''))
    for name, file in [('Attacker-technique comparison', 'forecast-comparison.json'), ('Network interaction experiment', 'temporal-benchmark.json')]:
        with st.expander(name):
            st.json(read_json(output / file, {'status': 'not run yet'}))

with tabs[6]:
    section('Attack timeline')
    table([{'step': s.get('step'), 'time': s.get('ts'), 'what happened': s.get('title'), 'host': s.get('host'), 'user': s.get('user'),
            'technique': s.get('technique'), 'tactic': s.get('tactic'), 'severity': severity_name(s.get('severity'))} for s in timeline])
    event_ids = sorted({e for s in timeline for e in s.get('event_ids', [])})
    cols = st.columns([4, 1, 1, 1])
    if event_ids:
        event_id = cols[0].selectbox('Cited event', event_ids)
        if cols[1].button('Load evidence', width='stretch'):
            import duckdb
            from tracekc.engine import dicts
            with duckdb.connect() as con:
                st.json(dicts(con, 'SELECT * FROM read_parquet(?) WHERE event_id=? LIMIT 1', [str(output / 'evidence.parquet'), event_id]))
    cols[2].download_button('Incident JSON', json.dumps(incident, indent=2), file_name=f"incident-{incident['id']}.json",
                            mime='application/json', width='stretch')
    cols[3].download_button('Report', incident.get('narrative', ''), file_name=f"incident-{incident['id']}.txt", width='stretch')

    triage_col, case_col = st.columns(2)
    with triage_col:
        section('SOC triage workflow')
        st.caption('Campaign facts → entity history / duplicate context → triage → optional investigation → report draft → analyst review. Alerts remain visible.')
        from tracekc.triage import TriagePipeline, TriageRequest, TriageReview
        triage = TriagePipeline(output)
        investigate = st.checkbox('Include follow-up investigation (additional Sarvam request)', value=False)
        if st.button('Run triage agent', type='primary', help=None if ai_ready else 'Without SARVAM_API_KEY the result is a reviewable insufficient-evidence case'):
            from tracekc.label import load_mapping
            with st.spinner('Retrieving past context and triaging the incident…'):
                st.session_state['triage_result'] = triage.run(incident, TriageRequest(investigate=investigate),
                                                               load_mapping(PROJECT_ROOT / 'configs/attack_mapping.yaml'))
        triage_result = st.session_state.get('triage_result')
        if not triage_result or triage_result.get('fingerprint') != incident['fingerprint']:
            triage_result = triage.latest(incident['fingerprint'])['result']
        if triage_result:
            st.write(f"Triage: **{triage_result['status']}** · priority **{triage_result['verdict']['priority']}**")
            st.json(triage_result['verdict'])
            with st.expander('Grounding, investigation and audit details'):
                st.json(triage_result)
            st.download_button('Download triage draft', triage_result['report_draft'], file_name=f"triage-{incident['id']}.md")
            if not triage_result['errors']:
                with st.form('triage_review'):
                    decision = st.selectbox('Analyst triage decision', ['escalate', 'monitor', 'likely_benign'])
                    reason = st.text_area('Reason for analyst decision', max_chars=4000)
                    if st.form_submit_button('Record analyst review'):
                        try:
                            triage.review(incident['fingerprint'], TriageReview(context_hash=triage_result['context_hash'], decision=decision, note=reason))
                            st.success('Analyst review recorded. Case status remains an explicit separate action.')
                        except ValueError as exc:
                            st.error(str(exc))
        with st.expander('Triage review history'):
            st.json(triage.latest(incident['fingerprint'])['reviews'])

    with case_col:
        section('Case management')
        from tracekc.cases import Cases, CaseUpdate
        cases = Cases(output)
        case = cases.get(incident['fingerprint'])
        statuses = ['new', 'investigating', 'contained', 'closed']
        with st.form('case_update'):
            status = st.selectbox('Case status', statuses, index=statuses.index(case['status']))
            note = st.text_area('Analyst note', max_chars=10000)
            if st.form_submit_button('Save case update'):
                try:
                    cases.update(incident['fingerprint'], CaseUpdate(status=status, note=note, version=case['version']))
                    st.success('Saved')
                except ValueError as exc:
                    st.error(str(exc))
        with st.expander('Case history'):
            st.json(cases.get(incident['fingerprint'])['history'])

        section('Ask Sarvam')
        from tracekc.ai import SarvamService, AIRequest, AIError, LANGUAGES
        service = SarvamService(output)
        st.caption(f"Model: {service.model} · {'key configured' if service.key else 'add SARVAM_API_KEY to .env'}")
        task = st.selectbox('AI task', ['summary', 'investigate', 'chat', 'map', 'rule', 'translate'])
        language = st.selectbox('Language', sorted(LANGUAGES))
        question = st.text_input('Question / investigation instruction', max_chars=2000)
        if st.button('Ask Sarvam', disabled=not bool(service.key)):
            from tracekc.label import load_mapping
            try:
                with st.spinner('Analyzing bounded incident evidence…'):
                    result = service.analyze(incident, AIRequest(task=task, language=language, question=question),
                                             load_mapping(PROJECT_ROOT / 'configs/attack_mapping.yaml'))
                st.json(result)
            except AIError as exc:
                st.error(str(exc))

    with st.expander('Isolated findings and audited suppressions'):
        findings = read_json(output / 'findings.json', [])
        st.json(findings[:100] if isinstance(findings, list) else {k: v[:100] if isinstance(v, list) else v for k, v in findings.items()})
        suppressed = read_json(output / 'suppressed.json', [])
        st.json(suppressed[:100] if isinstance(suppressed, list) else suppressed)
