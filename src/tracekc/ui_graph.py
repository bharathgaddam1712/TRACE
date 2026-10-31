"""Interactive incident graph for the Streamlit demo: Cytoscape.js (vendored) rendered offline."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[2] / 'web' / 'vendor' / 'cytoscape.min.js'

# type -> (legend name, colour, cytoscape shape, panel group)
NODE_TYPES = {
    'user': ('User', '#a78bfa', 'ellipse', 'Users'),
    'host': ('Host', '#60a5fa', 'round-rectangle', 'Hosts'),
    'external': ('External IP', '#f87171', 'diamond', 'IP addresses'),
    'ip': ('IP address', '#f87171', 'diamond', 'IP addresses'),
    'domain': ('Domain', '#fb923c', 'hexagon', 'Domains'),
    'event': ('Detection step', '#facc15', 'round-tag', 'Detection steps'),
    'signal': ('Detection step', '#facc15', 'round-tag', 'Detection steps'),
    'process': ('Process', '#34d399', 'round-rectangle', 'Processes'),
    'file': ('File', '#94a3b8', 'rectangle', 'Files'),
    'registry': ('Registry key', '#2dd4bf', 'barrel', 'Registry'),
}
ENTITY_TYPES = {'user', 'host', 'external', 'ip', 'domain'}
EDGE_LABELS = {
    'acted_on': 'logged on / acted on', 'lateral': 'lateral movement', 'outbound': 'outbound connection',
    'inbound': 'inbound connection', 'could_reach': 'could reach', 'observed_on': 'detected on',
    'contacted': 'contacted', 'ran': 'ran process', 'generated': 'generated', 'touched': 'touched file',
    'modified': 'modified', 'correlates_with': 'correlates with',
}


def node_type(node: dict) -> str:
    kind = node.get('type') or node['id'].split(':', 1)[0]
    return kind if kind in NODE_TYPES else 'event' if node['id'].startswith('signal:') else kind


def entity_view(graph: dict) -> dict:
    """Keep users, hosts, IPs and domains; rebuild host->domain/IP contact through collapsed detection steps."""
    nodes = {n['id']: n for n in graph.get('nodes', [])}
    keep = {i for i, n in nodes.items() if node_type(n) in ENTITY_TYPES}
    edges = [e for e in graph.get('edges', []) if e['source'] in keep and e['target'] in keep]
    via = {}
    for edge in graph.get('edges', []):
        for here, there in ((edge['source'], edge['target']), (edge['target'], edge['source'])):
            if here in nodes and here not in keep and there in keep:
                via.setdefault(here, []).append((there, edge))
    seen = {(e['source'], e['target'], e['kind']) for e in edges}
    for step, links in via.items():
        hosts = [(n, e) for n, e in links if node_type(nodes[n]) == 'host']
        remote = [(n, e) for n, e in links if node_type(nodes[n]) in {'domain', 'external', 'ip'}]
        for host, first in hosts:
            for target, second in remote:
                key = (host, target, 'contacted')
                if key in seen:
                    continue
                seen.add(key)
                edges.append({'id': f'via-{len(edges)}', 'source': host, 'target': target, 'kind': 'contacted',
                              'evidence_kind': 'observed_association', 'derived_via': nodes[step].get('label', step),
                              'techniques': sorted(set(first.get('techniques', [])) | set(second.get('techniques', []))),
                              'steps': sorted(set(first.get('steps', [])) | set(second.get('steps', []))),
                              'event_ids': sorted(set(second.get('event_ids', [])))[:100],
                              'first_seen': second.get('first_seen'), 'last_seen': second.get('last_seen')})
    return {'nodes': [nodes[i] for i in keep], 'edges': edges}


def connections(graph: dict) -> list[dict]:
    """One row per relationship, readable without the diagram."""
    nodes = {n['id']: n for n in graph.get('nodes', [])}
    rows = []
    for e in graph.get('edges', []):
        source, target = nodes.get(e['source'], {}), nodes.get(e['target'], {})
        rows.append({'from': source.get('label', e['source']), 'from type': NODE_TYPES.get(node_type(source), ('?',))[0] if source else '?',
                     'relation': EDGE_LABELS.get(e['kind'], e['kind']),
                     'to': target.get('label', e['target']), 'to type': NODE_TYPES.get(node_type(target), ('?',))[0] if target else '?',
                     'techniques': ', '.join(e.get('techniques') or []), 'steps': ', '.join(map(str, e.get('steps') or [])),
                     'events': len(e.get('event_ids') or []), 'first seen': e.get('first_seen'), 'last seen': e.get('last_seen'),
                     'evidence': 'hypothesis' if e['kind'] == 'could_reach' or e.get('evidence_kind') in {'hypothesis', 'inferred'} else 'observed'})
    return rows


def elements(graph: dict, path: list[str] | None = None) -> list[dict]:
    degree = {}
    for e in graph.get('edges', []):
        for end in (e['source'], e['target']):
            degree[end] = degree.get(end, 0) + 1
    on_path = set(path or [])
    out = []
    for n in graph.get('nodes', []):
        kind = node_type(n)
        name, colour, shape, group = NODE_TYPES.get(kind, (kind.title(), '#cbd5e1', 'ellipse', 'Other'))
        label = str(n.get('label', n['id']))
        out.append({'group': 'nodes', 'data': {
            'id': n['id'], 'label': label if len(label) <= 34 else label[:32] + '…', 'full': label, 'kind': kind,
            'kindName': name, 'group': group, 'colour': colour, 'shape': shape, 'role': n.get('role') or '',
            'suspected': bool(n.get('suspected')), 'degree': degree.get(n['id'], 0),
            'size': 26 + min(degree.get(n['id'], 0), 12) * 3, 'onPath': n['id'] in on_path}})
    path_pairs = {frozenset(p) for p in zip(path or [], (path or [])[1:])}
    for i, e in enumerate(graph.get('edges', [])):
        hypothesis = e['kind'] == 'could_reach' or e.get('evidence_kind') in {'hypothesis', 'inferred'}
        out.append({'group': 'edges', 'data': {
            'id': f"e{i}-{e.get('id', '')}", 'source': e['source'], 'target': e['target'], 'kind': e['kind'],
            'label': EDGE_LABELS.get(e['kind'], e['kind']), 'techniques': e.get('techniques') or [],
            'steps': e.get('steps') or [], 'events': len(e.get('event_ids') or []),
            'first': e.get('first_seen') or '', 'last': e.get('last_seen') or '', 'via': e.get('derived_via') or '',
            'hypothesis': hypothesis, 'onPath': frozenset((e['source'], e['target'])) in path_pairs}})
    return out


@lru_cache(maxsize=1)
def _cytoscape() -> str:
    return VENDOR.read_text(encoding='utf-8')


def render(graph: dict, path: list[str] | None = None, height: int = 660) -> str:
    data = json.dumps(elements(graph, path)).replace('</', '<\\/')
    legend = json.dumps({v[0]: v[1] for k, v in NODE_TYPES.items() if k in {node_type(n) for n in graph.get('nodes', [])}})
    return (_TEMPLATE.replace('__CYTOSCAPE__', _cytoscape().replace('</script', '<\\/script'))
            .replace('__ELEMENTS__', data).replace('__LEGEND__', legend).replace('__HEIGHT__', str(height)))


_TEMPLATE = r"""<!doctype html><html><head><meta charset="utf-8"><style>
:root{--bg:#0b1220;--panel:#111a2e;--line:#22304d;--text:#e5e7eb;--muted:#94a3b8;--accent:#3b82f6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:13px/1.45 Inter,system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{display:flex;gap:10px;height:__HEIGHT__px}
.main{flex:1;min-width:0;display:flex;flex-direction:column;border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}
.bar{display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--line)}
.bar #q,.bar select{background:#0b1220;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:5px 8px;font:inherit}
.bar #q{width:170px}#hyp input{margin:0}button{background:#1b2742;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:5px 9px;cursor:pointer;font:inherit}
button:hover{border-color:var(--accent)}.chip{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border:1px solid var(--line);border-radius:999px;cursor:pointer;user-select:none;color:var(--muted)}
.chip.on{color:var(--text);background:#16213a}.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
#cy{flex:1;min-height:0}.side{width:320px;border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:12px;overflow:auto}
.side h3{margin:0 0 2px;font-size:15px}.muted{color:var(--muted)}.kv{display:grid;grid-template-columns:90px 1fr;gap:3px 8px;margin:8px 0}
.grp{margin-top:12px}.grp h4{margin:0 0 6px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.conn{padding:7px 8px;border:1px solid var(--line);border-radius:7px;margin-bottom:6px;cursor:pointer}.conn:hover{border-color:var(--accent)}
.conn b{font-weight:600}.tag{display:inline-block;font-size:11px;padding:1px 6px;border-radius:4px;background:#1e293b;margin:2px 3px 0 0}
.sus{color:#fca5a5;font-weight:600}.tip{position:fixed;pointer-events:none;background:#020617;border:1px solid var(--line);padding:6px 8px;border-radius:6px;max-width:320px;display:none;z-index:9}
.legend{display:flex;flex-wrap:wrap;gap:10px;padding:6px 10px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
</style></head><body>
<div class="wrap"><div class="main">
 <div class="bar"><input id="q" placeholder="Search user, host, IP…"><select id="layout">
  <option value="cose">Force-directed</option><option value="concentric">Concentric (most connected centre)</option>
  <option value="breadthfirst">Hierarchy</option><option value="circle">Circle</option><option value="grid">Grid</option></select>
  <span id="chips"></span><label class="chip on" id="hyp"><input type="checkbox" checked> hypotheses</label>
  <button id="fit">Fit</button><button id="png">PNG</button></div>
 <div id="cy"></div><div class="legend" id="legend"></div></div>
 <div class="side" id="side"></div></div><div class="tip" id="tip"></div>
<script>__CYTOSCAPE__</script><script>
const els=__ELEMENTS__, legend=__LEGEND__;
const cy=cytoscape({container:document.getElementById('cy'),elements:els,wheelSensitivity:0.25,minZoom:0.15,maxZoom:3,
 style:[
  {selector:'node',style:{'background-color':'data(colour)','shape':'data(shape)','width':'data(size)','height':'data(size)','label':'data(label)',
   'color':'#e5e7eb','font-size':10,'text-valign':'bottom','text-margin-y':5,'text-outline-color':'#0b1220','text-outline-width':2,'border-width':1.5,'border-color':'#0b1220'}},
  {selector:'node[?suspected]',style:{'border-color':'#ef4444','border-width':4}},
  {selector:'node[?onPath]',style:{'border-color':'#22d3ee','border-width':5}},
  {selector:'edge',style:{'width':1.6,'line-color':'#475569','target-arrow-color':'#475569','target-arrow-shape':'triangle','curve-style':'bezier','arrow-scale':0.8,'opacity':0.85}},
  {selector:'edge[kind="lateral"]',style:{'line-color':'#f59e0b','target-arrow-color':'#f59e0b','width':2.6}},
  {selector:'edge[kind="acted_on"]',style:{'line-color':'#a78bfa','target-arrow-color':'#a78bfa','width':2.2}},
  {selector:'edge[kind="outbound"],edge[kind="contacted"]',style:{'line-color':'#f87171','target-arrow-color':'#f87171'}},
  {selector:'edge[kind="inbound"]',style:{'line-color':'#fb7185','target-arrow-color':'#fb7185'}},
  {selector:'edge[?hypothesis]',style:{'line-style':'dashed','opacity':0.55}},
  {selector:'edge[?onPath]',style:{'line-color':'#22d3ee','target-arrow-color':'#22d3ee','width':4,'opacity':1}},
  {selector:'.faded',style:{'opacity':0.08,'text-opacity':0}},
  {selector:'.hit',style:{'border-color':'#facc15','border-width':5}},
  {selector:'edge.focus',style:{'label':'data(label)','font-size':9,'color':'#cbd5e1','text-rotation':'autorotate','text-background-color':'#0b1220','text-background-opacity':0.9,'text-background-padding':2,'width':3,'opacity':1}},
  {selector:'node:selected',style:{'border-color':'#3b82f6','border-width':5}}],
 layout:{name:'cose',animate:false,nodeRepulsion:9000,idealEdgeLength:90,padding:30}});
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const side=document.getElementById('side'),tip=document.getElementById('tip');
function overview(){const kinds={};cy.nodes(':visible').forEach(n=>{kinds[n.data('kindName')]=(kinds[n.data('kindName')]||0)+1});
 const top=cy.nodes(':visible').sort((a,b)=>b.data('degree')-a.data('degree')).slice(0,8);
 side.innerHTML=`<h3>Incident graph</h3><div class="muted">${cy.nodes(':visible').length} entities · ${cy.edges(':visible').length} relationships</div>
 <div class="kv">${Object.entries(kinds).map(([k,v])=>`<span class="muted">${esc(k)}</span><span>${v}</span>`).join('')}</div>
 <div class="grp"><h4>Most connected</h4>${top.map(n=>`<div class="conn" data-id="${esc(n.id())}"><b>${esc(n.data('full'))}</b>
 <div class="muted">${esc(n.data('kindName'))} · ${n.data('degree')} links ${n.data('suspected')?'· <span class="sus">suspected</span>':''}</div></div>`).join('')}</div>
 <p class="muted">Click any user, host or IP to see who it connects to. Red outline = suspected compromised; dashed = hypothesis.</p>`;bindConn();}
function bindConn(){side.querySelectorAll('.conn').forEach(el=>el.onclick=()=>focus(cy.getElementById(el.dataset.id)))}
function focus(n){if(!n||!n.length)return;cy.elements().removeClass('faded focus');const hood=n.closedNeighborhood();
 cy.elements().not(hood).addClass('faded');if(hood.edges().length<=6)hood.edges().addClass('focus');cy.animate({fit:{eles:hood,padding:60}},{duration:350});
 const groups={};n.connectedEdges(':visible').forEach(e=>{const out=e.source().id()===n.id(),o=out?e.target():e.source();
  (groups[o.data('group')]=groups[o.data('group')]||[]).push({o,e,out})});
 side.innerHTML=`<h3>${esc(n.data('full'))}</h3><div class="muted">${esc(n.data('kindName'))}${n.data('role')?' · '+esc(n.data('role')):''}
 ${n.data('suspected')?' · <span class="sus">suspected compromised</span>':''}</div>
 <div class="kv"><span class="muted">Connections</span><span>${n.connectedEdges(':visible').length}</span><span class="muted">Neighbours</span><span>${n.neighborhood('node:visible').length}</span></div>
 ${Object.entries(groups).map(([g,list])=>`<div class="grp"><h4>${esc(g)} (${list.length})</h4>${list.map(({o,e,out})=>`
 <div class="conn" data-id="${esc(o.id())}"><b>${out?'→':'←'} ${esc(o.data('full'))}</b><div class="muted">${esc(e.data('label'))}${e.data('hypothesis')?' · hypothesis':''}${e.data('events')?' · '+e.data('events')+(e.data('events')===1?' event':' events'):''}</div>
 ${e.data('techniques').map(t=>`<span class="tag">${esc(t)}</span>`).join('')}${e.data('steps').length?`<span class="tag">step ${esc(e.data('steps').join(', '))}</span>`:''}
 ${e.data('first')?`<div class="muted" style="font-size:11px">${esc(e.data('first'))}${e.data('last')&&e.data('last')!==e.data('first')?' → '+esc(e.data('last')):''}</div>`:''}
 ${e.data('via')?`<div class="muted" style="font-size:11px">via ${esc(e.data('via'))}</div>`:''}</div>`).join('')}</div>`).join('')}
 <p><button id="back">← Back to overview</button></p>`;bindConn();document.getElementById('back').onclick=reset;}
function reset(){cy.elements().removeClass('faded focus hit');cy.animate({fit:{eles:cy.elements(':visible'),padding:30}},{duration:300});overview()}
cy.on('tap','node',e=>focus(e.target));cy.on('tap',e=>{if(e.target===cy)reset()});
cy.on('tap','edge',e=>{const d=e.target.data();cy.elements().removeClass('faded focus');cy.elements().not(e.target.connectedNodes().union(e.target)).addClass('faded');e.target.addClass('focus');
 side.innerHTML=`<h3>${esc(e.target.source().data('full'))} → ${esc(e.target.target().data('full'))}</h3><div class="muted">${esc(d.label)}${d.hypothesis?' · hypothesis, not observed':''}</div>
 <div class="kv"><span class="muted">Techniques</span><span>${esc(d.techniques.join(', ')||'—')}</span><span class="muted">Steps</span><span>${esc(d.steps.join(', ')||'—')}</span>
 <span class="muted">Events</span><span>${d.events}</span><span class="muted">First seen</span><span>${esc(d.first||'—')}</span><span class="muted">Last seen</span><span>${esc(d.last||'—')}</span></div>
 <p><button id="back">← Back to overview</button></p>`;document.getElementById('back').onclick=reset});
cy.on('mouseover','node,edge',e=>{const d=e.target.data();tip.innerHTML=e.target.isNode()?`<b>${esc(d.full)}</b><br><span class="muted">${esc(d.kindName)} · ${d.degree} links</span>`
 :`<b>${esc(d.label)}</b><br><span class="muted">${esc(d.techniques.join(', '))}</span>`;tip.style.display='block'});
cy.on('mouseout','node,edge',()=>tip.style.display='none');
document.addEventListener('mousemove',e=>{tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY+14)+'px'});
document.getElementById('legend').innerHTML=Object.entries(legend).map(([k,c])=>`<span><span class="dot" style="background:${c}"></span> ${esc(k)}</span>`).join('')+
 '<span><span class="dot" style="background:#ef4444"></span> suspected</span><span style="color:#f59e0b">━ lateral</span><span style="color:#a78bfa">━ logon</span><span style="color:#f87171">━ network</span><span>┅ hypothesis</span>';
const hidden=new Set();const chips=document.getElementById('chips');
Object.entries(legend).forEach(([k,c])=>{const el=document.createElement('span');el.className='chip on';el.innerHTML=`<span class="dot" style="background:${c}"></span>${esc(k)}`;
 el.onclick=()=>{hidden.has(k)?hidden.delete(k):hidden.add(k);el.classList.toggle('on');apply()};chips.appendChild(el)});
const hyp=document.querySelector('#hyp input');hyp.onchange=()=>{document.getElementById('hyp').classList.toggle('on',hyp.checked);apply()};
function apply(){cy.batch(()=>{cy.nodes().forEach(n=>n.style('display',hidden.has(n.data('kindName'))?'none':'element'));
 cy.edges().forEach(e=>e.style('display',(!hyp.checked&&e.data('hypothesis'))?'none':'element'))});overview()}
document.getElementById('layout').onchange=e=>cy.layout({name:e.target.value,animate:true,animationDuration:400,padding:30,
 nodeRepulsion:9000,idealEdgeLength:90,concentric:n=>n.data('degree'),levelWidth:()=>2,directed:true,spacingFactor:1.1}).run();
document.getElementById('fit').onclick=reset;
document.getElementById('q').oninput=e=>{const q=e.target.value.trim().toLowerCase();cy.nodes().removeClass('hit');
 if(!q)return;const m=cy.nodes(':visible').filter(n=>n.data('full').toLowerCase().includes(q));m.addClass('hit');if(m.length===1)focus(m);else if(m.length)cy.animate({fit:{eles:m,padding:80}})};
document.getElementById('png').onclick=()=>{const a=document.createElement('a');a.href=cy.png({full:true,scale:2,bg:'#0b1220'});a.download='trace-incident-graph.png';a.click()};
const onPath=cy.nodes('[?onPath]');if(onPath.length){cy.elements().not(onPath.union(cy.edges('[?onPath]'))).addClass('faded');cy.fit(onPath,60)}
overview();
</script></body></html>"""
