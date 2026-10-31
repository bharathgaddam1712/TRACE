'use strict';
const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let current = null, cy = null, selectionVersion = 0, aiStatus = {}, loadVersion = 0, graphOverride = null;
let token = sessionStorage.getItem('trace-token') || '';
$('#api-token').value = token;
async function api(url, options = {}) {
  const response = await fetch(url, {...options, headers: {...(options.body ? {'Content-Type':'application/json'} : {}), ...(token ? {'Authorization':'Bearer ' + token} : {}), ...(options.headers || {})}});
  if (!response.ok) { const error = await response.json().catch(() => ({})); throw new Error(typeof error.detail === 'string' ? error.detail : `Request failed (${response.status})`); }
  return response.json();
}
function eventButtons(ids) { return [...new Set(ids || [])].slice(0,30).map(id => `<button class="event-button" data-event="${esc(id)}">${esc(id)}</button>`).join(''); }
function bindEvidence(root) { root.querySelectorAll('[data-event]').forEach(button => button.addEventListener('click', event => {event.stopPropagation(); showEvidence(button.dataset.event);})); }
async function showEvidence(id) {
  $('#evidence-content').textContent = 'Loading evidence…'; $('#evidence-dialog').showModal();
  try { $('#evidence-content').textContent = JSON.stringify(await api(`/incidents/${current.id}/evidence/${encodeURIComponent(id)}`), null, 2); }
  catch (error) { $('#evidence-content').textContent = error.message; }
}
async function refresh() {
  const version = ++loadVersion;
  try {
    const query = new URLSearchParams({q:$('#search').value, min_score:$('#min-score').value || '0', status:$('#status-filter').value, limit:'1000'});
    const [rows, health, progress, metrics, ai] = await Promise.all([api('/incidents?' + query), api('/health'), api('/progress'), api('/metrics'), api('/ai/status')]);
    if (version !== loadVersion) return;
    aiStatus = ai;
    $('#health').textContent = `${health.incidents} incidents · ${ai.enabled ? 'Sarvam ready' : 'Local mode'}`;
    $('#progress').textContent = `Pipeline: ${progress.state} · ${progress.stage}`;
    const quality = metrics.ingest || {};
    $('#quality').textContent = quality.events === undefined ? 'No completed run yet' : `${quality.events.toLocaleString()} events · ${quality.quarantined_rows} quarantined · ${(quality.adapter_rejected_records || 0) + (quality.reader_rejected_records || 0)} rejected input line fragments · ${quality.reused_files || 0} cached files`;
    $('#list').innerHTML = rows.map(row => `<button class="incident ${current?.id === row.id ? 'selected':''}" data-id="${row.id}"><strong>${esc(row.score)}/100</strong> · ${esc(row.status)}<div>${esc(row.title)}</div><small>${row.signal_count} steps · ${row.merged_alert_count} merged alerts</small><small>${esc(row.first_seen)}</small></button>`).join('') || '<p class="muted">No incidents match these filters. Isolated detections remain available in Findings.</p>';
    $('#load-more').hidden=rows.length<1000;
    $('#list').querySelectorAll('[data-id]').forEach(button => button.addEventListener('click', () => showIncident(Number(button.dataset.id))));
    if (!current && rows.length) await showIncident(rows[0].id);
  } catch (error) { $('#health').textContent = error.message; $('#health').className = 'error'; }
}
async function showIncident(id) {
  const version = ++selectionVersion;
  $('#workspace').innerHTML = '<p class="loading">Loading investigation…</p>';
  try {
    const incident = await api(`/incidents/${id}`);
    if (version !== selectionVersion) return;
    current = incident; graphOverride = null;
    if (cy) { cy.destroy(); cy = null; }
    render();
    $('#list').querySelectorAll('[data-id]').forEach(button => button.classList.toggle('selected', Number(button.dataset.id) === id));
  } catch (error) { if (version === selectionVersion) $('#workspace').innerHTML = `<p class="error">${esc(error.message)}</p>`; }
}
function render() {
  const inc = current;
  $('#workspace').innerHTML = `<div class="summary"><div><h2>${esc(inc.title)}</h2><p class="muted">${esc(inc.first_seen)} — ${esc(inc.last_seen)}</p><div class="chips">${inc.tactics.map(t => `<span class="chip">${esc(t)}</span>`).join('')}</div></div><div class="risk">${inc.score}<small> / 100</small></div></div>
    <p>${esc(inc.host_path_text)} · ${inc.signal_count} steps · ${inc.merged_alert_count} alerts</p>
    <p class="muted">Risk is a heuristic priority score. Correlation indicates association; each link retains its evidence.</p>
    <nav class="tabs" aria-label="Investigation views">${['timeline','graph','predict','assistant','case','report','findings','coverage'].map(name => `<button data-tab="${name}" ${name === 'timeline' ? 'class="active"':''}>${name[0].toUpperCase()+name.slice(1)}</button>`).join('')}</nav>
    <section class="tab-panel" id="panel-timeline"><h3>Evidence timeline</h3><div class="scroll"><table><thead><tr><th>Step / time</th><th>Behavior / ATT&CK</th><th>Host / account</th><th>Connection</th><th>Evidence</th></tr></thead><tbody>${inc.timeline.map(step => `<tr class="step-row" data-step="${step.step}"><td>${step.step}<br>${esc(step.ts)}</td><td>${esc(step.title)}<br><small>${esc((step.technique_ids || [step.technique]).filter(Boolean).join(', '))} · ${esc(step.tactic || 'Unmapped')}</small><details><summary>Why mapped</summary>${esc(step.mapping_reason || step.mapping_source)}</details></td><td>${esc(step.host)}<br><small>${esc(step.user || 'Unknown account')}</small></td><td>${step.link ? `<span class="kind">${esc(step.link.kind)}</span> from step ${step.link.from_step}<br><small>${esc(step.link.reasons.join('; '))}</small>` : 'No earlier correlation edge'}<details><summary>${(step.links || []).length} correlation links</summary>${(step.links || []).map(link=>`<p>From step ${link.from_step}: ${esc(link.relation)} · ${esc(link.kind)} · similarity ${esc(link.similarity)}<br>${esc(link.reasons.join('; '))}</p>`).join('')}</details><br><small>${step.merged_detections} detections merged</small></td><td><details><summary>${step.event_ids.length} event references</summary>${eventButtons(step.event_ids)}<pre>${esc(JSON.stringify(step.evidence, null, 2))}</pre></details></td></tr>`).join('')}</tbody></table></div></section>
    <section class="tab-panel" id="panel-graph" hidden><h3>Entity and event graph</h3><div class="graph-toolbar"><label>Graph view<select id="graph-mode"><option value="entities">Entities and every correlation link</option><option value="related">Related incidents</option></select></label><label>Entity type<select id="entity-type"><option value="">All types</option>${['host','user','external','process','event','file','domain','registry'].map(t=>`<option>${t}</option>`).join('')}</select></label><label>From step<select id="from-step"><option value="">Beginning</option>${inc.timeline.map(s=>`<option value="${s.step}">${s.step}</option>`).join('')}</select></label><label>Through step<select id="to-step"><option value="">End</option>${inc.timeline.map(s=>`<option value="${s.step}">${s.step}</option>`).join('')}</select></label><button id="fit-graph">Fit graph</button></div><div class="graph-toolbar"><label>Focus entity<select id="focus-entity"><option value="">Choose an entity</option>${inc.graph.nodes.map(n=>`<option value="${esc(n.id)}">${esc(n.label.slice(0,60))}</option>`).join('')}</select></label><label>Search depth<input id="graph-depth" type="number" min="1" max="6" value="2"></label><button id="expand-neighborhood">Show neighborhood</button><button id="reset-graph">Show all links</button></div><details><summary>Weighted shortest-path search</summary><div class="graph-toolbar"><label>Source<select id="path-source">${inc.graph.nodes.map(n=>`<option value="${esc(n.id)}">${esc(n.label.slice(0,60))}</option>`).join('')}</select></label><label>Target<select id="path-target">${inc.graph.nodes.map(n=>`<option value="${esc(n.id)}">${esc(n.label.slice(0,60))}</option>`).join('')}</select></label><button id="find-path">Find path</button></div><p class="muted">Dijkstra minimizes configured evidence cost within the depth limit. It does not establish that an attacker followed the path.</p></details><pre id="graph-search-result" hidden></pre><div class="legend">Click a node or edge for evidence. Dashed edges show possible access. Predicted access does not establish compromise.</div><div class="graph-wrap"><div id="graph" aria-label="Interactive attack graph"></div><div id="graph-detail">Select a graph element.</div></div></section>
    <section class="tab-panel" id="panel-predict" hidden><h3>Possible next targets</h3><p class="notice">Access hypotheses using observations available by the incident's end. Confidence describes evidence strength, not attack probability.</p>${inc.lookahead.reachable.length ? `<div class="scroll"><table><tr><th>Asset</th><th>Access relation</th><th>Via</th><th>Strength</th><th>Evidence</th></tr>${inc.lookahead.reachable.map(item=>`<tr><td>${esc(item.asset)}</td><td>${esc(item.relation)}</td><td>${esc(item.via)}</td><td>${esc(item.confidence)}</td><td>${eventButtons(item.evidence.event_ids || [item.evidence.sample_event_id])}</td></tr>`).join('')}</table></div>`:'<p>Unknown: no eligible access evidence identifies a next target.</p>'}<div id="forecast-comparison"></div><h3>Next-technique estimate</h3><pre>${esc(JSON.stringify(inc.forecast || {status:'unavailable'},null,2))}</pre><ul>${inc.lookahead.assumptions.map(a=>`<li>${esc(a)}</li>`).join('')}</ul></section>
    <section class="tab-panel" id="panel-assistant" hidden><h3>Sarvam investigation assistant</h3><p id="ai-meta" class="muted">${aiStatus.enabled ? esc(aiStatus.model) + ' · ' + aiStatus.requests_today + ' requests reserved today' : 'Add SARVAM_API_KEY to the repository-root .env file, then restart the API.'}</p><p>Only a bounded, credential-redacted incident context is sent to Sarvam when you click Ask. Suggestions remain advisory.</p><div class="ai-controls"><label>Task<select id="ai-task"><option value="summary">Explain this incident</option><option value="chat">Ask about the evidence</option><option value="investigate">Suggest investigation checks</option><option value="map">Suggest ATT&CK mappings</option><option value="rule">Draft a Sigma rule</option><option value="translate">Multilingual incident report</option></select></label><label>Language<select id="ai-language">${['English','Hindi','Telugu','Tamil','Kannada','Malayalam','Marathi','Bengali','Gujarati','Punjabi','Odia'].map(l=>`<option>${l}</option>`).join('')}</select></label></div><label>Question<textarea id="ai-question" rows="3" maxlength="2000" placeholder="Why were these events linked? What evidence should we inspect next?"></textarea></label><button class="primary" id="ask-ai" ${aiStatus.enabled ? '':'disabled'}>Ask Sarvam</button><div id="ai-response" aria-live="polite"></div></section>
    <section class="tab-panel" id="panel-case" hidden><h3>Analyst case</h3><div class="case-grid"><div><label>Status<select id="case-status">${['new','investigating','contained','closed'].map(status=>`<option ${inc.case.status === status ? 'selected':''}>${status}</option>`).join('')}</select></label><label>Investigation note<textarea id="case-note" maxlength="10000" rows="6"></textarea></label><button id="save-case" class="primary">Save update</button><p id="case-message" role="status"></p></div><div id="case-history">${caseHistory()}</div></div></section>
    <section class="tab-panel" id="panel-report" hidden><h3>Evidence-based report</h3><div class="actions"><button id="download-report">Download report</button><button id="download-json">Download incident JSON</button></div><pre>${esc(inc.narrative)}</pre><p class="muted">Rule authors: ${esc(inc.attribution.join(', '))}</p></section>
    <section class="tab-panel" id="panel-coverage" hidden><h3>Detection and mapping coverage</h3><div id="coverage-content"></div></section><section class="tab-panel" id="panel-findings" hidden><h3>Isolated findings</h3><p>Detections that were not promoted into an incident remain available here.</p><div id="findings-content"></div></section>`;
  document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => switchTab(button.dataset.tab)));
  bindEvidence($('#workspace'));
  document.querySelectorAll('.step-row').forEach(row => row.addEventListener('click', event => { if (event.target.closest('details')) return; switchTab('graph'); highlightStep(Number(row.dataset.step)); }));
  ['#entity-type','#from-step','#to-step'].forEach(selector => $(selector).addEventListener('change', drawGraph));
  $('#fit-graph').addEventListener('click', () => cy?.fit(undefined, 35));
  $('#graph-mode').addEventListener('change', loadGraphMode);
  $('#expand-neighborhood').addEventListener('click', expandNeighborhood);
  $('#find-path').addEventListener('click', findPath);
  $('#reset-graph').addEventListener('click',()=>{graphOverride=null;$('#graph-mode').value='entities';drawGraph();});
  $('#ask-ai').addEventListener('click', askAI);
  $('#save-case').addEventListener('click', saveCase);
  $('#download-report').addEventListener('click', () => download(`trace-incident-${inc.id}.txt`, inc.narrative, 'text/plain'));
  $('#download-json').addEventListener('click', () => download(`trace-incident-${inc.id}.json`, JSON.stringify(inc,null,2), 'application/json'));
}
function switchTab(name) {
  document.querySelectorAll('[data-tab]').forEach(button => button.classList.toggle('active', button.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.hidden = panel.id !== 'panel-' + name);
  if (name === 'graph') { if (!cy) drawGraph(); else {cy.resize(); cy.fit(undefined,35);} }
  if (name === 'findings') loadFindings();
  if (name === 'coverage') loadCoverage();
  if (name === 'predict') {renderSequenceForecast();loadForecastComparison();loadTemporalComparison();}
}
function renderSequenceForecast() {
  let panel=$('#sequence-forecast');
  if(!panel){panel=document.createElement('div');panel.id='sequence-forecast';$('#panel-predict').prepend(panel);}
  const forecast=current.forecast || {}, sequences=forecast.sequences || [];
  panel.innerHTML=`<h3>Hypothetical next technique sequences</h3><p class="notice">${esc(forecast.interpretation || forecast.reason || 'No historical model configured.')}</p>${(forecast.evaluation_warnings || []).map(w=>`<p class="notice">${esc(w)}</p>`).join('')}${sequences.length?`<p>Model: ${esc(forecast.method)} · Label source: ${esc(forecast.label_source)}</p><ol>${sequences.map(path=>`<li><div class="chips">${path.techniques.map(t=>`<span class="chip">${esc(t)}</span>`).join('<span aria-label="then">→</span>')}</div><small>Empirical model path score: ${Number(path.model_path_score).toFixed(3)}; not attack probability.</small><details><summary>Support and backoff for each step</summary><pre>${esc(JSON.stringify(path.steps,null,2))}</pre></details></li>`).join('')}</ol>`:'<p>No supported sequence is available for this incident.</p>'}`;
}
function drawGraph() {
  if (!window.cytoscape) { $('#graph').textContent = 'Graph library unavailable. Use the timeline and report.'; return; }
  if (cy) cy.destroy();
  const type = $('#entity-type').value, from = Number($('#from-step').value || 0), to = Number($('#to-step').value || Infinity);
  const graphData=graphOverride || current.graph;
  const nodes = graphData.nodes.filter(n=>!type || n.type === type || n.type === 'host');
  const ids = new Set(nodes.map(n=>n.id));
  const edges = graphData.edges.filter(e=>ids.has(e.source) && ids.has(e.target) && ((!from && to === Infinity) || (e.steps || []).some(s=>s>=from && s<=to)));
  const used = new Set(edges.flatMap(e=>[e.source,e.target]));
  const colors = {host:'#63b6fa',user:'#65ddd0',external:'#ff929c',process:'#c4a6ff',event:'#ffc77a',file:'#d4d7e0',domain:'#f3a7cf',registry:'#a8bdc9',incident:'#bda9ff'};
  cy = cytoscape({container:$('#graph'),elements:[...nodes.filter(n=>!edges.length || used.has(n.id)).map(n=>({data:{...n,color:n.potential?'#7d8c9d':colors[n.type],label:n.label.length>55?n.label.slice(0,52)+'…':n.label}})),...edges.map((e,i)=>({data:{...e,id:e.id || 'edge:'+i,label:e.relation || e.kind}}))],style:[{selector:'node',style:{'background-color':'data(color)',label:'data(label)',color:'#dbe5ef','font-size':10,'text-wrap':'wrap','text-max-width':140}},{selector:'edge',style:{'curve-style':'bezier','target-arrow-shape':'triangle','line-color':'#5b718b','target-arrow-color':'#5b718b',width:1.4,label:'data(label)',color:'#95aac1','font-size':8}},{selector:'edge[kind="could_reach"]',style:{'line-style':'dashed'}},{selector:'edge[evidence_kind="inferred"]',style:{'line-style':'dotted','line-color':'#bc9ae8'}},{selector:'.highlight',style:{'border-width':4,'border-color':'#ffffff','line-color':'#ffffff','target-arrow-color':'#ffffff',width:3}}],layout:{name:'breadthfirst',directed:true,spacingFactor:1.2}});
  cy.on('tap','node, edge',event=>{const data=event.target.data();$('#graph-detail').innerHTML=`<h3>${esc(data.label || data.kind)}</h3>${data.incident_id ? `<button id="open-related">Open incident ${data.incident_id}</button>` : ''}${eventButtons(data.event_ids)}<pre>${esc(JSON.stringify(data,null,2))}</pre>`;bindEvidence($('#graph-detail'));if($('#open-related'))$('#open-related').addEventListener('click',()=>showIncident(data.incident_id));const selected=new Set(data.steps || []);document.querySelectorAll('[data-step]').forEach(row=>row.classList.toggle('selected',selected.has(Number(row.dataset.step))));});
}
function highlightStep(step) { cy?.elements().removeClass('highlight');cy?.elements().filter(el=>(el.data('steps') || []).includes(step)).addClass('highlight'); }
function caseHistory() { return current.case.history.length ? current.case.history.map(item=>`<div class="history-item"><strong>${esc(item.status)}</strong> <small>${esc(item.ts)}</small><pre>${esc(item.note || 'Status update')}</pre></div>`).join(''):'<p class="muted">No analyst updates yet.</p>'; }
async function saveCase() {
  const inc = current, id = inc.id; $('#save-case').disabled=true;
  try { const result=await api(`/incidents/${id}/case`,{method:'POST',body:JSON.stringify({status:$('#case-status').value,note:$('#case-note').value,version:inc.case.version})});if(current!==inc)return;current.case=result;$('#case-history').innerHTML=caseHistory();$('#case-note').value='';$('#case-message').textContent='Saved.';refresh(); }
  catch(error){if(current===inc)$('#case-message').textContent=error.message;}
  finally{if(current===inc)$('#save-case').disabled=false;}
}
async function askAI() {
  const inc=current, button=$('#ask-ai');button.disabled=true;$('#ai-response').textContent='Analyzing the supplied evidence…';
  try { const result=await api(`/incidents/${inc.id}/ai`,{method:'POST',body:JSON.stringify({task:$('#ai-task').value,question:$('#ai-question').value,language:$('#ai-language').value})});if(current!==inc)return;$('#ai-response').innerHTML=`<p class="muted">${esc(result.model)} · ${result.cached?'cached response':'new response'} · Advisory</p><pre>${esc(result.answer)}</pre><h3>Supporting events</h3>${eventButtons(result.citations)}${result.hypotheses.length?'<h3>Hypotheses</h3><ul>'+result.hypotheses.map(h=>`<li>${esc(h)}</li>`).join('')+'</ul>':''}${result.next_checks.length?'<h3>Next checks</h3><ul>'+result.next_checks.map(h=>`<li>${esc(h)}</li>`).join('')+'</ul>':''}${result.suggested_mappings.length?'<h3>Mapping suggestions</h3><pre>'+esc(JSON.stringify(result.suggested_mappings,null,2))+'</pre>':''}${result.sigma_yaml?'<h3>Sigma draft · compiler validated · not enabled</h3><pre>'+esc(result.sigma_yaml)+'</pre>':''}`;bindEvidence($('#ai-response')); }
  catch(error){if(current===inc)$('#ai-response').textContent=error.message;}
  finally{if(current===inc)button.disabled=false;}
}
async function loadFindings() { try{const findings=await api('/findings?limit=100');$('#findings-content').innerHTML=`<p>${findings.total_isolated_signals || 0} isolated signals; showing up to 100.</p><div class="scroll"><table><tr><th>Time</th><th>Detection</th><th>Host</th><th>Technique</th></tr>${(findings.findings || []).map(f=>`<tr><td>${esc(f.ts)}</td><td>${esc(f.title)}</td><td>${esc(f.host)}</td><td>${esc(f.technique || 'Unmapped')}</td></tr>`).join('')}</table></div>`;}catch(error){if($('#findings-content'))$('#findings-content').textContent=error.message;} }
function download(name,text,type) { const url=URL.createObjectURL(new Blob([text],{type:type+';charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000); }
$('#close-evidence').addEventListener('click',()=>$('#evidence-dialog').close());
$('#load-more').addEventListener('click',loadMoreIncidents);
$('#refresh').addEventListener('click',()=>{current=null;refresh();});
$('#connect').addEventListener('click',()=>{token=$('#api-token').value.trim();sessionStorage.setItem('trace-token',token);current=null;refresh();});
let debounce;$('#search').addEventListener('input',()=>{clearTimeout(debounce);debounce=setTimeout(refresh,250);});
$('#min-score').addEventListener('change',refresh);$('#status-filter').addEventListener('change',refresh);
refresh();
setInterval(async()=>{try{const progress=await api('/progress');$('#progress').textContent=`Pipeline: ${progress.state} · ${progress.stage}`;}catch{}},5000);
async function loadGraphMode() {
  const inc=current;
  try {graphOverride=$('#graph-mode').value==='related' ? (await api('/relationships?'+new URLSearchParams({incident_id:inc.id,depth:$('#graph-depth').value || '2'}))).graph : null;if(current!==inc)return;$('#from-step').value='';$('#to-step').value='';$('#entity-type').value='';drawGraph();}
  catch(error){$('#graph-detail').textContent=error.message;}
}
async function expandNeighborhood() {
  const inc=current, depth=$('#graph-depth').value || '2';
  try {
    if($('#graph-mode').value==='related'){await loadGraphMode();return;}
    const entity=$('#focus-entity').value;if(!entity){$('#graph-detail').textContent='Choose a focus entity first.';return;}
    const result=await api(`/incidents/${inc.id}/neighborhood?`+new URLSearchParams({entity,depth}));
    if(current!==inc)return;graphOverride=result;drawGraph();$('#graph-detail').textContent=result.truncated?'Neighborhood is capped. Reduce depth to inspect all returned links.':`Showing depth ${depth}; ${result.nodes.length} nodes, ${result.edges.length} edges.`;
  }catch(error){if(current===inc)$('#graph-detail').textContent=error.message;}
}
async function findPath() {
  const inc=current;
  try {
    const result=await api(`/incidents/${inc.id}/shortest-path?`+new URLSearchParams({source:$('#path-source').value,target:$('#path-target').value,depth:$('#graph-depth').value || '6'}));
    if(current!==inc)return;graphOverride=null;$('#graph-mode').value='entities';$('#from-step').value='';$('#to-step').value='';$('#entity-type').value='';drawGraph();
    const ids=new Set([...(result.nodes || []),...(result.edge_ids || [])]);cy?.elements().filter(element=>ids.has(element.id())).addClass('highlight');
    $('#graph-search-result').hidden=false;$('#graph-search-result').textContent=JSON.stringify(result,null,2);
  }catch(error){if(current===inc){$('#graph-search-result').hidden=false;$('#graph-search-result').textContent=error.message;}}
}
async function loadCoverage() {
  try {const data=await api('/coverage');if(!$('#coverage-content'))return;const pack=data.rules.community || {};$('#coverage-content').innerHTML=`<p class="notice">${esc(data.note)}</p><div class="scroll"><table><tr><th>Measure</th><th>Value</th></tr><tr><td>Rules loaded</td><td>${data.rules.loaded || 0}</td></tr><tr><td>Applicable base rules evaluated on this input</td><td>${data.detection.base_rules_evaluated ?? 'Re-run to measure'}</td></tr><tr><td>Active ATT&CK catalog techniques</td><td>${data.catalog_techniques}</td></tr><tr><td>Techniques tagged by enabled rules</td><td>${(data.rules.covered_techniques || []).length}</td></tr><tr><td>SigmaHQ compiler-compatible rules</td><td>${pack.enabled || 0}</td></tr><tr><td>SigmaHQ unsupported rules</td><td>${pack.unsupported || 0}</td></tr><tr><td>SigmaHQ statuses excluded</td><td>${pack.excluded_status || 0}</td></tr></table></div><h3>Mapping provenance</h3><pre>${esc(JSON.stringify(data.mapping,null,2))}</pre><p>Every timeline step includes its mapping reason. Unsupported rule details and original authors are recorded in rules/community/manifest.json.</p>`;}catch(error){if($('#coverage-content'))$('#coverage-content').textContent=error.message;}
}
async function loadForecastComparison() {
  try{const data=await api('/forecast/benchmark');if(!$('#forecast-comparison'))return;if(!data.test){$('#forecast-comparison').textContent=data.reason || 'No model comparison yet.';return;}$('#forecast-comparison').innerHTML=`<h3>Chronological model comparison</h3><p class="notice">Label source: ${esc(data.label_source)}. ${esc(data.interpretation)}</p><p>Selected using validation: ${esc(data.selected_on_validation)}</p><table><tr><th>Model</th><th>Test top-1</th><th>Top-3</th><th>MRR</th></tr>${Object.entries(data.test).map(([name,result])=>`<tr><td>${esc(name)}</td><td><progress max="1" value="${result.top1 || 0}"></progress> ${((result.top1 || 0)*100).toFixed(1)}%</td><td>${((result.top3 || 0)*100).toFixed(1)}%</td><td>${Number(result.mrr || 0).toFixed(3)}</td></tr>`).join('')}</table>${data.sarvam?'<h3>Sarvam held-out comparison</h3><pre>'+esc(JSON.stringify(data.sarvam,null,2))+'</pre>':''}`;}catch(error){if($('#forecast-comparison'))$('#forecast-comparison').textContent=error.message;}
}
async function loadTemporalComparison() {
  let panel = $('#temporal-comparison');
  if (!panel) {panel=document.createElement('div');panel.id='temporal-comparison';$('#panel-predict').append(panel);}
  try {
    const data=await api('/temporal/benchmark');
    if (!panel.isConnected) return;
    if (!data.test) {panel.textContent=data.reason;return;}
    panel.innerHTML=`<h3>Temporal network interaction experiment</h3><p class="notice">These scores measure observed network interactions against sampled alternatives. They are not attack detection or attack-success accuracy.</p><p>Selected on validation: ${esc(data.selected_on_validation)}. ${esc(data.events)} chronological interactions.</p><table><tr><th>Model</th><th>Test MRR</th><th>Hits@1</th><th>Hits@3</th></tr>${Object.entries(data.test).map(([name,result])=>`<tr><td>${esc(name)}</td><td>${Number(result.mrr ?? 0).toFixed(3)}</td><td>${Number(result.hits1 ?? 0).toFixed(3)}</td><td>${Number(result.hits3 ?? 0).toFixed(3)}</td></tr>`).join('')}</table><details><summary>Evaluation protocol and limitations</summary><pre>${esc(JSON.stringify({protocol:data.protocol,negative_sampling:data.negative_sampling,cold_pair_test:data.cold_pair_test,limitations:data.limitations},null,2))}</pre></details>`;
  } catch(error) {panel.textContent=error.message;}
}
async function loadMoreIncidents() {
  const version=loadVersion;$('#load-more').disabled=true;
  try{const offset=$('#list').querySelectorAll('[data-id]').length;const query=new URLSearchParams({q:$('#search').value,min_score:$('#min-score').value || '0',status:$('#status-filter').value,limit:'1000',offset:String(offset)});const rows=await api('/incidents?'+query);if(version!==loadVersion)return;for(const row of rows){const button=document.createElement('button');button.className='incident';button.dataset.id=row.id;button.innerHTML=`<strong>${esc(row.score)}/100</strong> · ${esc(row.status)}<div>${esc(row.title)}</div><small>${row.signal_count} steps · ${row.merged_alert_count} alerts</small>`;button.addEventListener('click',()=>showIncident(row.id));$('#list').append(button);}$('#load-more').hidden=rows.length<1000;}
  catch(error){$('#health').textContent=error.message;}finally{$('#load-more').disabled=false;}
}
