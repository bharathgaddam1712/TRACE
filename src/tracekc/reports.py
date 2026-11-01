"""Portable Markdown handoffs assembled from validated results, without model calls."""
import html
import re

from tracekc.timeutil import timestamp


def _text(value):
    """Treat source/model fields as text, never as report structure or HTML."""
    value=html.escape(str(value if value is not None else 'Not recorded'),quote=False)
    return re.sub(r'([\\`*_{}\[\]#|!])',r'\\\1',value).replace('\r','').replace('\n',' ')


def _utc(value):
    if not value:return 'Not recorded'
    try:return timestamp(value).isoformat(timespec='milliseconds').replace('+00:00','Z')
    except (ValueError,TypeError):return _text(value)


def _prose(value):
    return '\n\n'.join(_text(paragraph) for paragraph in re.split(r'\n\s*\n',str(value).strip()))


def _table(rows):
    return ['| Field | Value |','|---|---|',*[f'| {_text(k)} | {_text(v)} |' for k,v in rows],'']


def _section(title,items,numbered=False,empty='None documented.'):
    lines=[f'## {title}','']
    lines.extend(f'{i+1 if numbered else "-"}{"." if numbered else ""} {_text(item)}'
                 for i,item in enumerate(items))
    if not items:lines.append(empty)
    return lines+['']


def _context(incident):
    entities=incident.get('entities',{})
    return _table([
        ('Incident',f'INC-{incident["id"]:04d}'),('Title',incident.get('title','Not recorded')),
        ('First observed',_utc(incident.get('first_seen'))),('Last observed',_utc(incident.get('last_seen'))),
        ('Hosts',', '.join(entities.get('hosts',[])) or 'No host identity recorded'),
        ('Accounts',', '.join(entities.get('users',[])) or 'No account identities recorded'),
        ('Priority score',f'{incident.get("score","Not recorded")} / 100 (heuristic, not probability)'),
        ('Observed steps',len(incident.get('timeline',[])))])


def _evidence(incident,event_ids):
    lookup={}
    for step in incident.get('timeline',[]):
        for event in step.get('event_ids',[]):lookup.setdefault(event,[]).append(step)
    lines=['## Supporting event references','',
           'Event identifiers are retained in full for lookup in the incident evidence or JSON export.','',
           '| Reference | Event ID | Step(s) | Referenced step time |',
           '|---|---|---|---|']
    for i,event in enumerate(dict.fromkeys(event_ids),1):
        steps=lookup.get(event,[])
        lines.append(f'| E{i:02d} | {_text(event)} | '
            f'{_text(", ".join(str(s["step"]) for s in steps) or "Access evidence")} | '
            f'{_utc(steps[0].get("ts")) if steps else "See cited access evidence"} |')
    if not event_ids:lines+=['| — | No event references supplied | — | — |']
    return lines+['']


def _reachability(incident):
    lookahead=incident.get('lookahead',{});candidates=lookahead.get('reachable',[])
    lines=['## Observed-access reachability','']
    if candidates:
        lines+=['These are possible access paths, not confirmed compromises or future actions.','',
                '| Asset | Relation | Evidence strength | Via |','|---|---|---|---|']
        lines += ['| '+' | '.join(_text(c.get(k,'Not recorded')) for k in ('asset','relation','confidence','via'))+' |'
                  for c in candidates]
    else:lines+=['No additional asset met the current access-evidence and time constraints. '
                 'This does not establish that no path exists.']
    return lines+['']


def triage_report(incident,result,reviews=()):
    verdict=result['verdict'];grounding=result.get('grounding',{})
    lines=['# TRACE AI Triage Report','',
           '> Advisory assessment for analyst review. No alert was automatically dismissed and no containment action was executed.','',
           '## Report details','']
    lines+=_table([('Incident',f'INC-{incident["id"]:04d}'),('Prepared',_utc(result.get('created_at'))),
        ('Provider / model',f'Sarvam / {result.get("model","Not recorded")}'),
        ('Workflow status',result.get('status','Not recorded').replace('_',' ')),
        ('Assessment',verdict['assessment'].replace('_',' ')),('Priority',verdict['priority']),('Severity',verdict['severity'])])
    lines+=['## Executive assessment','',_prose(verdict['rationale']),'','## Incident context','']+_context(incident)
    omitted=grounding.get('omitted_steps',0)
    lines+=['## Analysis coverage','',
        f'The model context omitted {omitted} of {len(incident.get("timeline",[]))} incident steps. '
        'The assessment is limited to the supplied evidence and must not be treated as a review of unseen records.','']
    lines+=_evidence(incident,verdict['citations'])
    lines+=_section('Contradicting observations',verdict['contradictory_evidence'])
    lines+=_section('Missing evidence and limitations',verdict['missing_evidence'])
    lines+=_section('Recommended investigation plan',verdict['next_checks'],numbered=True)
    lines+=_reachability(incident)
    lines+=_section('Analyst review record',[
        f'{_utc(r.get("ts"))} — {r["decision"].replace("_"," ")}: {r.get("note","")}' for r in reviews],
        empty='Analyst sign-off is pending. The model assessment is not a case disposition.')
    if result.get('errors'):lines+=_section('Processing limitations',result['errors'])
    lines+=['## Provenance','']+_table([('Policy',result.get('policy','Not recorded')),
        ('Context SHA-256',result.get('context_hash','Not recorded')),('Incident fingerprint',incident.get('fingerprint','Not recorded'))])
    lines+=['Narrative assessments and investigation recommendations are AI-assisted. Incident context, '
            'event references and reachable assets come from TRACE artifacts. Confidence and scores are '
            'heuristic evidence/prioritization measures, not calibrated attack probabilities.','']
    return '\n'.join(lines)


def incident_report(incident):
    lines=['# TRACE Incident Investigation Report','','## Incident overview','']+_context(incident)
    lines+=['## Executive summary','',f'TRACE linked {len(incident.get("timeline",[]))} suspicious steps. '
        'The findings require analyst review; a detection does not itself establish successful compromise.','']
    lines+=_section('ATT&CK tactics observed',incident.get('tactics',[]))
    lines+=['## Evidence timeline','','All published incident steps are listed below. Export the incident JSON for full event-ID lists and payloads.','',
        '| Step | First observed | Finding | Technique | First event reference |','|---|---|---|---|---|']
    for s in incident.get('timeline',[]):
        lines+=['| '+' | '.join([_text(f'Step {s.get("step")}'),_utc(s.get('ts')),_text(s.get('title')),
            _text(s.get('technique') or 'Unmapped'),_text(next(iter(s.get('event_ids',[])),'Not recorded'))])+' |']
    lines+=['']+_reachability(incident)
    lines+=['## Interpretation and handoff','','Preserve the original logs and review input-quality/quarantine metrics. '
        'Missing telemetry is uncertainty, not evidence of benign activity. Verify attempts versus successful actions '
        'before recording a case disposition. This report is evidence-derived; it does not contain a Sarvam triage verdict.','']
    return '\n'.join(lines)


def analysis_report(incident,result):
    lines=['# TRACE AI Investigation Report','','> AI-assisted analysis for analyst review. Recommendations have not been executed.','',
        '## Report details','']+_table([('Model',result.get('model','Not recorded')),
        ('Task',result.get('task','Not recorded')),('Language',result.get('language','Not recorded')),
        ('Prepared',_utc(result.get('created_at')))])
    lines+=['## Incident context','']+_context(incident)
    lines+=['## Analysis','',_prose(result['answer']),'']
    lines+=_evidence(incident,result.get('citations',[]))
    lines+=_section('Hypotheses requiring verification',result.get('hypotheses',[]))
    lines+=_section('Recommended next checks',result.get('next_checks',[]),numbered=True)
    mappings=result.get('suggested_mappings',[])
    lines+=_section('Suggested ATT&CK mapping changes',[
        f'{m["technique"]}: {m["reason"]} — events: {", ".join(m["event_ids"])}' for m in mappings])
    if result.get('sigma_yaml'):
        # A longer fence prevents a quoted model string from closing this block.
        fence='`'*max(3,max((len(m) for m in re.findall(r'`+',result['sigma_yaml'])),default=0)+1)
        lines+=['## Sigma draft — not enabled','',fence+'yaml',result['sigma_yaml'],fence,'']
    lines+=['## Scope and limitations','',f'{result.get("omitted_steps",0)} incident steps were omitted from the model context. '
        'Hypotheses and suggested rule/mapping changes require analyst validation. Event references are retained in full.','',
        'Context SHA-256: '+_text(result.get('context_hash','Not recorded')),'']
    return '\n'.join(lines)
