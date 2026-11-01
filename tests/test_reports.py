"""Exports preserve evidence, uncertainty and document boundaries."""
from tracekc.reports import analysis_report,incident_report,triage_report


def example():
    inc={'id':1,'title':'Logon investigation','score':45,'fingerprint':'case-one',
        'first_seen':'2026-10-20T10:00:00.123Z','last_seen':'2026-10-20T10:00:01Z',
        'entities':{'hosts':['HOST'],'users':[]},'tactics':['Credential Access'],
        'timeline':[{'step':1,'ts':'2026-10-20T10:00:00.123Z','title':'Blocked attempt',
            'technique':'T1110','event_ids':['full-event-identifier']}], 'lookahead':{'reachable':[]}}
    result={'created_at':'2026-10-20T11:00:00+00:00','model':'example-model','status':'NEEDS_REVIEW',
        'policy':'triage-v2','context_hash':'a'*64,'grounding':{'omitted_steps':0},'errors':[],
        'verdict':{'assessment':'insufficient_evidence','priority':'P2','severity':'medium',
            'rationale':'Blocked activity needs review.','citations':['full-event-identifier'],
            'contradictory_evidence':['No success shown.'],'missing_evidence':['Authentication telemetry.'],
            'next_checks':['Review the host.']}}
    return inc,result


def test_triage_report_contains_full_references_scope_and_review():
    inc,result=example()
    report=triage_report(inc,result,[{'decision':'monitor','note':'Reviewed evidence.','ts':'2026-10-20T12:00:00Z'}])
    for expected in ['# TRACE AI Triage Report','## Executive assessment','## Supporting event references',
        'full-event-identifier','2026-10-20T10:00:00.123Z','No account identities recorded',
        '## Contradicting observations','## Missing evidence and limitations','1. Review the host.',
        'Analyst review record','Reviewed evidence.','does not establish','not calibrated']:
        assert expected in report
    assert report.endswith('\n')


def test_report_fields_cannot_inject_html_headings_or_table_columns():
    inc,result=example();inc['title']='name|value\n## forged <script>alert(1)</script>'
    result['verdict']['rationale']='## forged\n<script>bad</script>'
    report=triage_report(inc,result)
    assert '\n## forged' not in report and '<script>' not in report
    assert 'name\\|value' in report and '&lt;script&gt;' in report


def test_evidence_report_lists_all_steps_without_claiming_an_ai_verdict():
    inc,_=example();report=incident_report(inc)
    assert 'Step 1' in report and 'full-event-identifier' in report
    assert 'does not contain a Sarvam triage verdict' in report
    assert 'not evidence of benign activity' in report


def test_analysis_report_preserves_hypotheses_and_fences_sigma_drafts():
    inc,_=example()
    result={'answer':'Review access.','model':'example','task':'rule','language':'English',
        'citations':['full-event-identifier'],'hypotheses':['Possible attempt.'],'next_checks':['Check auth.'],
        'suggested_mappings':[],'sigma_yaml':'title: draft\n# ``` boundary','omitted_steps':0}
    report=analysis_report(inc,result)
    assert '## Hypotheses requiring verification' in report
    assert '## Sigma draft — not enabled' in report and '````yaml' in report
    assert 'full-event-identifier' in report and 'Prepared | Not recorded' in report
