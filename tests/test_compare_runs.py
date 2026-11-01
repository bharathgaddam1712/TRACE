"""Quality gate must catch evidence drift hidden by matching counters."""
import json
from pathlib import Path
import subprocess
import sys

import duckdb


def test_comparison_rejects_changed_evidence_with_identical_counts(tmp_path):
    roots=[tmp_path/'reference',tmp_path/'candidate']
    report={'ingest':{'events':1},'detect':{'detections_by_source':{'sigma':1},
        'detections_by_rule':{'rule':1}},'signals':1,'output':{'incidents':1},
        'timings':{'total_wall_seconds':1}}
    for root in roots:
        (root/'work').mkdir(parents=True);(root/'incidents').mkdir()
        (root/'run_metrics.json').write_text(json.dumps(report),encoding='utf-8')
        (root/'index.json').write_text(json.dumps([{'fingerprint':'same'}]),encoding='utf-8')
        (root/'incidents/1.json').write_text(json.dumps({'evidence':{'pid':1}}),encoding='utf-8')
        with duckdb.connect() as con:
            target=str(root/'work/events.parquet').replace("'","''")
            con.execute(f"COPY (SELECT 'event' AS event_id) TO '{target}' (FORMAT PARQUET)")
    script=Path(__file__).resolve().parents[1]/'scripts/compare_runs.py'
    command=[sys.executable,str(script),'--reference',str(roots[0]),'--candidate',str(roots[1])]
    assert subprocess.run(command,capture_output=True).returncode==0
    (roots[1]/'incidents/1.json').write_text(json.dumps({'evidence':{'pid':2}}),encoding='utf-8')
    result=subprocess.run(command,capture_output=True,text=True)
    assert result.returncode==1
    output=json.loads(result.stdout)
    assert output['checks']['incident_evidence_fingerprints']
    assert not output['checks']['complete_incident_payloads']
    assert output['mismatched_incident_files']==['1.json']
