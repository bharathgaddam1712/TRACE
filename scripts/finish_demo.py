"""Finish model artifacts once the active full-file pipeline publishes its output."""
from pathlib import Path
import json
import time
import subprocess
import sys

root=Path('out/firex-full-demo')
deadline=time.monotonic()+1200
while True:
    state=json.loads((root/'progress.json').read_text(encoding='utf-8'))
    if state.get('state')=='failed':
        raise RuntimeError(state.get('error','Pipeline failed'))
    if state.get('state')=='complete' and not (root/'.pipeline.lock').exists():
        break
    if time.monotonic()>deadline:
        raise TimeoutError('Pipeline has not completed; inspect progress.json')
    time.sleep(3)

def run(*args):
    subprocess.run([sys.executable,*args],check=True)

# A pipeline already in progress when byte accounting was added may publish the
# older metrics shape. Recover exact rejected ranges from this run's ledgers.
metrics_path=root/'run_metrics.json'
metrics=json.loads(metrics_path.read_text(encoding='utf-8'))
if 'reader_rejected_bytes' not in metrics['ingest']:
    intervals={}
    for ledger in (root/'ingest_cache').glob('*.quarantine.jsonl'):
        for line in ledger.read_text(encoding='utf-8').splitlines():
            row=json.loads(line)
            intervals.setdefault(row['source_file'],[]).append((row['source_byte_offset'],row['source_byte_offset']+row['bytes']))
    total=0
    for ranges in intervals.values():
        right=-1
        for start,end in sorted(ranges):
            total+=max(0,end-max(start,right));right=max(right,end)
    metrics['ingest']['reader_rejected_bytes']=total
    from tracekc.materialize import write_json
    write_json(metrics_path,metrics)

run('-m','tracekc','export-history','--out',str(root),'--save',str(root/'histories.json'))
run('-m','tracekc','forecast-benchmark','--input',str(root/'histories.json'),'--out',str(root/'forecast-comparison.json'),'--model-out',str(root/'forecast-model.json'))
run('-m','tracekc','attach-forecast','--out',str(root),'--model',str(root/'forecast-model.json'))
run('scripts/demo_smoke.py','--out',str(root))
run('scripts/streamlit_smoke.py','--out',str(root))
