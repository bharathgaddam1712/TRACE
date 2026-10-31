"""Run the shipped sample plus a time-spread planted-chain acceptance loop without an API key."""
import argparse
import json
from pathlib import Path

from fastapi.testclient import TestClient

from tracekc.api import create_app
from tracekc.config import PROJECT_ROOT, load_config
from tracekc.evaluate import evaluate, gt_from_labels
from tracekc.pipeline import run_pipeline
from tracekc.synth import scale_up


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample', type=Path, default=PROJECT_ROOT / 'data/sample/edr_events.json')
    parser.add_argument('--out', type=Path, default=PROJECT_ROOT / 'out/sample-loop')
    args = parser.parse_args()
    cfg = load_config(overrides=['engine.memory_limit=1GB', 'engine.threads=4'])
    sample = run_pipeline(cfg, args.sample, args.out / 'sample')
    labels = evaluate(args.out / 'sample', gt_from_labels(args.sample))
    scale_up(args.sample, args.out / 'validation_input', target_gb=0.05)
    planted = run_pipeline(cfg, args.out / 'validation_input', args.out / 'planted')
    gt = json.loads((args.out / 'validation_input_gt.json').read_text(encoding='utf-8-sig'))
    evaluation = evaluate(args.out / 'planted', gt)
    if labels['any']['detection_rate'] != 1 or evaluation['incident']['detection_rate'] != 1 or evaluation['incident']['path_rate'] != 1:
        raise RuntimeError('Sample-loop acceptance criteria failed; inspect evaluation output')
    with TestClient(create_app(args.out / 'planted')) as client:
        import os
        headers = {'Authorization': 'Bearer ' + os.environ['TRACE_API_TOKEN']} if os.environ.get('TRACE_API_TOKEN') else {}
        response = client.get('/incidents', headers=headers)
        response.raise_for_status()
        incidents = response.json()
        detail = client.get(f"/incidents/{incidents[0]['id']}", headers=headers)
        detail.raise_for_status()
        incident = detail.json()
        eid = incident['timeline'][0]['event_ids'][0]
        client.get(f"/incidents/{incident['id']}/evidence/{eid}", headers=headers).raise_for_status()
        client.get('/', headers=headers).raise_for_status()
        ai_status = client.get('/ai/status', headers=headers).json()
    result = {'sample': {'events': sample['ingest']['events'], 'evaluation': labels},
              'planted_chain': {'events': planted['ingest']['events'], 'evaluation': evaluation,
                                'output': planted['output'], 'timings': planted['timings']},
              'api': 'incident, cited evidence and static UI passed', 'sarvam': ai_status,
              'sarvam_live_call': 'not attempted; configure .env and use the Assistant tab'}
    target = args.out / 'validation.json'
    target.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print(f'Validation report: {target}')
    print(f'Serve: python -m tracekc serve --out "{args.out / "planted"}"')


if __name__ == '__main__':
    main()
