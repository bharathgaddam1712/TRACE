"""Check the real-data demo's API, evidence links and temporal report without AI calls."""
import argparse
import json
import os
from pathlib import Path
from fastapi.testclient import TestClient
from tracekc.api import create_app


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',default='out/firex-demo')
    args=parser.parse_args()
    output=Path(args.out)
    app=create_app(output)
    headers={'Authorization':'Bearer '+os.environ['TRACE_API_TOKEN']} if os.environ.get('TRACE_API_TOKEN') else {}
    with TestClient(app,headers=headers) as client:
        def get(path):
            response=client.get(path);response.raise_for_status();return response
        listed=get('/incidents?limit=1000').json()
        rows=json.loads((output/'index.json').read_text(encoding='utf-8'))
        assert rows,'No demo incidents'
        assert listed,'API did not return incidents'
        forecasts=[]
        for row in rows:
            # Validate every stored graph without repeatedly serializing all its
            # evidence/relationships through HTTP; API behavior is checked below.
            inc=json.loads((output/'incidents'/f"{row['id']}.json").read_text(encoding='utf-8'))
            ids={n['id'] for n in inc['graph']['nodes']}
            assert all(e['source'] in ids and e['target'] in ids for e in inc['graph']['edges'])
            if inc.get('forecast',{}).get('sequences'):
                forecasts.append(row['id'])
        incident=get(f"/incidents/{rows[0]['id']}").json()
        event=incident['timeline'][0]['event_ids'][0]
        get(f"/incidents/{incident['id']}/evidence/{event}")
        get('/')
        temporal=get('/temporal/benchmark').json()
        assert temporal['task']=='future_network_interaction_ranking' and temporal['attack_accuracy'] is None
        assert forecasts,'No eligible future incident received a supported sequence'
        result={'incidents':len(rows),'incidents_with_sequence_hypotheses':len(forecasts),
                'example_sequence_incident_ids':forecasts[:5], 'graph_integrity':'passed for all incidents',
                'api_evidence':'passed','temporal_report':'passed','live_sarvam':'not called'}
        (output/'demo-smoke.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
