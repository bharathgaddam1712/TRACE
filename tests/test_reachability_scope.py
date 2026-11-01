import json

from fastapi.testclient import TestClient

from tracekc.api import create_app


def test_time_ordered_api_survives_model_route_removal(tmp_path, monkeypatch):
    monkeypatch.setenv('TRACE_API_TOKEN', '')
    monkeypatch.setenv('TRACE_GRAPH_BACKEND', 'local')
    incident = {
        'id': 1, 'fingerprint': 'case-one',
        'first_seen': '1970-01-01T00:00:00Z', 'last_seen': '1970-01-01T00:00:00.040Z',
        'timeline': [], 'lookahead': {'status': 'unknown', 'reachable': []},
        'graph': {'nodes': [{'id': node} for node in 'ABC'], 'edges': [
            {'source': 'A', 'target': 'B', 'kind': 'observed_on', 'observation_times_ms': [10]},
            {'source': 'B', 'target': 'C', 'kind': 'observed_on', 'observation_times_ms': [20]},
        ]},
    }
    (tmp_path / 'incidents').mkdir()
    (tmp_path / 'incidents/1.json').write_text(json.dumps(incident), encoding='utf-8')
    (tmp_path / 'index.json').write_text(json.dumps([{'id': 1, 'fingerprint': 'case-one'}]), encoding='utf-8')
    app = create_app(tmp_path)
    assert not any(route.path.startswith(('/forecast/', '/temporal/')) for route in app.routes)
    with TestClient(app) as client:
        result = client.get('/incidents/1/temporal-path?source=A&target=C&depth=2')
        assert result.status_code == 200
        assert result.json()['nodes'] == ['A', 'B', 'C']
        assert result.json()['observation_times_ms'] == [10, 20]
        # No public model endpoints remain; unknown paths have normal 404 behavior.
        for path in ['/forecast/model', '/forecast/model/download', '/forecast/benchmark', '/temporal/benchmark']:
            assert client.get(path).status_code == 404
        assert client.get('/incidents/1').json()['lookahead']['reachable'] == []
