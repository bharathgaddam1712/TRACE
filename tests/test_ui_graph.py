"""Interactive Streamlit graph: entity view keeps who-talks-to-whom and log text cannot escape the page."""
from tracekc import ui_graph

GRAPH = {'nodes': [{'id': 'user:alice', 'label': 'alice', 'type': 'user'},
                   {'id': 'host:WS1', 'label': 'WS1', 'type': 'host', 'suspected': True},
                   {'id': 'signal:1', 'label': 'Step 1: beacon', 'type': 'event'},
                   {'id': 'domain:evil.test', 'label': 'evil.test</script><script>alert(1)</script>', 'type': 'domain'}],
         'edges': [{'source': 'user:alice', 'target': 'host:WS1', 'kind': 'acted_on', 'techniques': ['T1078'], 'event_ids': ['a']},
                   {'source': 'host:WS1', 'target': 'signal:1', 'kind': 'observed_on', 'techniques': ['T1071'], 'event_ids': ['b']},
                   {'source': 'signal:1', 'target': 'domain:evil.test', 'kind': 'contacted', 'techniques': ['T1071'], 'event_ids': ['b']}]}


def test_entity_view_collapses_steps_into_host_to_domain_contact():
    view = ui_graph.entity_view(GRAPH)
    assert {n['id'] for n in view['nodes']} == {'user:alice', 'host:WS1', 'domain:evil.test'}
    contact = [e for e in view['edges'] if e['kind'] == 'contacted']
    assert [(e['source'], e['target']) for e in contact] == [('host:WS1', 'domain:evil.test')]
    assert contact[0]['techniques'] == ['T1071'] and contact[0]['derived_via'] == 'Step 1: beacon'


def test_connections_table_and_render_escape_log_text():
    rows = ui_graph.connections(ui_graph.entity_view(GRAPH))
    assert {('alice', 'WS1'), ('WS1', 'evil.test</script><script>alert(1)</script>')} == {(r['from'], r['to']) for r in rows}
    page = ui_graph.render(GRAPH)
    assert '</script><script>alert(1)' not in page and 'cytoscape' in page
