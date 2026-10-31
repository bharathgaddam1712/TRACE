"""Sigma compiler: modifiers, conditions, correlation parsing, and the shipped ruleset."""
import pytest

from conftest import ROOT
from tracekc.sigma import SigmaError, emitting_rule_ids, load_rules, parse_rule


def rule(detection, logsource=None, **extra):
    return parse_rule({"id": "t", "title": "t", "level": "high", "logsource": logsource or {},
                       "detection": detection, "tags": ["attack.execution", "attack.t1059.001"], **extra}, "x.yml")


def test_contains_list_is_or_and_case_insensitive():
    r = rule({"sel": {"process.command_line|contains": ["-enc", "Hidden"]}, "condition": "sel"})
    assert "LIKE '%-enc%'" in r.where and "LIKE '%hidden%'" in r.where and " OR " in r.where


def test_all_modifier_is_and():
    r = rule({"sel": {"process.command_line|contains|all": ["a", "b"]}, "condition": "sel"})
    assert " AND " in r.where


def test_condition_precedence_and_quantifiers():
    r = rule({"sel_a": {"process.name": "x.exe"}, "sel_b": {"process.name": "y.exe"},
              "filter": {"user.name": "svc"}, "condition": "1 of sel_* and not filter"})
    assert r.where.startswith("((") and "NOT" in r.where


def test_backslash_values_are_escaped_for_like():
    r = rule({"sel": {"registry.path|contains": "\\CurrentVersion\\Run"}, "condition": "sel"})
    assert "\\\\currentversion\\\\run" in r.where


def test_numeric_and_cidr():
    r = rule({"sel": {"winlog.event_id": [4728, 4732]}, "net": {"destination.ip|cidr": "10.0.0.0/8"},
              "condition": "sel and not net"})
    assert "win_event_id = 4728" in r.where and "ipv4_int(dst_ip) BETWEEN 167772160 AND 184549375" in r.where


def test_logsource_constraint_added():
    r = rule({"sel": {"process.name": "x.exe"}, "condition": "sel"}, {"category": "process_creation"})
    assert "action = 'process_created'" in r.where


def test_tags_give_technique_and_tactic():
    r = rule({"sel": {"process.name": "x"}, "condition": "sel"})
    assert r.techniques == ["T1059.001"] and r.tactic_hint == "execution"


@pytest.mark.parametrize("det", [
    {"sel": {"no.such.field": "x"}, "condition": "sel"},
    {"sel": {"process.name|base64": "x"}, "condition": "sel"},
    {"sel": ["keyword"], "condition": "sel"},
    {"sel": {"process.name": "x"}, "condition": "sel and missing"},
])
def test_rejects_unsupported(det):
    with pytest.raises(SigmaError):
        rule(det)


def test_correlation_rule_parse():
    r = parse_rule({"id": "c", "title": "c", "level": "medium", "correlation": {
        "type": "event_count", "rules": ["b"], "group-by": ["user.name", "source.ip"], "timespan": "5m",
        "condition": {"gte": 20}}}, "x.yml")
    assert r.corr["span_ms"] == 300_000 and r.corr["group"] == ["user_name", "src_ip"] and r.corr["threshold"] == 20


def test_shipped_rules_load_cleanly():
    rules, errors = load_rules(ROOT / "rules")
    assert errors == []
    emit = emitting_rule_ids(rules)
    assert "trace-failed-logon" not in emit          # building block stays silent
    assert "trace-bruteforce-burst" in emit          # always_emit extension
    assert "trace-bruteforce-then-success" in emit


@pytest.mark.parametrize('threads,reverse',[(1,False),(1,True),(4,False),(4,True)])
def test_equal_timestamp_session_boundaries_are_independent_of_order(threads,reverse):
    import duckdb
    from tracekc.sigma import ENTITY_COLS,relation_sql
    rules,_=load_rules(ROOT/'rules')
    con=duckdb.connect();con.execute(f'SET threads={threads}')
    entities=', '.join(f'{name} '+('BIGINT' if name=='proc_pid' else 'VARCHAR') for name in ENTITY_COLS)
    con.execute(f'CREATE TABLE rule_hits(event_id VARCHAR,ts_ms BIGINT,{entities},hits VARCHAR[])').fetchall()
    rows=[]
    for batch,ts in enumerate((0,1200000)):
        for index in range(10):
            values={name:None for name in ENTITY_COLS};values.update(host='WS',user_name=f'user-{index}',src_ip='8.8.8.8')
            rows.append([f'{batch}-{index}',ts,*[values[name] for name in ENTITY_COLS],['trace-failed-logon']])
    if reverse:rows.reverse()
    con.executemany('INSERT INTO rule_hits VALUES ('+','.join('?' for _ in rows[0])+')',rows)
    query=relation_sql('trace-password-spray',rules,1000)
    result=con.execute(f'SELECT ts_first_ms,event_count FROM ({query}) ORDER BY ts_first_ms').fetchall()
    assert result==[(0,10),(1200000,10)]
    con.close()
