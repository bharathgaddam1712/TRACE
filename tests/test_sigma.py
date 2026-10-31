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
