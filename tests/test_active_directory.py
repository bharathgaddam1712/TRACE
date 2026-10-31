"""Active Directory detections on Winlogbeat-shaped domain controller events: each attack fires,
and its benign look-alike does not."""
import itertools
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import pytest

from tracekc.config import load_config
from tracekc.pipeline import run_pipeline
from tracekc.sigma import SigmaError, load_rules, relation_sql

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 10, 20, 10, 0, tzinfo=timezone.utc)
REPLICATION_GUID = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
RECORD = itertools.count(1000)


def ts(minute):
    return (START + timedelta(minutes=minute)).isoformat().replace('+00:00', 'Z')


def win(minute, event_id, data=None, **ecs):
    """One DC event without event.id (as Winlogbeat ships it). Accounts/IPs come only from event_data."""
    event = {'@timestamp': ts(minute), 'event': {'kind': 'event', 'category': ['iam'], 'action': f'win-{event_id}'},
             'host': {'name': 'DC01.corp.local', 'os': {'type': 'windows'}},
             'winlog': {'event_id': str(event_id), 'record_id': next(RECORD), 'event_data': data or {}}}
    event.update(ecs)
    return event


def ad_events():
    ev = []
    # Kerberoasting: alice gets RC4 tickets for 7 service accounts in 10 minutes.
    ev += [win(i, 4769, {'TargetUserName': 'alice@CORP.LOCAL', 'ServiceName': f'svc_sql{i}',
                         'TicketEncryptionType': '0x17', 'IpAddress': '::ffff:10.0.0.50'}) for i in range(7)]
    # Benign: AES tickets, too few RC4 services, RC4 tickets for machine accounts.
    ev += [win(i, 4769, {'TargetUserName': 'bob', 'ServiceName': f'svc_web{i}',
                         'TicketEncryptionType': '0x12', 'IpAddress': '10.0.0.51'}) for i in range(7)]
    ev += [win(i, 4769, {'TargetUserName': 'carol', 'ServiceName': f'svc_app{i}',
                         'TicketEncryptionType': '0x17', 'IpAddress': '10.0.0.52'}) for i in range(3)]
    ev += [win(i, 4769, {'TargetUserName': 'dave', 'ServiceName': f'FS0{i}$',
                         'TicketEncryptionType': '0x17', 'IpAddress': '10.0.0.53'}) for i in range(8)]
    # Golden ticket indicator: krbtgt ticket with RC4; an AES krbtgt ticket is normal.
    ev.append(win(20, 4769, {'TargetUserName': 'mallory', 'ServiceName': 'krbtgt',
                             'TicketEncryptionType': '0x17', 'IpAddress': '10.0.0.60'}))
    ev.append(win(20, 4769, {'TargetUserName': 'frank', 'ServiceName': 'krbtgt',
                             'TicketEncryptionType': '0x12', 'IpAddress': '10.0.0.61'}))
    # Password spray: 12 accounts fail pre-auth from one address in 3 minutes; 5 accounts stays below threshold.
    ev += [win(30 + i / 4, 4771, {'TargetUserName': f'user{i}', 'Status': '0x18',
                                  'IpAddress': '::ffff:10.0.0.66'}) for i in range(12)]
    ev += [win(30 + i / 4, 4771, {'TargetUserName': f'staff{i}', 'Status': '0x18',
                                  'IpAddress': '10.0.0.70'}) for i in range(5)]
    # DCSync by a user; a domain controller replicating is normal.
    ev.append(win(40, 4662, {'SubjectUserName': 'eve', 'AccessMask': '0x100',
                             'Properties': '%%7688 {' + REPLICATION_GUID + '} {19195a5b-6da0-11d0-afd3-00c04fd930c9}'}))
    ev.append(win(40, 4662, {'SubjectUserName': 'DC02$', 'AccessMask': '0x100',
                             'Properties': '%%7688 {' + REPLICATION_GUID + '}'}))
    ev.append(win(41, 5136, {'SubjectUserName': 'eve', 'AttributeLDAPDisplayName': 'nTSecurityDescriptor',
                             'ObjectDN': 'DC=corp,DC=local',
                             'AttributeValue': 'O:BAG:BAD:(OA;;CR;' + REPLICATION_GUID + ';;S-1-5-21-1-1104)'}))
    ev.append(win(42, 4742, {'SubjectUserName': 'eve', 'ServicePrincipalNames':
                             'E3514235-4B06-11D1-AB04-00C04FC2DCD2/abc/corp.local GC/WS99.corp.local/corp.local'}))
    # Privileged groups: named only in TargetUserName (no ECS group.name), and via ECS group.name.
    ev.append(win(43, 4728, {'SubjectUserName': 'eve', 'TargetUserName': 'Domain Admins', 'MemberName': 'CN=eve'}))
    ev.append(win(43, 4732, {'SubjectUserName': 'eve', 'MemberName': 'CN=eve'}, group={'name': 'DnsAdmins'}))
    ev.append(win(43, 4728, {'SubjectUserName': 'hr_admin', 'TargetUserName': 'Marketing', 'MemberName': 'CN=gina'}))
    # Directory object changes.
    ev.append(win(44, 5136, {'SubjectUserName': 'eve', 'AttributeLDAPDisplayName': 'nTSecurityDescriptor',
                             'ObjectDN': 'CN=AdminSDHolder,CN=System,DC=corp,DC=local'}))
    ev.append(win(45, 5136, {'SubjectUserName': 'eve', 'AttributeLDAPDisplayName': 'servicePrincipalName',
                             'ObjectClass': 'user', 'ObjectDN': 'CN=svc_backup,CN=Users,DC=corp,DC=local'}))
    ev.append(win(45, 5136, {'SubjectUserName': 'WS01$', 'AttributeLDAPDisplayName': 'servicePrincipalName',
                             'ObjectClass': 'user', 'ObjectDN': 'CN=WS01,CN=Computers,DC=corp,DC=local'}))
    ev.append(win(46, 5136, {'SubjectUserName': 'eve', 'AttributeLDAPDisplayName': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                             'ObjectDN': 'CN=FS01,CN=Computers,DC=corp,DC=local'}))
    ev.append(win(47, 5136, {'SubjectUserName': 'eve', 'AttributeLDAPDisplayName': 'gPCFileSysPath',
                             'ObjectDN': 'CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local'}))
    # SYSVOL: a startup script is suspicious, a policy XML is not.
    sysvol = r'C:\Windows\SYSVOL\domain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Scripts\Startup'
    for name in ('run.ps1', 'Registry.xml'):
        ev.append({'@timestamp': ts(48), 'event': {'kind': 'event', 'category': ['file'], 'action': 'file_created'},
                   'host': {'name': 'DC01.corp.local', 'os': {'type': 'windows'}}, 'user': {'name': 'eve'},
                   'file': {'path': sysvol + '\\' + name, 'name': name}})
    # LDAP (Directory Service 1644): LAPS password read and a large result set; a small search is normal.
    ev.append(win(50, 1644, message='Client: 10.0.0.80:50111 Filter: (objectClass=computer) '
                                    'Attribute selection: [all_with_list]ms-Mcs-AdmPwd Entries Returned: 3'))
    ev.append(win(51, 1644, message='Client: 10.0.0.81:50112 Filter: (objectClass=user) Entries Visited: 4800 Entries Returned: 4210'))
    ev.append(win(52, 1644, message='Client: 10.0.0.82:50113 Filter: (cn=printer1) Entries Visited: 12 Entries Returned: 12'))
    return ev


def run(tmp_path, events):
    source = tmp_path / 'dc_security.ndjson'
    source.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
    run_pipeline(load_config(), source, tmp_path / 'out')
    return tmp_path / 'out'


@pytest.fixture(scope='module')
def signals(tmp_path_factory):
    out = run(tmp_path_factory.mktemp('ad'), ad_events())
    with duckdb.connect() as con:
        return con.execute('SELECT rule_ids, user_name, src_ip, technique FROM read_parquet(?)',
                           [str(out / 'signals.parquet')]).fetchall()


def matching(signals, rule_id):
    return [s for s in signals if rule_id in s[0]]


def test_kerberoasting_needs_many_rc4_services_for_one_user(signals):
    hits = matching(signals, 'trace-ad-kerberoasting')
    assert [s[1] for s in hits] == ['alice']        # not bob (AES), carol (3 services) or dave (machine accounts)
    assert hits[0][3] == 'T1558.003'
    assert not matching(signals, 'trace-ad-kerberos-rc4-tgs')   # building block stays silent


def test_krbtgt_weak_encryption_only_for_rc4(signals):
    assert [s[1] for s in matching(signals, 'trace-ad-krbtgt-weak-encryption')] == ['mallory']


def test_password_spray_from_one_source_with_ipv4_mapped_address(signals):
    hits = matching(signals, 'trace-ad-password-spray')
    assert [s[2] for s in hits] == ['10.0.0.66']    # ::ffff: prefix stripped; the 5-account source is not flagged
    assert hits[0][3] == 'T1110.003'


def test_dcsync_by_user_not_by_domain_controller(signals):
    assert [s[1] for s in matching(signals, 'trace-ad-dcsync')] == ['eve']
    assert matching(signals, 'trace-ad-replication-rights-granted')
    assert matching(signals, 'trace-ad-dcshadow')


def test_privileged_group_rules_ignore_ordinary_groups(signals):
    assert len(matching(signals, 'trace-ad-tier0-group-add')) == 1         # Domain Admins via TargetUserName
    assert len(matching(signals, 'trace-ad-privileged-group-add')) == 1    # DnsAdmins via group.name
    assert [s[1] for s in matching(signals, 'trace-admin-group-add')] == ['hr_admin']   # Marketing: generic, low
    assert not any(s[1] == 'hr_admin' for s in matching(signals, 'trace-ad-tier0-group-add')
                   + matching(signals, 'trace-ad-privileged-group-add'))


def test_directory_object_and_gpo_changes(signals):
    for rule in ('trace-ad-adminsdholder-modified', 'trace-ad-delegation-modified', 'trace-ad-gpo-modified',
                 'trace-ad-sysvol-script-drop', 'trace-ad-ldap-sensitive-attribute', 'trace-ad-ldap-enumeration'):
        assert len(matching(signals, rule)) == 1, rule
    assert [s[1] for s in matching(signals, 'trace-ad-spn-modified')] == ['eve']   # WS01$ self-update excluded


def test_same_millisecond_windows_events_are_not_deduplicated(tmp_path):
    events = [win(0, 4769, {'TargetUserName': 'alice', 'ServiceName': f'svc{i}', 'TicketEncryptionType': '0x12'})
              for i in range(3)]
    for event in events:
        event['event']['action'] = 'kerberos-service-ticket-requested'
    out = run(tmp_path, events)
    assert json.loads((out / 'run_metrics.json').read_text())['ingest']['events'] == 3


def test_value_count_on_event_field_rejects_correlation_inputs():
    rules, _ = load_rules(ROOT / 'rules')
    nested = rules['trace-ad-kerberoasting']
    rules['nested'] = type(nested)(**{**nested.__dict__, 'id': 'nested',
                                      'corr': {**nested.corr, 'rules': ['trace-ad-password-spray']}})
    with pytest.raises(SigmaError):
        relation_sql('nested', rules, 50)
