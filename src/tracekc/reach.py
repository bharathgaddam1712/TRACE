"""Time-bounded access hypotheses from observed telemetry, never calibrated probabilities."""
from __future__ import annotations

import re
from collections import defaultdict

from tracekc.engine import run

INTERACTIVE = {'interactive', 'remoteinteractive', '2', '10', 'cachedinteractive', '11'}
CONF_RANK = {'high': 3, 'medium': 2, 'low': 1}


class AccessGraph:
    def __init__(self, con, cfg: dict):
        self.cfg = cfg
        self.la = cfg['lookahead']
        self.excluded = set(cfg['correlation']['excluded_users'])
        self.criticality = [(re.compile(c['pattern']), int(c['weight'])) for c in self.la['criticality']]
        # One earliest evidenced observation per hour and relation keeps the graph compact.
        # Counts are not exposed because later events in the same bucket may be after the cutoff.
        self.logons = run(con, """SELECT user_name, host, coalesce(logon_type, 'unknown'),
            min(ts_ms), arg_min(event_id, ts_ms) FROM ev
            WHERE action = 'user_logon' AND outcome = 'success' AND user_name IS NOT NULL
            GROUP BY user_name, host, logon_type, ts_ms // 3600000""")
        self.admins = run(con, """SELECT user_name, host, min(ts_ms), arg_min(event_id, ts_ms)
            FROM ev WHERE win_event_id = 4672 AND user_name IS NOT NULL
            GROUP BY user_name, host, ts_ms // 3600000""")
        ports = ', '.join(str(int(p)) for p in self.la['admin_ports'])
        self.network = run(con, f"""SELECT host, dst_host, dst_port, min(ts_ms), arg_min(event_id, ts_ms),
            coalesce(outcome, 'unknown') FROM ev WHERE action = 'network_connection'
            AND dst_host IS NOT NULL AND dst_host <> host AND dst_port IN ({ports})
            AND coalesce(outcome, 'unknown') <> 'failure'
            GROUP BY host, dst_host, dst_port, outcome, ts_ms // 3600000""")
        self.latest = max([r[3] for r in self.logons] + [r[2] for r in self.admins] + [r[3] for r in self.network] + [0])
        self.logons_by_user, self.logons_by_host = defaultdict(list), defaultdict(list)
        self.admins_by_user, self.network_by_host = defaultdict(list), defaultdict(list)
        for row in sorted(self.logons, key=lambda r:(r[3],r[4])):
            self.logons_by_user[row[0]].append(row)
            self.logons_by_host[row[1]].append(row)
        for row in sorted(self.admins, key=lambda r:(r[2],r[3])):
            self.admins_by_user[row[0]].append(row)
        for row in sorted(self.network, key=lambda r:(r[3],r[4])):
            self.network_by_host[row[0]].append(row)

    def lookahead(self, users: set[str], hosts: set[str], as_of_ms: int | None = None) -> dict:
        cutoff = self.latest if as_of_ms is None else as_of_ms
        floor = cutoff - int(self.la.get('evidence_max_age_s', 604800)) * 1000
        session_floor = cutoff - int(self.la.get('session_max_age_s', 28800)) * 1000
        users = {u for u in users if u and u not in self.excluded}
        accounts, sessions, network = defaultdict(dict), defaultdict(dict), defaultdict(dict)
        relevant_users = set(users)
        if int(self.la['max_hops']) >= 2:
            for host in sorted(hosts):
                for user, _, kind, ts, event in self.logons_by_host.get(host, ()):
                    if kind in INTERACTIVE and max(floor,session_floor) <= ts <= cutoff and user not in self.excluded:
                        sessions[host][user] = {'ts':ts, 'event':event}
                        relevant_users.add(user)
        for user, host, kind, ts, event in (row for user in sorted(relevant_users) for row in self.logons_by_user.get(user, ())):
            if floor <= ts <= cutoff:
                accounts[user][host] = {'ts': ts, 'event': event, 'kind': kind, 'admin': False}
                if kind in INTERACTIVE and ts >= session_floor:
                    sessions[host][user] = {'ts': ts, 'event': event}
        for user, host, ts, event in (row for user in sorted(relevant_users) for row in self.admins_by_user.get(user, ())):
            if floor <= ts <= cutoff:
                accounts[user][host] = {'ts': ts, 'event': event, 'kind': 'privileged_logon', 'admin': True}
        for src, dst, port, ts, event, outcome in (row for host in sorted(hosts) for row in self.network_by_host.get(host, ())):
            if floor <= ts <= cutoff:
                network[src][dst] = {'ts': ts, 'event': event, 'port': port, 'outcome': outcome}
        users = {u for u in users if u and u not in self.excluded}
        candidates = {}

        def add(host, confidence, relation, via_type, via, observations, hops):
            evidence = {'event_ids': [e['event'] for e in observations],
                        'sample_event_id': observations[0]['event'],
                        'observed_at_ms': [e['ts'] for e in observations]}
            candidate = {'asset': host, 'confidence': confidence, 'relation': relation,
                         'via': f'{via_type} {via}', 'via_entity': {'type': via_type, 'id': via},
                         'evidence': evidence, 'hops': hops,
                         'criticality': next((w for rx, w in self.criticality if rx.search(host)), 1),
                         'interpretation': 'possible access; not proof of compromise or future action'}
            current = candidates.get(host)
            if current is None or CONF_RANK[confidence] > CONF_RANK[current['confidence']]:
                candidates[host] = candidate

        for user in sorted(users):
            for host, evidence in accounts.get(user, {}).items():
                if host not in hosts:
                    add(host, 'high' if evidence['admin'] else 'medium',
                        'AdminTo' if evidence['admin'] else 'CanLogon', 'user', user, [evidence], 1)
        for host in sorted(hosts):
            for dst, evidence in network.get(host, {}).items():
                if dst not in hosts:
                    add(dst, 'low', 'NetReach', 'host', host, [evidence], 1)
            if int(self.la['max_hops']) >= 2:
                for user, session in sessions.get(host, {}).items():
                    if user in users or user in self.excluded:
                        continue
                    for dst, evidence in accounts.get(user, {}).items():
                        if dst not in hosts:
                            add(dst, 'low', 'HasSession->CanLogon', 'host', host, [session, evidence], 2)
        ranked = sorted(candidates.values(), key=lambda c: (-CONF_RANK[c['confidence']], -c['criticality'], c['asset']))
        assumptions = ['Confidence is a heuristic evidence strength, not an attack probability.',
                       'Past logon does not establish current authorization; session credential exposure is a hypothesis.',
                       'Hourly first observations are used conservatively; some later within-hour access may be omitted.']
        if not any(accounts.get(u) for u in users):
            assumptions.append('No successful-logon telemetry for the compromised accounts; next hop unknown.')
        if not any(e['admin'] for u in users for e in accounts.get(u, {}).values()):
            assumptions.append('No admin-privilege (4672) evidence before the cutoff; logon access is not admin access.')
        return {'status': 'evidenced' if ranked else 'unknown', 'as_of_ms': cutoff,
                'method': 'time_bounded_access_graph', 'total_candidates': len(ranked),
                'reachable': ranked[:int(self.la['max_results'])], 'assumptions': assumptions}
