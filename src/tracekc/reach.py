"""Stage 6: what could the attacker reach next (FR-6).

A BloodHound-style access graph built only from observed telemetry:
  CanLogon   user -> host   successful logons (event 4624 / user_logon success)
  AdminTo    user -> host   special-privilege logons (event 4672) when present
  HasSession host -> user   interactive / RDP logons leave reusable credentials on the host
  NetReach   host -> host   successful connections to admin ports (SMB, RDP, WinRM, SSH, RPC)
Hop 1: hosts the compromised accounts can already log on to, plus admin-port reachability.
Hop 2: accounts with sessions on compromised hosts (credential exposure) and the hosts *they* can
reach. Nothing is guessed: with no logon data for the accounts the answer is "unknown".
"""
from __future__ import annotations

import re
from collections import defaultdict

from tracekc.engine import run

INTERACTIVE = {"interactive", "remoteinteractive", "2", "10", "cachedinteractive", "11"}
CONF_RANK = {"high": 3, "medium": 2, "low": 1}


class AccessGraph:
    def __init__(self, con, cfg: dict):
        la = cfg["lookahead"]
        self.max_hops = int(la["max_hops"])
        self.max_results = int(la["max_results"])
        self.criticality = [(re.compile(c["pattern"]), int(c["weight"])) for c in la["criticality"]]
        self.excluded = set(cfg["correlation"]["excluded_users"])
        self.user_hosts: dict[str, dict[str, dict]] = defaultdict(dict)
        self.host_sessions: dict[str, dict[str, dict]] = defaultdict(dict)
        self.host_net: dict[str, dict[str, dict]] = defaultdict(dict)
        for user, host, ltype, n, ev in run(con, """
                SELECT user_name, host, coalesce(logon_type, 'unknown'), count(*), min(event_id)
                FROM ev WHERE action = 'user_logon' AND outcome = 'success' AND user_name IS NOT NULL
                GROUP BY ALL"""):
            e = self.user_hosts[user].setdefault(host, {"logons": 0, "types": set(), "admin": False, "event": ev})
            e["logons"] += n
            e["types"].add(ltype)
            if ltype in INTERACTIVE:
                self.host_sessions[host].setdefault(user, {"logons": 0, "event": ev})["logons"] += n
        for user, host in run(con, """SELECT DISTINCT user_name, host FROM ev
                                      WHERE win_event_id = 4672 AND user_name IS NOT NULL"""):
            self.user_hosts[user].setdefault(host, {"logons": 0, "types": set(), "admin": False, "event": None})
            self.user_hosts[user][host]["admin"] = True
        ports = ", ".join(str(int(p)) for p in la["admin_ports"])
        for src, dst, port, n, ev in run(con, f"""
                SELECT host, dst_host, dst_port, count(*), min(event_id) FROM ev
                WHERE action = 'network_connection' AND dst_host IS NOT NULL AND dst_host <> host
                  AND dst_port IN ({ports}) GROUP BY ALL"""):
            e = self.host_net[src].setdefault(dst, {"ports": set(), "connections": 0, "event": ev})
            e["ports"].add(int(port))
            e["connections"] += n

    def _weight(self, host: str) -> int:
        return next((w for rx, w in self.criticality if rx.search(host)), 1)

    def lookahead(self, users: set[str], hosts: set[str]) -> dict:
        users = {u for u in users if u and u not in self.excluded}
        cands: dict[str, dict] = {}

        def add(host, conf, relation, via, evidence, hop):
            cur = cands.get(host)
            if cur is None or CONF_RANK[conf] > CONF_RANK[cur["confidence"]]:
                cands[host] = {"asset": host, "confidence": conf, "relation": relation, "via": via,
                               "evidence": evidence, "hops": hop, "criticality": self._weight(host)}

        known_users = [u for u in users if u in self.user_hosts]
        for u in known_users:
            for h, e in self.user_hosts[u].items():
                if h in hosts:
                    continue
                rel = "AdminTo" if e["admin"] else "CanLogon"
                add(h, "high" if e["admin"] else "medium", rel, f"account {u}",
                    {"logons": e["logons"], "logon_types": sorted(e["types"]), "sample_event_id": e["event"]}, 1)
        for h in hosts:
            for dst, e in self.host_net.get(h, {}).items():
                if dst not in hosts:
                    add(dst, "low", "NetReach", f"network from {h}",
                        {"ports": sorted(e["ports"]), "connections": e["connections"], "sample_event_id": e["event"]}, 1)
        if self.max_hops >= 2:
            for h in hosts:
                for u2, s in self.host_sessions.get(h, {}).items():
                    if u2 in users or u2 in self.excluded:
                        continue
                    for h2, e in self.user_hosts.get(u2, {}).items():
                        if h2 not in hosts:
                            add(h2, "low", "HasSession->CanLogon", f"credentials of {u2} exposed on {h}",
                                {"session_logons": s["logons"], "logons": e["logons"], "sample_event_id": e["event"]}, 2)
        ranked = sorted(cands.values(), key=lambda c: (-CONF_RANK[c["confidence"]], -c["criticality"], c["asset"]))
        status = "evidenced" if ranked else "unknown"
        assumptions = []
        if not known_users:
            assumptions.append("no successful-logon telemetry for the compromised accounts; next hop unknown")
        if not any(e["admin"] for u in known_users for e in self.user_hosts[u].values()):
            assumptions.append("no admin-privilege (4672) events seen; access shown is logon ability, not admin")
        return {"status": status, "total_candidates": len(ranked), "reachable": ranked[: self.max_results],
                "assumptions": assumptions}
