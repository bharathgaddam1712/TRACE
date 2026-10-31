# Data contract (Stage 0)

Derived from `data/sample/edr_events.json` (8.4 MB, 10,000 rows) on 31 Oct 2026. Re-check every point
when the 100 MB dev sample and the full tiers arrive. Anything not listed here is not assumed.

## Format
- Newline-delimited JSON, one ECS-style event per line, UTF-8, no compression in the sample.
  The ingest stage also accepts `.ndjson`, `.jsonl` and gzip.
- Producer: `observer.product = SimEDR` (vendor Mitigata), `event.module = edr`.
- 0 malformed lines, 0 duplicate `event.id`.

## Fields present (row counts out of 10,000)
| Field | Rows | Notes |
|---|---|---|
| `@timestamp` | 10,000 | ISO-8601 UTC with ms, monotonic in file order |
| `event.id` | 10,000 | UUID, used as the stable event id |
| `event.kind` | 10,000 | `event` 9,495 / `alert` 505 |
| `event.action` | 10,000 | process_created 2,967, network_connection 2,480, dns_query 1,902, file_modified 1,189, user_logon 863, registry_value_set 488, file_rename 111 |
| `event.outcome` | 863 | logons only: success 715 / failure 148 |
| `host.name`, `host.ip[]` | 10,000 | 28 hosts: WS-{FIN,HR,ENG,SALES}-010..015, SRV-{DC,FILE,DB,WEB}-01; one IP per host (10.10.x.y); used for IP -> host resolution |
| `user.name`, `user.domain` | 10,000 | 12 accounts incl. `svc_backup`, `svc_sql`; domain `CORP` |
| `process.*` | 9,137 | name/pid everywhere, command line + parent + hashes on process_created |
| `source.*`, `destination.*`, `network.*` | 2,480–3,343 | outbound connections with bytes and destination domain |
| `winlog.event_id`, `winlog.logon.type` | 863 | 4624 / 4625; Network, RemoteInteractive, Interactive |
| `registry.path`, `registry.data.strings` | 488 | |
| `file.path`, `file.extension` | 1,300 / 111 | |
| `threat.technique.id[]`, `threat.tactic.name[]`, `rule.*` | 505 | alerts only; ATT&CK labels |
| `labels.simulated_detection` | 505 | `"true"` on every alert row |
| `labels_extra.failed_count_5min`, `labels_extra.files_renamed_60s` | 98 / 111 | pre-aggregated counts on alert rows |

## Labelled alerts (possible ground truth)
| rule.id | Name | Technique | Tactic | Rows |
|---|---|---|---|---|
| 8476ceb0 | Rapid mass file rename to uniform extension | T1486 | Impact | 111 |
| 1581c4a4 | Autorun key created by scripting engine | T1547.001 | Persistence | 101 |
| 5cb93fae | Office application spawned a scripting engine | T1059.001 | Execution | 100 |
| ccb7b967 | High rate of failed logons from single source | T1110 | Credential Access | 98 |
| 34eb26ba | Beaconing to low-reputation destination | T1071.001 | Command and Control | 95 |

Observations that drive the design:
1. **Label convention.** The sample uses the parent ID `T1110` for brute force and sub-techniques
   elsewhere, so the TRACE rules emit the same IDs. The scorer reports strict and parent-level accuracy.
2. **Stage taxonomy.** The sample's tactic names are ATT&CK tactics, so `kill_chain_stage` = ATT&CK tactic.
   The Lockheed phase is emitted as an extra field.
3. **No chains in the sample.** The alerts are scattered at random over users and hosts. On WS-FIN-011,
   ransomware fires before the macro, and no process ID links one alert to another. The sample therefore
   cannot test path reconstruction, which is why `tracekc plant` / `gen-scale` exist.
4. **Degenerate time span.** All 10,000 rows fall within 0.33 seconds, so time windows,
   recurrence and first-seen logic have nothing to work with on this sample alone.
5. **Malicious behaviour only on alert rows.** No `kind=event` row touches the attacker IPs
   (192.0.2.88, 198.51.100.23, 203.0.113.57). Brute force appears as one pre-aggregated row per burst,
   not 20+ raw failures. TRACE handles both shapes.
6. **TRACE's Sigma rules re-detect all 505 alerts** from raw fields, with zero extra matches, when vendor
   alerts are switched off (`tests/test_pipeline.py::test_sigma_rules_reproduce_every_labelled_sample_alert`).

## Still unknown until the full data arrives
- Whether the tiers contain other sources (firewall, proxy, AD) and in which format.
- The ground-truth file format, and whether planted steps are the labelled alert rows or separate chains.
- Real time span and noise density. These set `session_gap_s` and the recurrence buckets.
- Admin or group-membership telemetry (4672 / 4728 / 4732). Without it, look-ahead reports logon ability, not admin rights.
