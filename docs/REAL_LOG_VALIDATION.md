# Local real-file validation — 1 November 2026

This report describes the saved `my-demo-fixed2` run and a read-only investigation
of incident 1. The filename is `firex-30G.log`; actual source size and quality,
not the filename, define the benchmark.

## Input and runtime

| Property | Saved measurement |
|---|---:|
| Source bytes | 19,621,285,387 |
| Valid normalized events | 6,828,021 |
| Reader-quarantined bytes | 15,326,318,664 |
| Reader-rejected physical records | 1 |
| Additional normalized quarantined rows | 2 |
| Incidents | 1,385 |
| Total wall time | 478.298 seconds |
| Read | 251.863 seconds |
| Detect | 66.204 seconds |
| Map | 3.989 seconds |
| Correlate | 36.543 seconds |
| Materialize, including graphs and lookahead | 108.246 seconds |

Stage sums exclude setup. Approximately 78% of source bytes were quarantined.
Sampled regions at the failing boundary, 8 GiB, 12 GiB and near EOF were
zero-filled. Do not report this as a healthy 30 GB telemetry throughput test or
as evidence of real-data precision/recall. Verify the downloaded file against
its origin; quarantine cannot reconstruct missing source content.

## Why incident 1 has zero reachable candidates

The localhost browser API returned the same lookahead as the saved incident
JSON. Incident 1 has no account identities and one host. For that host within
the configured evidence window and incident cutoff:

- 3,940 normalized events; 3,762 network flows.
- Zero allowed/unknown-outcome administrative-port flows.
- Zero eligible observed-access network edges.

Across the accepted dataset, there are zero successful logons with an account
identity and zero account-linked Windows 4672 events. There are 589 allowed or
unknown-outcome administrative-port flows globally, but none satisfy the
resolved distinct-host edge requirements used by the current access graph.
All saved incidents have zero lookahead candidates in this run. A firewall
contact alone does not establish account authorization or a lateral-access path.

**Decision:** keep evidence and cutoff requirements. Do not invent reachable
assets or relax graph semantics to fill the demo panel. Endpoint/authentication
telemetry or qualifying internal access observations are required for additional
supported paths. A labeled planted case can demonstrate the feature separately;
it must be identified as controlled demo data.

## AI triage diagnosis

The API reported a configured key and model `glm5.3`. Earlier failures returned a
generic combined message and did not retain a detailed cause, so their exact
cause cannot be established retrospectively.

One diagnostic retry returned `finish_reason=stop`, 2,875 completion tokens
(1,722 reasoning tokens) and schema-valid, supported citations. It was saved
with no errors and an `insufficient_evidence` assessment. `NEEDS_REVIEW` is an
expected uncertainty outcome, not proof the provider was unavailable.

Triage previously capped output at 4,096 despite the configured service budget.
It now honors `SARVAM_MAX_TOKENS`, includes that budget in the cache identity,
and differentiates HTTP, network, incomplete-output, schema and citation errors.
Validation remains strict; transient failures are not cached and no model
response automatically changes case status. Raw provider error bodies and
credentials are not echoed in error messages.

Source: saved `run_metrics.json`, incident JSON, read-only queries against the
run's `work/trace.duckdb`, localhost API responses and bounded live triage
response metadata. No raw logs or credentials are published with this report.
