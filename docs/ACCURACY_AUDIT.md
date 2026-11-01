# Accuracy investigation — 1 November 2026

This is an investigation of existing saved output, not a new run or an independent accuracy evaluation. Source: local `firex-10G.log` (6,543,120,032 bytes); saved output: `%LOCALAPPDATA%/TRACE/firex-balanced-fresh`.

## Rejected source bytes

The quarantine ledger accounts for 1,727,444,911 bytes in eight coalesced spans, containing 6,722,658 physical fragments. Seven spans start with an unrecognized-record reason (1,711,286,762 bytes); one starts with an invalid-UTF-8 reason (16,158,149 bytes). A span's reason describes its first failure; it does not prove every fragment has that same error.

Start/middle/end sampling of the seven spans yielded 21 windows, 1,376,256 bytes, no valid UTF-8 windows and no FortiGate prefixes. Three sampled windows from the remaining span yielded 196,608 bytes, no valid UTF-8 windows and one FortiGate prefix at the transition. This supports binary corruption in the inspected regions, not an assertion that every rejected byte is harmless noise.

The boundary record is 298 bytes. Its first invalid byte is at offset 273. The intact prefix contains source fields but no destination fields. Accepting it as a complete connection would require inventing missing evidence. Keep the original file and quarantine ledger; do not silently discard or repair these bytes.

**Decision:** no parser acceptance change. Review any newly encountered rejection reason against raw byte offsets before proposing one.

## Vendor promotion

Join saved `signals` with `signal_incident`, group by non-null incident ID, and count sources and distinct core tactics. Own-supported means builtin, Sigma or Sigma correlation; core means severity >= 50 and not recurrent.

| Existing output property | Count |
|---|---:|
| Incidents | 1,940 |
| Incidents containing no own-supported signal | 0 |
| Incidents with more than half their signals vendor-supported | 1,795 |
| Incidents with at least two own-supported core tactics | 1,940 |

Vendor-majority is not vendor-only. A requirement for two own-supported core tactics would retain all 1,940 in this saved output by the SQL eligibility check; this is not a newly executed promotion benchmark.

**Decision:** leave promotion unchanged. There is no independently labeled ground truth for this real file, so these counts do not establish its precision, recall or false-alarm rate. Planted tests establish controlled-case behavior only.
