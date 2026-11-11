# INTEG_CANDIDATE_001_P2_DISPOSITION

ASOF_UTC=2026-11-09T17:36:00Z
CANDIDATE=tip_integ_candidate_001
BINARY_SHA_PREFIX=1046C2B8
BINARY_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
FREEZE=RELEASE_SCOPE_FREEZE.md

## Law

```
JOURNAL_AUTHORITATIVE_FOR_INPUT_EVENT=1
INCOMPLETE_HARNESS_SLICE ≠ RUNTIME_FAILURE
JOURNAL_LINE_ALONE ≠ E2E_DISPATCH_PASS
NO_CROSS_SHA_PASS_INHERITANCE=1
P1_PASS_ON_1046C2B8 ≠ INTEGRATED_ACCEPTANCE
```

## Current disposition (controlling)

```
P1=PASS
P2=FAIL_CLOSED
INPUT_EVENT=AWAITING_JOURNAL_VERIFICATION
EXACTLY_ONCE=PASS_PREVIOUS_SCOPE
OPEN_EDIT_SAVE=NOT_YET_REMEASURED
T05_CANCEL_RECOVERY=NOT_YET_REMEASURED
CHAT_ONE_DISPATCH=HUNG
ISSUE49=FAIL_CLOSED_PARTIAL_STEPS
ISSUE49_LAST_MEASURED=2/11
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
```

## Verification sequence (same SHA unless source repair forces rebuild)

1. **INPUT_EVENT** — From chat_runtime journal extract timestamp, event type, request_id, dispatch_id, result. Confirm Ctrl+Enter, Send-button, hold separately. Correlate request → execution → response when claiming E2E.
2. **Open/edit/save** — Open real file, modify, save, reopen, byte-compare persisted content.
3. **T05 cancel** — Start active request, cancel, verify termination, reject late responses, next request succeeds.
4. **Evidence reconciliation** — Bind each receipt to EXE SHA-256, source commit, freeze lineage.
5. **Gate update** — Mark PASS only when that gate’s own criteria are demonstrated.

Rebuild only if a source repair is necessary; if SHA changes, remeasure P1 — do not carry 1046C2B8 PASS forward.
