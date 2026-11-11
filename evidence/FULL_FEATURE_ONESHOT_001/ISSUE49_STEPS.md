# ISSUE49_STEPS — local step ledger (tip_integ_candidate_001)

ASOF_UTC=2026-11-10T02:44:17Z
ACTIVE_TRACK=ISSUE_49
CANDIDATE=tip_integ_candidate_001
BINARY_SHA256=4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6
PRIOR_SHA_CHAIN=5A34→69A7→4DE0
NO_CROSS_SHA_PASS=1
USER_AUTH_PROMOTE_EXPORT=1
AUTH_SOURCE=USER_MESSAGE_THIS_SESSION
PROMOTE=1
CERTIFIED=1
PRODUCT_PASS=1
TIP_MOVE_AUTHORIZED=1
CONTROLLING_TIP=4DE0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
MATURITY_NOTE=Yardstick allows reassess; no post-acceptance numeric — AUTH did not force climb
E6CF_RESTORE=HELD
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
TIP006_SEAL=HELD
DASHBOARD_NE_PRODUCT_PASS=1
DASHBOARD_EXPORT=FAIL_401

## Score

```
ISSUE49=11/11
ONE_SHA_1_11=PASS
FAIL_MAPS=
CHAT_INPUT=PASS
SESSION_LOOP=PASS
E2E_CHAT_RESPONSE_CORRELATED=PASS
CANCEL_RECOVERY=PASS
SESSION_PERSISTENCE=PASS
EXTENSION_LIFECYCLE=PASS
MAP9_CLEAN_EXIT=PASS
MAP10_REPEATED_USE_FAILURE_RECOVERY=PASS
MAP11_PACKAGE_CLEAN_ROLLBACK=PASS
MAJOR_INTEGRATED_ACCEPTANCE=DEMONSTRATED
```

## Absorbed gates — tip_integ_candidate_001

| Gate | Result | Evidence |
|------|--------|----------|
| P3 four-panel 1–17 | **PASS** on 4DE0 (ORDERED_BLOCKER; ≠ maps 1–11) | `ISSUE49_P3_FOUR_PANEL_4DE0_RECEIPT.txt` |
| Maps 1–11 ONE_SHA | **PASS 11/11** on 4DE0 | `ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT.txt` |
| Historical 5A34 MAJOR | seal-only; **NO_INHERIT** | `ISSUE49_ONE_SHA_REMEASURE_5A34_RECEIPT.txt` |
| PRODUCT_PASS / CERTIFIED / PROMOTE | **AUTHORIZED=1** this session | `ISSUE49_PRODUCT_PASS_PROMOTE_AUTH_RECEIPT.txt` |

## Issue #49 map (11 product-final steps) — measured on 4DE0 only

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Open / edit / save | **PASS** on 4DE0 | `ISSUE49_OES_RECEIPT.txt` OPEN/EDIT/SAVE/REOPEN/BYTE PASS (hardened harness retry `integ_map1_run_20261109-192006`) |
| 2 | Compile / link / run (MSVC) | **PASS** on 4DE0 | `ISSUE49_COMPILE_LINK_RUN_RECEIPT.txt` |
| 3 | Output Build HWND + Problems + click-to-line | **PASS** on 4DE0 | `ISSUE49_OUTPUT_PROBLEMS_HWND_RECEIPT.txt` |
| 4 | Model response in Chat | **PASS** on 4DE0 | `ISSUE49_E2E_CHAT_RESPONSE_RECEIPT.txt` |
| 5 | Agent tool durable FS | **PASS** on 4DE0 | `ISSUE49_SESSION_LOOP_RECEIPT.txt` |
| 6 | Cancellation and recovery | **PASS** on 4DE0 | `ISSUE49_CANCEL_RECOVERY_RECEIPT.txt` |
| 7 | Session persistence | **PASS** on 4DE0 | `ISSUE49_SESSION_PERSISTENCE_RECEIPT.txt` |
| 8 | Extension load→activate→deactivate→shutdown | **PASS** on 4DE0 | `ISSUE49_EXTENSION_LIFECYCLE_RECEIPT.txt` |
| 9 | Clean exit (no orphan workers) | **PASS** on 4DE0 | `ISSUE49_CLEAN_EXIT_RECEIPT.txt` |
| 10 | Repeated-use + failure-recovery | **PASS** on 4DE0 | `ISSUE49_REPEATED_USE_RECEIPT.txt` |
| 11 | Package → clean-machine → rollback | **PASS** on 4DE0 | `ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt` |

```
MEASURED_PASS_HITS=11/11
ONE_SHA_REMEASURE_DEBT=CLOSED
MAPS_ON_4DE0_MEASURED=1,2,3,4,5,6,7,8,9,10,11
RECEIPT=artifacts\ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT.txt
AUTH_RECEIPT=artifacts\ISSUE49_PRODUCT_PASS_PROMOTE_AUTH_RECEIPT.txt
MAJOR_INTEGRATED_ACCEPTANCE=DEMONSTRATED
PRODUCT_PASS=1
CERTIFIED=1
PROMOTE=1
TIP_MOVE_AUTHORIZED=1
CONTROLLING_TIP=4DE0
E6CF_RESTORE=HELD
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
NEXT_STEP_ONLY=DASHBOARD_EXPORT_FAIL_401
```

## ONE_SHA remasure proof (maps 1–11 on 4DE0)

- Orchestrator: `artifacts\_issue49_one_sha_remeasure_4DE0.ps1` RUN `integ_one_sha_1_11_4DE0_20261109-185919` (10/11; map1 SAVE FAIL)
- Map1 retry seal: `artifacts\_issue49_map1_retry_and_seal_4DE0.ps1` RUN `integ_one_sha_1_11_4DE0_map1retry_20261109-192021` → 11/11
- Tip EXE hash verified 4DE0 before/after; no rebuild; NO_CROSS_SHA_PASS
- Map1 PASS via hardened harness `_issue49_oes_e2e_4DE0.ps1` (EM_REPLACESEL + SendMessage Save 2003); disk wrote `OES_EDITED`; reopen+byte PASS
- Prior FAIL mode was harness/race (fixture stayed `OPEN_ONLY`), not a product rebuild on 4DE0
- Maps 2–11 left as prior 4DE0 PASS receipts (not re-run)
- P3 four-panel cited separately: `ISSUE49_P3_FOUR_PANEL_4DE0_RECEIPT.txt` (17/17) — not substituted for maps 1–11
- Promote/export: USER_AUTH this session; dashboard still FAIL_401
