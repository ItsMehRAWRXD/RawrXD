# ORDERED_BLOCKER_LIST — smallest set unlocking integrated workflow

ASOF_UTC=2026-11-10T02:44:17Z
USER_AUTH_PROMOTE_EXPORT=1
AUTH_SOURCE=USER_MESSAGE_THIS_SESSION
PROMOTE=1
CERTIFIED=1
PRODUCT_PASS=1
TIP_MOVE_AUTHORIZED=1
CONTROLLING_TIP=4DE0
MATURITY=82_UNCHANGED
MATURITY_NOTE=Yardstick allows reassess; no post-acceptance numeric — AUTH did not force climb
CONTROLLING_TIP_SHA=4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6
SHA_SUPERSEDED=69A7654A546182F554A7975F81D347EB293C31809E7366831A116A06F170310E
PRIOR_SHA_CHAIN=5A34→69A7→4DE0
CANDIDATE=tip_integ_candidate_001
SOURCE=ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT + ISSUE49_P3_FOUR_PANEL_4DE0_RECEIPT + ISSUE49_PRODUCT_PASS_PROMOTE_AUTH_RECEIPT
MAJOR_INTEGRATED_ACCEPTANCE=DEMONSTRATED_ON_4DE0
ISSUE49=11/11_ON_4DE0
ONE_SHA_1_11=PASS
CC79_SEAL_UNREPLACED=1
A4F_IMMUTABLE=1
TIP006_SEAL=HELD
E6CF_RESTORE=HELD
DASHBOARD_EXPORT=FAIL_401

Priority = dependency order for **one candidate SHA**. Symptoms below parents are not separate first repairs.

| Pri | Blocker | Status on tip | Evidence | Unlocks |
|-----|---------|---------------|----------|---------|
| P0 | **One candidate EXE** | **CLOSED** on 4DE0 (SHA verify + ONE_SHA 11/11) | tip_integ_candidate_001 @ 4DE0; ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT.txt | All later gates |
| P1 | **Output Build HWND + Problems + click-to-line** | **PASS on 4DE0** | MAP3 — ISSUE49_OUTPUT_PROBLEMS_HWND_RECEIPT.txt | Compile/nav chain |
| P1 | **PowerShell panel routing** | **ABSORBED** | INTEG_CANDIDATE_001_PS_RECEIPT | Terminal/PS leg |
| P1 | **VS_UNICODE_OUTPUT / Problems env scrub** (H27) | **ABSORBED** | Problems HWND live on 4DE0 MAP3 | Stable Problems |
| P2 | **Chat input events + session_id bind** | **PASS on 4DE0** | MAP4 | Model response leg |
| P2 | **AgentSession ownership + cancel** (H57) | **PASS on 4DE0** | MAP5+MAP6 | Tool action + cancel/recovery |
| P2 | **ExtensionHost cleanup FORCE_KILL=0** (H51) | **PASS on 4DE0** | MAP8+MAP9 | Ext shutdown + clean exit |
| P3 | **Debugger UI keep-alive** (S10) | **PASS on 4DE0** | ISSUE49_P3_FOUR_PANEL_4DE0_RECEIPT.txt S10=PASS | Four-panel conjunction |
| P3 | **Four-panel conjunction** Ext+Chat+Term+Output(+Debug) | **PASS on 4DE0** (17/17) | harness four_panel_1_17_measure.ps1; S11 WFDE real receipt | PRODUCT_PASS leg |
| P4 | **Issue #49 product-final E2E (11-step maps)** | **CLOSED_MAJOR_ON_4DE0** | ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT.txt 11/11 | Maturity reassess allowed; numeric not specified |
| P5 | **Package + clean-machine + rollback** | **CLOSED_ON_4DE0** | ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt (in ONE_SHA) | Delivery seal |
| P6 | **PRODUCT_PASS / CERTIFIED / PROMOTE** | **AUTHORIZED=1** | ISSUE49_PRODUCT_PASS_PROMOTE_AUTH_RECEIPT.txt | Product-final tip 4DE0 |
| P7 | **Freeze Control dashboard export** | **FAIL_401** | GET/POST root+api endpoints 401; no API key | Dashboard import of MASTER + ISSUE49 |

## Explicitly NOT first-line

- H01/H04 CMake/feature-flag inventory — fold into P0 candidate link map, don't solo-chase
- H87 GPU device-loss specialty — not on daily-driver chain unless model path requires
- H113 stub backends — only if selected on candidate product path
- 120 INVESTIGATE / 56 UNVERIFIED — no arithmetic; chase only if a P0–P3 gate fails
- Parallel tip packages (30B9, 2B1D, C43B, tip006, 1046, B39, 27E2, 5A34) — absorb, don't remeasure all
- E6CF restore — held; no invent restore

## Next engineering gap (sole open after AUTH)

```
NEXT=DASHBOARD_EXPORT_FAIL_401
P3_FOUR_PANEL=PASS
FOUR_PANEL_INTEGRATION=PASS
S10=PASS
S11=PASS
ONE_SHA_1_11=PASS
MAJOR_INTEGRATED_ACCEPTANCE=DEMONSTRATED_ON_4DE0
P3_RECEIPT=artifacts\ISSUE49_P3_FOUR_PANEL_4DE0_RECEIPT.txt
ONE_SHA_RECEIPT=artifacts\ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT.txt
AUTH_RECEIPT=artifacts\ISSUE49_PRODUCT_PASS_PROMOTE_AUTH_RECEIPT.txt
NO_CROSS_SHA_PASS=1
PROMOTE=1
PRODUCT_PASS=1
CERTIFIED=1
TIP_MOVE_AUTHORIZED=1
CONTROLLING_TIP=4DE0
MATURITY=82_UNCHANGED
E6CF_RESTORE=HELD
DASHBOARD_EXPORT=FAIL_401
```

## Law

```
INVESTIGATE ≠ CONFIRMED
PARTIAL_TIP_PASS ≠ INTEGRATED_PASS
MAJOR_INTEGRATED_ACCEPTANCE ≠ PRODUCT_PASS ≠ PROMOTE
P3_FOUR_PANEL_PASS ≠ PRODUCT_PASS ≠ PROMOTE
USER_AUTH_MAY_FLIP_HELD_GATES=1
100% = AGREED_GATES_ON_FINAL_SHA
PROMOTE_AND_CERT_SEPARATE=1
NOT_RUN ≠ PASS
DASHBOARD_FAIL ≠ LOCAL_LEDGER_ABSENCE
```
