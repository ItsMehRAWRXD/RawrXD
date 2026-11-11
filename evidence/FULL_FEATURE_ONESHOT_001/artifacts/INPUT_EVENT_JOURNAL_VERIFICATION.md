# INPUT_EVENT_JOURNAL_VERIFICATION

ASOF_UTC=2026-11-09T17:42:12Z
TIP_PACKAGE=tip_integ_candidate_001
TIP_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
TIP_EXE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe
SESSION_ID=integ_p2_ied_20261109-122536
RUN_ID=integ_p2_ied_run_20261109-122536
PRIMARY_JOURNAL=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001\ied_p2_20261109-122536\chat_runtime.log
LEGACY_JOURNAL=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001\ied\chat_runtime.log
SOURCE_COMMIT=23ca021d68062539ddb72b7c8e6ff42194780b84
FREEZE_LINEAGE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\RELEASE_SCOPE_FREEZE.md
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
CC79_UNREPLACED=1
A4F_IMMUTABLE=1

## Law

```
JOURNAL_AUTHORITATIVE_FOR_INPUT_EVENT=1
INCOMPLETE_HARNESS_SLICE != RUNTIME_FAILURE
JOURNAL_LINE_ALONE != E2E_DISPATCH_PASS
EXACTLY_ONCE=PASS_PREVIOUS_SCOPE (no new claim / no reopen as FAIL)
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## Parsed rows (session-bound)

- ROW kind=ENTER_NEWLINE dispatch_id=NONE request_id=NONE result=NEWLINE_NO_SEND line=2
- ROW kind=CTRL_ENTER dispatch_id=1 request_id= result=CANCELLED_ACK req=1 line=3
- ROW kind=BUTTON_CLICK dispatch_id=2 request_id= result=CANCELLED_ACK req=2 line=14
- ROW kind=CTRL_ENTER dispatch_id=3 request_id= result=CANCELLED_ACK req=3 line=24

## One-dispatch gates (journal)

| Check | Result |
|-------|--------|
| ENTER_INSERTS_NEWLINE | PASS |
| HELD_KEY_NO_UNINTENDED_REPEAT_SEND | PASS |
| BUTTON_ONE_DISPATCH_PER_CLICK | PASS |
| CTRL_ENTER_ONE_DISPATCH | PASS |
| INPUT_EVENT_ONE_DISPATCH_GATE | PASS |

## E2E correlation

E2E_REQUEST_EXEC_RESPONSE=NOT_MET_CANCELLED_BEFORE_UI_COMPLETE

This primary session used PostMessage Stop between probes; terminals are CANCELLED_ACK, not UI_COMPLETE. That satisfies INPUT_EVENT+CHAT_SEND_* one-dispatch proof; it does **not** invent full chat E2E response PASS.

## Harness note

Prior `input_event_dispatch_measure.ps1` Slice-New miscount reported FAIL while journal contained CTRL_ENTER / BUTTON_CLICK / CHAT_SEND_ATTEMPT. Classified evidence gap in harness attribution, not runtime absence.

## Companion P2 remounts (same SHA)

| Gate | Result | Receipt |
|------|--------|---------|
| OPEN_EDIT_SAVE | PASS | INTEG_CANDIDATE_001_OES_RECEIPT.txt |
| T05_CANCEL_RECOVERY | PASS | INTEG_CANDIDATE_001_T05_RECEIPT.txt |

## Conjunction

```
P1=PASS (preserved; SHA unchanged)
P2_INPUT_EVENT=PASS
P2_OPEN_EDIT_SAVE=PASS
P2_T05=PASS
P2_CONJUNCTION=PASS
INTEGRATED_P1_P2=PASS
EXACTLY_ONCE_DELIVERY=PASS_PREVIOUS_SCOPE
PROMOTE=0
```
