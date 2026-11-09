# INPUT_EVENT_DISPATCH

ASOF_UTC=2026-11-09T17:26:36Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED

## Verdict

`INPUT_EVENT_DISPATCH=FAIL` on tip package `tip_input_event_dispatch_001`.

Sealed HWND tip `30B9BA78â€¦` lacked `INPUT_EVENT` journal strings â†’ rebuild required.
This receipt binds the **rebuilt** EXE SHA, not cross-inherited CC79 / 30B9 AIM PASS.

| Check | Result |
|-------|--------|
| BUTTON_ONE_DISPATCH_PER_CLICK | FAIL |
| CTRL_ENTER_ONE_DISPATCH | FAIL |
| ENTER_INSERTS_NEWLINE | PASS |
| HELD_KEY_NO_UNINTENDED_REPEAT_SEND | FAIL |

## Bind

- TIP_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
- SESSION_ID=integ_p2_ied_20261109-122536
- RUN_ID=integ_p2_ied_run_20261109-122536
- DISPATCH_ID_SEQUENCE=1,1,1,1,2,2,2,2,3,3,3,3
- DISPATCH_ID_RESTART_CLASS=MONOTONIC_WITHIN_SESSION_RUN
- EXACTLY_ONCE_DELIVERY=NOT_VERIFIED

## Per-event map

- event=ENTER_NEWLINE path=AIM_GETMESSAGE_WM_KEYDOWN input=SendInput_VK_RETURN dispatch_id=NONE outcome=NO_SEND journal_events=1
- event=HELD_CTRL_ENTER path=AIM_GETMESSAGE_WM_KEYDOWN input=SendInput_HELD_CTRL_RETURN_OS_REPEAT dispatch_id=1 outcome=CANCELLED_OR_INTERRUPTED ctrl_enter=0 suppressed=0 attempts=1
- event=BUTTON_CLICK path=WM_COMMAND_BN_CLICKED input=SendMessage_WM_COMMAND_1204 dispatch_id=2 outcome=CANCELLED_OR_INTERRUPTED journal_button=0 attempts=1
- event=CTRL_ENTER path=AIM_GETMESSAGE_WM_KEYDOWN input=SendInput_CTRL_RETURN dispatch_id=3 outcome=CANCELLED_OR_INTERRUPTED journal_ctrl_enter=0 attempts=1

## Evidence

- Runtime: `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001\ied_p2_20261109-122536\chat_runtime.log`
- Runlog: `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\input_event_dispatch_run_20261109-122606.txt`
- Receipt: `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\INPUT_EVENT_DISPATCH_RECEIPT.txt`
- Harness: `harness\input_event_dispatch_measure.ps1`

Proof source = `INPUT_EVENT` + `CHAT_SEND_*` journal (Win32 path tags). Model replies are forbidden as probe evidence.
