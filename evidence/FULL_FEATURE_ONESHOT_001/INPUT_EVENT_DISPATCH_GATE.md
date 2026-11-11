# INPUT_EVENT_DISPATCH_GATE

ASOF_UTC=2026-11-09T13:48:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
NO_CROSS_SHA_PASS_INHERITANCE=1
CC79_UNREPLACED=1

```
GATE=INPUT_EVENT_DISPATCH
STATUS=PASS
TIP_SHA=C43B01ABE886700B7A085C570575CCB9DED63A140000380ADCBE07ADEF33A629
TIP_PACKAGE=CHAT_C43B_INPUT_EVENT_READY
ABSORB=CHAT_C43B_INPUT_EVENT_READY.md
SESSION_ID=ied_sess_20261109-084440
INPUT_EVENT_DISPATCH=PASS
ENTER_NEWLINE=PASS
HOLD_NO_DUP=1
PRIOR_MEASURED_TIP_SHA=2B1D36BA53CF5873ED8700F158875E2CF3CFC48B1AC48E39B6ED5D312D2E9925
PRIOR_HWND_TIP_SHA=30B9BA7899FB8C7D4A0AAE3B1B81883B5C7DBA2606CFA28396A3517273BFC393
MODEL_RESPONSE_AS_PROBE_EVIDENCE=FORBIDDEN
TRANSCRIPT_SUPPORTS_DELIVERY_ONLY=1
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
NEXT=clean matrix without inter-probe cancel (owner 9643a336)
```

## Pass criteria (all required on one EXE SHA + session_id)

1. Instrument **actual** button and keyboard events (not model-echo of probe labels).
2. Prove **one dispatch per** Send-button click.
3. Prove **one dispatch per** Ctrl+Enter.
4. Prove bare **Enter inserts newline** (no send).
5. Prove **held keys** produce no unintended repeat sends.
6. Receipt binds: full EXE SHA256, session_id, run_id, per-event dispatch_id map, input-event source (WM_*/SendInput/AIM path).

## Measured (this run)

| Check | Result | Win32 path | dispatch_id |
|-------|--------|------------|-------------|
| ENTER_INSERTS_NEWLINE | PASS | AIM_GETMESSAGE_WM_KEYDOWN + SendInput VK_RETURN | NONE |
| HELD_KEY_NO_UNINTENDED_REPEAT_SEND | PASS | AIM_GETMESSAGE_WM_KEYDOWN + SendInput held Ctrl+Enter | 1 |
| BUTTON_ONE_DISPATCH_PER_CLICK | PASS | WM_COMMAND_BN_CLICKED | 2 |
| CTRL_ENTER_ONE_DISPATCH | PASS | AIM_GETMESSAGE_WM_KEYDOWN + SendInput Ctrl+Enter | 3 |

No-response rows classified **CANCELLED_OR_INTERRUPTED** (Stop between probes). Proof = `INPUT_EVENT` + `CHAT_SEND_*` journal, not model text.

Sealed HWND tip `30B9BA78…` lacked `INPUT_EVENT` strings → rebuild into `tip_input_event_dispatch_001` (no overwrite of tip_hwnd / A4F / CC79).

```
MODEL_REPLY ≠ UI_EVENT_PASS
DISPATCH_ID_RESTART_WITHOUT_SESSION_ID = AMBIGUOUS
EXACTLY_ONCE_DELIVERY = NOT_VERIFIED until this gate + multi-send cert
PROMOTE=0
```
