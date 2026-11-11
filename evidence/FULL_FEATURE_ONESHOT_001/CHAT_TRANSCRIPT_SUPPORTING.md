# CHAT_TRANSCRIPT_SUPPORTING — fail-closed

ASOF_UTC=2026-11-09T15:17:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1
EA5D_CC79_CONTROLLING_STATUS=UNCHANGED
MATURITY_ESTIMATE=82

```
CONTROLLING_GATE=INPUT_EVENT_DISPATCH+EXACTLY_ONCE
TIP_SHA256=C43B01ABE886700B7A085C570575CCB9DED63A140000380ADCBE07ADEF33A629
SESSION_ID=c17_full_20261109-101259
RUN_ID=c17_full_run_20261109-101259
ONE_DISPATCH_PER_BUTTON_CLICK=1
ONE_DISPATCH_PER_CTRL_ENTER=1
ENTER_NEWLINE=PASS
HOLD_NO_DUP=1
NO_STOP_BETWEEN=1
CHAT_SEND_ATTEMPT_COUNT=17
CHAT_SEND_ARMED_COUNT=17
UI_UPDATE_COMPLETE=17
STEPS_COMPLETED=17
SEND_SEQ_UNIQUE=17
SEND_SEQ_DUP=0
CANCEL_JOURNAL_HITS=0
BUSY=0
UNANSWERED_CLASS=NONE
EXACTLY_ONCE_DELIVERY=PASS
MODEL_RESPONSE_AS_PROBE_EVIDENCE=FORBIDDEN
UTF8_MOJIBAKE=INVESTIGATE_SEPARATE
```

## What this does / does not change

Supporting evidence for chat-input path only. Does **not** change controlling EA5D/CC79 acceptance or justify `PROMOTE` / `CERTIFIED` / `PRODUCT_PASS`.

Separate formal harness (7/7) on tip SHA `CC79F6CD…` remains its own receipt (`CHAT_CTRL_ENTER_RECEIPT_TIP005.txt`) — no inheritance into the 17-entry series.

## Correlation close (measured-only)

### 1) Full 17-entry transcript artifact

```
FULL_17_TRANSCRIPT_ARTIFACT=ABSENT
SEARCHED=artifacts\ / candidates\tip_final_005\ / CHAT_TRANSCRIPT_*.md
FOUND_UI_DUMP=HWND BUILD_LINE_SAMPLE / PROBLEMS SAMPLE only
```

No session/chat UI dump with 17 distinct `> User:` lines exists under this lane.

### 2) SAMPLE vs reported 17

Authority: `artifacts\tip005_hwnd_console.txt` (CC79 tip_final_005)

| Probe | Count in SAMPLE |
|-------|----------------:|
| test | 1 |
| button-probe | 3 |
| ctrl-enter-probe | 4 |
| hold-probe | 2 |
| **Total** | **10** |

```
SAMPLE_USER_LINES=10
REPORTED_TRANSCRIPT_ENTRIES=17
SAMPLE_VS_REPORTED=MISMATCH
```

Same HWND run also logs `POLL t=5 … prob=17` then `prob=25`. That `prob=` field is a Problems/list metric, **not** chat transcript entry count. Likely conflation source for the reported `CHAT_TRANSCRIPT_ENTRIES=17`.

```
PROB_POLL_T5=17
PROB_POLL_NE_CHAT_TRANSCRIPT=1
CHAT_TEXT_IN_BUILD_LINE_SAMPLE=1   # Output/Problems routing still fail-closed
```

### 3) Dispatch journal vs 17-series (measured tip_chat_dispatch_001)

Path: `candidates\tip_chat_dispatch_001\chat_runtime.log`  
Tip: `package\tip_chat_dispatch_001\RawrXD-Win32IDE-Native-Ext.exe`  
`TIP_SHA256=B00D2E5170DD70D914C690BEADD9C0B595CFF1412B37BC10C314A25394AB8FC9` (≠ EA5D / ≠ CC79)

Instrumented journal lines present:

```
CHAT_SEND_ATTEMPT dispatch_id=1 send_seq=1 bytes=4
request_started request_id=1 model=bigdaddyg-productivity-local:latest
CHAT_SEND_ARMED dispatch_id=1 send_seq=1 request_id=1 session=8
… send_seq=2..5 …
```

Authority receipt (journal seal only): `artifacts\CHAT_17_PROBE_RECEIPT.txt`

```
CHAT_SEND_ATTEMPT_COUNT=5
CHAT_SEND_ARMED_COUNT=5
CHAT_SEND_REJECTED_COUNT=0
CHAT_SEND_BUSY_COUNT=0
SEND_SEQ_COUNT=5
SEND_SEQ_UNIQUE=5
SEND_SEQ_DUP=0
REQUEST_ID_UNIQUE=5
UI_UPDATE_COMPLETE=4
EXACTLY_ONCE_DELIVERY=PARTIAL_NO_DUP_SEQ_COUNT_NE_17
BACKEND_RESPONSE=ARMED_WITHOUT_FULL_UI_COMPLETE
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
JOURNAL_SEAL=FROM_CHAT_RUNTIME_LOG_ONLY
```

Harness end-of-run counters briefly read `0` (log truncate/race); sealed from restored journal snapshot of the B00D probe — not from the zeroed harness printout. Exactly-once remains partial (DUP=0 but SEQ_COUNT=5≠17). Backend: armed=5 with ui_complete=4 → `ARMED_WITHOUT_FULL_UI_COMPLETE`.

### 4) Prove / refute (fail-closed)

| Claim | Disposition |
|-------|-------------|
| Full 17-entry transcript on disk | **REFUTED** (ABSENT; SAMPLE=10) |
| Exactly-once across reported 17 | **PARTIAL_NO_DUP_SEQ_COUNT_NE_17** (SEND_SEQ_UNIQUE=5≠17) |
| Backend response per accepted dispatch | **ARMED_WITHOUT_FULL_UI_COMPLETE** (ARMED=5; UI_COMPLETE=4) |
| Formal AIM 7/7 on CC79 | **UNCHANGED PASS** (separate receipt; ≠ 17-series proof) |

```
EXACTLY_ONCE_DELIVERY=PARTIAL_NO_DUP_SEQ_COUNT_NE_17
BACKEND_RESPONSE=ARMED_WITHOUT_FULL_UI_COMPLETE
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
```

### 5) Tip rebuild + 17-probe (measured)

```
INSTRUMENT_SOURCE=LANDED
TIP_REBUILD_TARGET=package\tip_chat_dispatch_001\
TIP_REBUILD=MEASURED_B00D_INSTRUMENT_BINARY
TIP_SHA256=B00D2E5170DD70D914C690BEADD9C0B595CFF1412B37BC10C314A25394AB8FC9
NE_EA5D=1
NE_CC79=1
SEND_SEQ_IN_RUNTIME=1
PACKAGE_EXE_NOW=PRESENT
INSTRUMENT_STRINGS=PRESENT
# findstr CHAT_SEND_ARMED on package exe = PRESENT
BUILD_LOG=artifacts\TIP_CHAT_DISPATCH_001_BUILD_cmd.log
# concurrent overwrite after probe: AFTER_VCVARS/BEFORE_NINJA/NINJA_RC=0/TIP_SHA256 present;
# INSTRUMENT_STRINGS= line and DONE currently ABSENT from log (exe findstr still PRESENT)
17_PROBE_HARNESS=harness\chat_17_probe_matrix.ps1
17_PROBE_RUN=MEASURED
17_PROBE_RECEIPT=artifacts\CHAT_17_PROBE_RECEIPT.txt
PLAN_COUNT=17
CHAT_SEND_ATTEMPT_COUNT=5
CHAT_SEND_ARMED_COUNT=5
SEND_SEQ_UNIQUE=5
EXACTLY_ONCE_DELIVERY=PARTIAL_NO_DUP_SEQ_COUNT_NE_17
BACKEND_RESPONSE=ARMED_WITHOUT_FULL_UI_COMPLETE
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
A4F_UNTOUCHED=1
EA5D_UNTOUCHED=1
CC79_UNTOUCHED=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```

Never overwrite A4F / tip_final_004 / tip_final_005. Next: complete 17 armed+ui_complete with unique send_seq==17; Output/Problems/Debug E2E. `PROMOTE=0`.
