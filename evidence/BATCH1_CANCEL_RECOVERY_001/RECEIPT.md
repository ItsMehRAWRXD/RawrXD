# BATCH1_CANCEL_RECOVERY_001 RECEIPT

ASOF_UTC=2026-11-03T07:05:00Z
EXE=F:\rawrxd\build_modelroute\bin\Release\RawrXD-Win32IDE-Native.exe
LAST_HARNESS_SHA256=74678E5AB75D3BEAA952D1A0EE8EFD3370B6B6678711EF0D0F95DA3DAE754BAB
SEAL_AUTHORITY_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
SEAL_AUTHORITY_TOUCHED=0
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
TIP_CLIMB=HOLD
RUNTIME_REACHED=1
DISPOSITION=FAIL_CLOSED_CRASH_ON_REQUEST_A
STOP_REASON=Last harness on SHA 74678E5A… crashed on Request A (comctl32 AV). Crash fix landed in tip source (TabCtrl reentrancy fence + no LBS_NOTIFY + prior thought-timer/RichEdit mitigations). Post-fix tip rebuild did not complete in-session; harness NOT re-run. NOT_RUN!=PASS for cancel gates after fix.

## Gates 04-08 (fail-closed — last runtime evidence)

| Gate | Feature | Result | Evidence |
| ---- | ------- | ------ | -------- |
| 04 | Worker cancellation signal | FAIL | Stop never clicked; process crashed on Request A |
| 05 | Worker cancellation cleanup | FAIL | Cancel/cleanup path not reached at runtime |
| 06 | Inference-running flag reset | FAIL | No observable clear within 5s (no Stop/B) |
| 07 | Request B admission after Stop | FAIL | Request B not sent |
| 08 | Request B response rendering | FAIL | No Request B response |

## Source path

- Cancelable Ollama HTTP: SOURCE_WIRED (see SOURCE_CANCEL_PATH.md / SOURCE_FIX_RECEIPT.md).
- Request A comctl32 crash: SOURCE_WIRED fix (see CRASH_ROOT_CAUSE.md). RUNTIME_PROVEN=0 until harness re-run on named post-fix tip SHA.

`SOURCE_WIRED != RUNTIME_REACHED != PASS`.

## Harness class

`CancelRecov010` in `harness_cancel_recovery.ps1` (007/008 mismatch already resolved).

## Assert (not satisfied)

m_inferenceRunning cleared OR Request B accepted within ≤5s after Stop — **not observed** (crash before Stop on last run; fix not runtime-proven).

FAIL_CLOSED_LAW=NOT_RUN!=PASS
RUNLOG=F:\rawrxd\evidence\BATCH1_CANCEL_RECOVERY_001\CANCEL_RECOVERY_RUNLOG.txt
