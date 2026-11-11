# DISPOSITION — BATCH1_CANCEL_RECOVERY_001

```
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
TIP_CLIMB=HOLD
SEAL_AUTHORITY_TOUCHED=0
TESTED_EXE=F:\rawrxd\build_modelroute\bin\Release\RawrXD-Win32IDE-Native.exe
TESTED_SHA256=74678E5AB75D3BEAA952D1A0EE8EFD3370B6B6678711EF0D0F95DA3DAE754BAB
SEAL_AUTHORITY_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB

GATE_04=FAIL
GATE_05=FAIL
GATE_06=FAIL
GATE_07=FAIL
GATE_08=FAIL

CANCEL_HTTP_SOURCE_WIRED=1
RUNTIME_REACHED=1
RUNTIME_PASS=0
NEXT_GATE=STABILIZE_REQUEST_A_THEN_RERUN_CANCEL_RECOVERY
```

## Notes

1. Parent cancel fix is **source-wired** (cancelable WinHTTP + immediate `m_inferenceRunning=false` on Stop).
2. Tip Release rebuild completed; seal `CB34EF4E…` was **not** replaced.
3. Harness launched tip Native, selected Ollama `qwen2.5-coder:1.5b-base`, submitted Request A; process crashed (`unhandled exception; minidump written`) before Stop/Request B.
4. Fail-closed: crash ≠ cancel PASS. Gates 04–08 all **FAIL**.
