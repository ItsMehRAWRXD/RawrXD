# Issue #49 — IDE exit(-1) while holding deep2_agentic_loop

```
ASOF_UTC=2026-11-09T20:11:21Z
PIN_SHA=35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563
MEASURE_EXE=RXD_PIN_A190_35C22.exe
A190_OVERWRITE=0
```

## Observed

- Prior harness: SESSION_LOOP partial; IDE often ExitCode=-1; loop sometimes died early when stdout/stderr redirected.
- MULTI_TAB_EXIT_RECEIPT (F017 era): WM_CLOSE / prepareForExit path still yields process ExitCode=-1 (not PostQuitMessage(0)).
- Product note: prepareForExit exists in Win32IDE_lifecycle.cpp; orderly exit-0 not sealed on pin for close path.

## Harness-only mitigations that worked (v2)

```
HARNESS=artifacts\issue49_session_hold_v2.ps1
FIX=
  - no RedirectStandardOutput/Error (keeps Process handle honest)
  - isolated loop workdir (avoids IDE/log contention)
  - IDE first, Minimized; no WM_CLOSE during hold
  - RAWRXD_GHOSTTEXT_TEST_DELAY_* = 600000
RESULT=
  SESSION_LOOP=PASS_BOTH_ALIVE_WINDOW
  MAX_BOTH_ALIVE_S=118
  COEXIST_BROKEN=0
  IDE_EXIT_CODE=na (alive through window)
  LOOP_EXIT_CODE=1 (after session; no semantic edit)
```

## Still open

- Semantic agent edit + build recovery (loop exit 1 / CPU prefill incomplete).
- Product orderly ExitCode=0 on WM_CLOSE held (out of scope for pin-byte freeze; harness avoids closing during hold).
- PROMOTE=0 · CERTIFIED=0 · FREEZE001=PASS ≠ ISSUE49 11/11
