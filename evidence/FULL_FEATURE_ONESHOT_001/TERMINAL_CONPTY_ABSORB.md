# TERMINAL_CONPTY_ABSORB — cross-tree note

ASOF_UTC=2026-11-09T09:48:00Z
PROMOTE=0
INVENT_PASS=0

## Earned on G:\~dev (FOUR_PANEL_COMPLETION_001)

```
TERMINAL=PASS
FIX=CREATE_SUSPENDED → close PTY-side pipes → ResumeThread
     + STARTF_USESTDHANDLES null + UpdateProcThreadAttribute(hPC)
HARNESS_SHA=5125CFE10FE6C89F649B401A216EA976BC44DB06D44D1EA401E41411D579094D
EVIDENCE=G:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001\TERMINAL_GATE.md
WORKER=aa7a38b9-ad39-4a2c-9e1f-41036b96eeec
748B_UNTOUCHED=1
```

## F:\rawrxd product source

`F:\rawrxd\src\win32app\Win32TerminalManager.cpp` already contains `CREATE_SUSPENDED` / `ResumeThread` sequence (string present).

```
ONESHOT_TERMINAL_GATE_PRIOR=FAIL_CLOSED (pre-fix harness VT-only)
ONESHOT_TERMINAL_RETEST_ON_F=PENDING (must re-run capture harness against F sources/tip — no cross-SHA invent PASS)
```

## Next

1. Candidate IDE relink with `-DRAWRXD_BUILD_WIN32IDE=ON` (G p1-candidate) — resumed worker
2. Re-run F oneshot `terminal_conpty_capture` / gate → update `TERMINAL_GATE.md` only if marker∈pipe earned on F tip SHA
3. HWND Output/Problems/Debug/Integration still FAIL_CLOSED until candidate EXE exists
