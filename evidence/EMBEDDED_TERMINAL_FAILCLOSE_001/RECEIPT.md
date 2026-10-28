# EMBEDDED_TERMINAL_FAILCLOSE_001 — receipt

```
ASOF_UTC=2026-10-28T17:12:00Z
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
SOURCE_WIRED=1
RUNTIME_ON_TIP_748B=NOT_IN_TIP (pre-fix binary)
RELINK_REQUIRED=1
CANDIDATE_FREEZE=TIP_FREEZE_CANDIDATE_P1_SURFACE_001
748B_CLOBBER=0
```

## Change

`src/terminal/embedded_terminal.cpp` — refuse success without product ConPTY owner.
Prior Track B v14.7 pipe-as-ConPTY `return true` removed.
Gate: `[EMBEDDED_TERMINAL] FAIL_CLOSED ... OWNER=Win32TerminalManager`.

Product CreatePseudoConsole owner remains `Win32TerminalManager`.
