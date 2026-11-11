# TIP_FIX=NOT_APPLIED — SHA 4ED342CE

ASOF_UTC=2026-11-09T03:22:00Z
ACTIVE_SHA=4ED342CE16BC868681B06AA41C68B1719FE69BD8DA87357160D65EEE6A442885

```
TIP_FIX=NOT_APPLIED
TIP_FIX_JUSTIFIED_BY_STACK=0
OWNERSHIP_LIFETIME_CAUSALITY=NOT_PROVEN
STOP_SPECULATIVE_UI_FIXES=1
REBUILD=NOT_RUN
REQUEST_A_REPLAY_AFTER_FIX=NOT_RUN
REQUEST_A_SURVIVES=0 (prior sealed exercise of 4ED; unchanged)
PROMOTE=0
CERTIFIED=0
T08_REOPEN=0
```

## Why no tip fix

1. 4ED residual stack has **no** product WndProc / subclass.
2. GhostText `editorProc` cleared vs F41; crash **unchanged** at COMCTL32 AV write — GhostText not sufficient origin.
3. Nearest product frame is message-pump helper only — not a proven lifetime owner.
4. HWND/class not recoverable from minidump.
5. Origin hypothesis confidence = **LOW** → must not patch.

Authority: fail-closed stack-first disposition + user Crash Evidence Update.
