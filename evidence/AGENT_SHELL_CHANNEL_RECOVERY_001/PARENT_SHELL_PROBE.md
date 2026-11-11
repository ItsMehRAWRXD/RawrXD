# PARENT_SHELL_PROBE — AGENT_SHELL_CHANNEL_RECOVERY_001

ASOF_UTC=2026-11-02T13:50:30Z
GATE_STATUS=OPEN

## Authorized command

```
cmd.exe /d /c "echo HELLO & exit /b 0"
```

cwd=`C:\` · no Tee · no orchestration wrappers

## Native outside Cursor

CLASS=`PENDING` — must be run in Windows Command Prompt outside Cursor (this agent cannot produce that channel).

## Parent Agent Shell attempt

See companion capture from this turn (`PARENT_SHELL_PROBE_RESULT.txt` if written; else terminal metadata).

Interpretation rule:
- Native PASS + parent FAIL → parent Agent Shell execution/capture defect
- Native FAIL → Windows process execution (Cursor-independent)
- Native PASS + parent PASS → shell recovery demonstrated; product cert still separately blocked
