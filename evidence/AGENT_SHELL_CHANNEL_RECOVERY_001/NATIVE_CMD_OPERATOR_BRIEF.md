# NATIVE_CMD_OUTSIDE_CURSOR — operator brief

GATE=`AGENT_SHELL_CHANNEL_RECOVERY_001` · STATUS=`OPEN` / `BLOCKED`  
Agent cannot execute this channel. No rebuild / product E2E / promote from this brief.

## Command (Windows Command Prompt outside Cursor)

```
cmd.exe /d /c "echo HELLO & exit /b 0"
```

Capture: stdout, exit code, elapsed time. Paste or save as `NATIVE_CMD_RESULT.txt` under this evidence dir.

## Decision boundary

| Native result | Next attribution |
|---------------|------------------|
| PASS | Cursor parent Agent Shell launch / stdout transport / lifecycle / env |
| FAIL | Windows process execution / host shell (before blaming Cursor) |
| NOT_VERIFIED | Maintain hold |

Tee is **not** required to reproduce parent FAIL (already FAIL without Tee).

Root cause remains **UNPROVEN** until native result lands.
