# OPEN — ConPTY compile+run gate

```
PROMOTE=0
TIP_CLIMB=HOLD
STATUS=OPEN
NOT_RUN != PASS
```

## Measured (2026-11-13)

```
COMMAND=g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe
SHA256=5125CFE10FE6C89F649B401A216EA976BC44DB06D44D1EA401E41411D579094D
EXIT=1
HARNESS=terminal_gate.exe v4
```

### Sub-results

| Check | Result |
|-------|--------|
| echo capture marker_in_pipe | PASS |
| compile+run via ConPTY | FAIL |
| interrupt issued | PASS |
| resize | PASS |
| restart | PASS |
| capture after restart | PASS |
| no orphan after stop | PASS |
| PowerShell capture | PASS |

```
TERMINAL_GATE fail_count=1
TERMINAL=FAIL_CLOSED
```

## Disposition

- Overall Terminal-Bench / terminal_gate suite: **FAIL_CLOSED** (not PASS).
- ConPTY compile+run remains **OPEN** — do not treat prior FOUR_PANEL `TERMINAL=PASS` echo/marker seal as closing this sub-gate.
- No invented score. Fix owner: ConPTY product path under `src/win32app/Win32TerminalManager.cpp` + terminal_gate harness case for compile+run.

## Log

`logs/cb_terminal_gate_out.txt`
