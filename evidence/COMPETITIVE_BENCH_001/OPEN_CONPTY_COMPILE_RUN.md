# ConPTY compile+run gate

```
PROMOTE=0
TIP_CLIMB=HOLD
STATUS=CLOSED_PASS (local terminal_gate v5)
NOT_RUN != PASS
EXTERNAL_TERMINAL_BENCH=NOT_IN_TREE
```

## Prior measured FAIL (superseded for this sub-gate)

```
COMMAND=g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe
SHA256=5125CFE10FE6C89F649B401A216EA976BC44DB06D44D1EA401E41411D579094D
EXIT=1
HARNESS=terminal_gate.exe v4
compile+run via ConPTY = FAIL
TERMINAL_GATE fail_count=1
```

## This-turn measured PASS (2026-11-13T14:50:45-05:00)

```
COMMAND=g:\~dev\rawrxd\evidence\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe
SHA256=30DBF28C7280CF080F3C5D6C527969007C86E8D3FBCEAE9DC08840B4529B2D1B
HARNESS=terminal_gate.exe v5
LOG=logs/terminal_bench_20261113_145045_out.txt
META=logs/terminal_bench_20261113_145045_meta.json
```

### Sub-results

| Check | Result |
|-------|--------|
| echo capture marker_in_pipe | PASS |
| compile+run via ConPTY | PASS |
| interrupt issued | PASS |
| resize | PASS |
| restart | PASS |
| capture after restart | PASS |
| no orphan after stop | PASS |
| PowerShell capture | PASS |

```
TERMINAL_GATE fail_count=0
TERMINAL=PASS
```

## Disposition

- Local terminal_gate / Terminal-Bench stub: **PASS** (artifact stdout).
- Named upstream Terminal-Bench package: still **NOT_IN_TREE**.
- Process ExitCode in meta may be null (Start-Process quirk); content disposition uses STDOUT_LOG.
- COMPETITIVE_PASS=0 for peer leaderboard (no matched Ollama/vLLM/llama.cpp suite).
- PROMOTE=0 · TIP_CLIMB=HOLD · CERTIFIED=0
