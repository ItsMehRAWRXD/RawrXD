# CONPTY_STREAM_OWNER_001 — matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
SOURCE_WIRED=1
RELINK_REQUIRED=1
RUNTIME_REACHED=NOT_RUN
EXE_RELINK=0
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T11:15:00Z
```

| ID | Surface | Evidence / cite | Disposition |
|----|---------|-----------------|-------------|
| C0 | Product CreatePseudoConsole owner | `Win32TerminalManager.cpp` ResolveConPtyApis + CreatePseudoConsole | **SOURCE_WIRED** |
| C1 | PowerShell panel session bind | `m_dedicatedPowerShellTerminal->start` / `tab.manager` | **SOURCE_WIRED** (existing call sites) |
| C2 | Fail-closed absent/fail | `GateConPtyStream` → `GATE_STREAM.txt` | FAIL_CLOSED gate |
| C3 | HWND chrome geometry | `SHELLLAYOUT_PHASE5_001` getPowerShellPanel | unchanged (no tip relink) |
| C4 | Orphan header CreatePseudoConsole | `src/core/pty_terminal.hpp` | NOT product-linked (non-claim) |
| C5 | ASM TUI | `RawrXD_ConPTY_Renderer.asm` | TUI ≠ stream owner |
| C6 | Tip EXE absorbs wire | tip `6832F439…` pre-wire | **RELINK_REQUIRED** |
| C7 | RUNTIME / PASS / PROMOTE | LAW forbids invent | NOT_RUN / 0 / 0 |

## Fail-closed reminder

`SOURCE_WIRED != RUNTIME_REACHED != PASS`. No invented ConPTY E2E PASS. No PROMOTE.
