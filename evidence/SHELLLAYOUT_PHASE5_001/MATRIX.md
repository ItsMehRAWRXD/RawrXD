# SHELLLAYOUT_PHASE5_001 — matrix

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
ASOF_UTC=2026-10-28T10:55:00Z
```

| ID | Surface | Evidence / cite | Disposition |
|----|---------|-----------------|-------------|
| P0–P4 | Shell phases 0–4 | `P1_UI_SHELL_LAYOUT_001/PHASE_0N.txt` | PASS (frozen) |
| P5G | Terminal chrome geometry in `LayoutIDE` | `Win32IDE_ShellLayout.cpp` MoveHwnd(getPowerShellPanel) | **SOURCE_WIRED** |
| P5F | Missing HWND | `GateTerminalMissing` → `GATE_TERMINAL.txt` | FAIL_CLOSED gate |
| P5C | ConPTY stream/PTY | `RawrXD_ConPTY_Renderer.asm` ownership split | UNCLAIMED (not PASS) |
| P5E | Product claim PASS on PHASE=5 | LAW forbids | FORBIDDEN |
| P5R | Tip EXE absorbs wire | tip `6832F439…` pre-wire | **RELINK_REQUIRED** |
| P5S | Silent-skip PHASE=5 | LAW forbids | FORBIDDEN |
| P6 | Full spatial legacy | `P1_UI_SHELL_LAYOUT_001/GATE.txt` | NOT_RUN |
| Prior | Empty-body refuse | `SHELL_LAYOUT_PHASE5_001` | HISTORICAL (geometry superseded) |

## Policy

| Predicate | Value |
|-----------|-------|
| `RebuildRestrictActive` | rebuild && phase ∈ [0,5] |
| Terminal HWND owner | `Win32IDE::getPowerShellPanel` |
| Phase 5 in CBT allow-list | YES (this seal) |
| `UseLegacySpatial(5)` | false |

## Fail-closed reminder

`SOURCE_WIRED != RUNTIME_REACHED != PASS`. No invented terminal PASS. No PROMOTE.
