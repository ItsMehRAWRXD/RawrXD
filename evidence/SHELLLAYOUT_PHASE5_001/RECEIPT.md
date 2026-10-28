# RECEIPT — SHELLLAYOUT_PHASE5_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
SOURCE_WIRED=1
RELINK_REQUIRED=1
RUNTIME_REACHED=NOT_RUN
EXE_RELINK=0
SMOKE_RELINK=0
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T10:55:00Z
```

## Verdict

| Gate | Result |
|------|--------|
| S-005 phase 5 geometry wire | **SOURCE_WIRED** |
| U06 ConPTY chrome layout | **SOURCE_WIRED** (HWND owner only) |
| ConPTY CreatePseudoConsole stream | UNCLAIMED (not PASS) |
| Missing HWND | GateTerminal FAIL_CLOSED |
| RUNTIME_REACHED | **NOT_RUN** (tip EXE unchanged) |
| RELINK_REQUIRED | **1** (tip `6832F439…` must stay) |
| PROMOTE | 0 |

Phases 0–4 remain frozen PASS under `P1_UI_SHELL_LAYOUT_001`. Prior
`SHELL_LAYOUT_PHASE5_001` GATED_UNIMPLEMENTED empty-body refuse is historical
for the pre-wire stub; geometry owner is now wired in source.

## Source edits (owned TUs only)

| File | Change |
|------|--------|
| `src/win32app/Win32IDE_ShellLayout.cpp` | PHASE=5 MoveHwnd/SetChildVisible; GateTerminalMissing; RebuildRestrict 0..5 |
| `src/win32app/Win32IDE_ShellLayout.hpp` | Ladder + policy comment |
| `src/asm/RawrXD_ConPTY_Renderer.asm` | Ownership comment (TUI ≠ geometry) |

## Explicit non-claims

```
RUNTIME_REACHED=0
PHASE_05.txt freeze=ABSENT
CONPTY_STREAM_E2E=NOT_RUN
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
TIP_SHA_UNCHANGED=1
```

## Seal paths

- `evidence/SHELLLAYOUT_PHASE5_001/LAW.txt`
- `evidence/SHELLLAYOUT_PHASE5_001/MATRIX.md`
- `evidence/SHELLLAYOUT_PHASE5_001/RECEIPT.md`
- Closure matrix: S-005 / U06 → SOURCE_WIRED (RELINK_REQUIRED)
