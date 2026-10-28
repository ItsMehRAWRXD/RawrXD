# RECEIPT — SHELL_LAYOUT_PHASE5_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
EXE_RELINK=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:25:00Z
```

## Verdict

Phase 5 terminal chrome is **GATED_UNIMPLEMENTED**. No PASS invented. Phases
0–4 remain frozen PASS under `P1_UI_SHELL_LAYOUT_001`. Dual-path
`Win32IDE_Window::createWindow` refuse is **GATED_INTENTIONAL**.

## Trace summary

1. `PhaseFromEnvironment()` reads `RAWRXD_SHELL_LAYOUT_PHASE` (default 3, clamp 0..6).
2. Rebuild CBT policy (`RebuildRestrictActive`) covers phases **0–4 only**.
3. `LayoutIDE` layouts 1→4 then hits empty phase-5 body (reserves `terminalH`
   in editor math but never `MoveHwnd`s terminal) — intentional refuse, not PASS.
4. `ApplyFromIde` registers PowerShell/output HWNDs for visibility host at
   phase≥3; that is **not** phase-5 geometry certification.
5. Core (`Win32IDE_Core.cpp`) owns product `onSize` → `LayoutIDE` when rebuild
   && !legacy. Session restore suppressed under rebuild.

## Dispositions

| Item | Disposition | Path |
|------|-------------|------|
| Phase 0 | PASS (frozen) | `evidence/P1_UI_SHELL_LAYOUT_001/PHASE_00.txt` |
| Phase 1 | PASS (frozen) | `evidence/P1_UI_SHELL_LAYOUT_001/PHASE_01.txt` |
| Phase 2 | PASS (frozen) | `evidence/P1_UI_SHELL_LAYOUT_001/PHASE_02.txt` |
| Phase 3 | PASS (frozen) | `evidence/P1_UI_SHELL_LAYOUT_001/PHASE_03.txt` |
| Phase 4 | PASS (frozen) | `evidence/P1_UI_SHELL_LAYOUT_001/PHASE_04.txt` |
| Phase 5 terminal | GATED_UNIMPLEMENTED | this packet + `Win32IDE_ShellLayout.cpp` |
| Phase 6 spatial | NOT_RUN | `evidence/P1_UI_SHELL_LAYOUT_001/GATE.txt` |
| `createWindow` orphan refuse | GATED_INTENTIONAL_DUAL_PATH_REFUSE | `src/win32app/Win32IDE_Window.cpp` |
| Ladder GATE | PHASE_4_PASS preserved | `evidence/P1_UI_SHELL_LAYOUT_001/GATE.txt` |

## Source markers (comment-only; no EXE relink)

- `src/win32app/Win32IDE_ShellLayout.hpp` — ladder line cites this seal
- `src/win32app/Win32IDE_ShellLayout.cpp` — phase≥5 body annotated GATED_UNIMPLEMENTED

## Seal paths

- `evidence/SHELL_LAYOUT_PHASE5_001/LAW.txt`
- `evidence/SHELL_LAYOUT_PHASE5_001/MATRIX.md`
- `evidence/SHELL_LAYOUT_PHASE5_001/RECEIPT.md`

## Outside this seal (NOT PASS)

- Terminal HWND geometry certification / `PHASE_05.txt` freeze — absent
- PHASE=6 / 6A–6C — NOT_RUN
- `P1_UI_WINDOW_OWNERSHIP_001` OVERALL — FAIL (`FORCE_MULTIPLE`) until that gate closes
- PROMOTE / TIP_CLIMB / CERTIFIED — held at 0 / HOLD / 0
