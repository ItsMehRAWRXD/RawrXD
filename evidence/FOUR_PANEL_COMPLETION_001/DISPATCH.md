# FOUR_PANEL_COMPLETION_001 — DISPATCH

ASOF_LOCAL=2026-11-09
PROMOTE=0
TIP_CLIMB=HOLD
CAMPAIGN=RAWRXD_FOUR_PANEL_FULL_COMPLETION
WORKER=aa7a38b9-ad39-4a2c-9e1f-41036b96eeec
PARENT_MODE=COORDINATOR_DISPATCH
NOT_RUN != PASS

## Tracks
G=NATIVE_TERMINAL
H=OUTPUT_PANEL
I=PROBLEMS_PANEL
J=DEBUG_CONSOLE
INTEGRATION=FOUR_PANEL_INTEGRATION

## Candidate (integration target)
PATH_HINT=g:\~dev\rawrxd\build-win32ide-p1-candidate
DO_NOT_TOUCH=TIP_FREEZE_001 / immutable A4F baseline

## Known SOURCE_WIRED (pre-runtime; ≠ PASS)
- Win32TerminalManager.cpp — CreatePseudoConsole ConPTY owner (RUNTIME previously NOT_RUN / RELINK gaps)
- Win32IDE_PowerShellPanel.cpp — dedicated PowerShell session
- Win32IDE_ProblemsPanel.cpp — ProblemsAggregator ListView
- Win32IDE_*Debugger* / NativeDebugPanel — backend determination required (no mock invent)

## Status (pre-evidence)
TERMINAL=NOT_RUN
OUTPUT_PANEL=NOT_RUN
PROBLEMS_PANEL=NOT_RUN
DEBUG_CONSOLE=NOT_RUN
FOUR_PANEL_INTEGRATION=NOT_RUN

Gate receipts to be earned under this folder:
TERMINAL_GATE.md OUTPUT_GATE.md PROBLEMS_GATE.md DEBUG_CONSOLE_GATE.md FOUR_PANEL_INTEGRATION.md
