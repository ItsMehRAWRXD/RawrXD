# G75 — Production source-reachability inventory (2026-11-22)

Source of truth: `build/RawrXD-Win32IDE-Native.vcxproj` (generated VS project),
160 `<ClCompile>` translation units, 0 `ExcludedFromBuild` entries.

## Active vs inactive (Win32 IDE)
| File | In vcxproj | Status |
| --- | --- | --- |
| `Win32IDE_lifecycle.cpp` | YES | **ACTIVE** — WindowProc, handleMessage, WM_CLOSE, deferred close prompt |
| `Win32IDE_FileOps.cpp` | YES | **ACTIVE** — saveIdeSession/loadIdeSession, ide_session.json |
| `Win32IDE_Commands.cpp` | YES | **ACTIVE** — command router, handleToolsCommand, build dispatch |
| `Win32IDE.cpp` | YES | **ACTIVE** — main window, menus, GhostText integration |
| `Win32IDE_AgentCommands.cpp` | YES | **ACTIVE** — agent commands, onBackendSelectionChanged |
| `Win32IDE_GhostText.cpp` | YES | **ACTIVE** — GhostText lifecycle |
| `Win32IDE_Debugger.cpp` | YES | **ACTIVE** — debugger |
| `Win32IDE_Core.cpp` | **NO** | **DEAD** — duplicate WindowProc/handleMessage |
| `Win32IDE_Session.cpp` | **NO** | **DEAD** — duplicate saveSession/restoreSession |
| `Win32IDE_DebugConsole.cpp` | **NO** | **DEAD** — Debug Console implementation is elsewhere |

## Corrections to earlier claims
- **G54**: the patches in `Win32IDE_Session.cpp` (saveSession window geometry,
  restoreSession re-apply, SaveWindowState→saveSession) and the `[CLOSE]`
  instrumentation in `Win32IDE_Core.cpp` are in **dead files** → **no runtime
  effect**. The G54 seed-restore PASS came from the **active** implementation
  (`Win32IDE_FileOps.cpp` / `Win32IDE_lifecycle.cpp`), not from those patches.
  The G54 fix, if any is still needed, belongs in `Win32IDE_FileOps.cpp`.
- **G53**: `Win32IDE_DebugConsole.cpp` is dead; the Debug Console must be
  implemented in an active file (likely `Win32IDE.cpp`/`Win32IDE_FileOps.cpp`).
  Locate with `rg -uuu -n 'DebugConsole|debug_console|Debug Console' src/win32app`.

## Mandate
Every future fix MUST begin by confirming the target file appears in
`build/RawrXD-Win32IDE-Native.vcxproj` (or a linked library), otherwise the
change cannot affect the shipping executable. Do not delete dead files (they may
be experimental); mark them clearly.

## Ledger
```
G75=PASS (reachability inventory)
DEAD_FILES=Win32IDE_Core.cpp, Win32IDE_Session.cpp, Win32IDE_DebugConsole.cpp
ACTIVE_FILES=lifecycle, FileOps, Commands, Win32IDE, AgentCommands, GhostText, Debugger
```