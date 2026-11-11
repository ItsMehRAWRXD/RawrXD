# AGENT_RUNTIME_WIRE_001 — Build notes

## Policy
- `CERTIFIED=0` `PROMOTE=0`
- `SOURCE_WIRED != RUNTIME_REACHED`
- `NOT_RUN != PASS`

## Touched TUs
| TU | Result |
|----|--------|
| `Win32IDE_AgentExecutionFSM.cpp` | **Compiled** → `evidence/AGENT_RUNTIME_WIRE_001/obj/Win32IDE_AgentExecutionFSM.obj` via VS2022 BuildTools `cl /c` |
| `Win32IDE_AgentExecutor.cpp` | **Not standalone-clean** — pulls `Win32IDE.h` → `AgenticLoopBridge.h` → `agent_esp.hpp` / `rawrxd_snap_detectors.hpp` / watchdog graph. Needs full CMake include dirs for `RawrXD-Win32IDE-Native`. |
| `Win32IDE_AutonomousLoop.cpp` | Same include-graph dependency as Executor (via `Win32IDE.h` + Bridge). |
| `Win32IDE_AgenticBridge.cpp` | Same; also concurrent BackendRouter/ToolCallBridge wiring present. |
| Full IDE link | **Not completed** this turn. Other workers own Breadcrumbs/MultiCursor/CommandPalette/RenamePreview/Minimap clusters — not touched. |

## CMake
Added to `RAWRXD_NATIVE_IDE_SOURCES` (near AgentExecutor):
- `src/win32app/Win32IDE_AutonomousLoop.cpp` + `.h`
- `src/win32app/Win32IDE_AgentExecutionFSM.cpp` + `.h`

`Win32IDE_PlanExecutor.cpp` **not** added (not chosen SSOT; polluted/missing-header include graph).

## How to resume compile
From an existing VS2022 CMake build tree:

```bat
cmake --build F:\rawrxd\build --config Release --target RawrXD-Win32IDE-Native
```

Expect other-worker TU failures until those clusters land; do not invent PASS from partial obj success.
