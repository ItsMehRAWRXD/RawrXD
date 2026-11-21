# G50 (Native debugger) + G53 (Debug Console) — source audit (2026-11-21)

## G50 — Native debugger
- `src/win32app/Win32NativeDebugBackend.cpp` (34 KB) + `.h` — Win32 debug backend
  (`WaitForDebugEvent` loop, process/thread control, breakpoint/watch handling).
- `src/win32app/Win32IDE_Debugger.cpp` (35 KB) — IDE debugger integration:
  `startDebugging`, `stopDebugging`, `continueExecution`, `stepOverExecution`,
  `stepIntoExecution`, `stepOut`, breakpoints, call stack, variable inspection.
- `src/win32app/Win32IDE_DebuggerIntegration.cpp` + `_test.cpp` — integration layer
  and unit tests.
- `src/win32app/Win32IDE_DebugWatchFormat.cpp` — watch/variable formatting.
- Menu/commands: `IDM_DEBUG_START/STOP/CONTINUE/STEP_OVER/STEP_INTO/STEP_OUT/SHOW_CALLSTACK`
  are routed in the command router (`Win32IDE_Commands.cpp` ~227-235) to
  `startDebugging`/`stopDebugging`/`continueExecution`/`stepOver`/`stepInto`/`stepOut`.

## G53 — Debug Console
- Debug Console pane exists in the bottom panel; commands are routed to the active
  debug session (same debugger backend).

## Acceptance status
| Requirement | Status |
| --- | --- |
| Launch (startDebugging) | Implemented |
| Breakpoints | Implemented |
| Stepping (over/into/out) | Implemented |
| Continue/stop | Implemented |
| Variables/call stack | Implemented |
| Debug Console command execution | Implemented |
| Runtime GUI acceptance | **PENDING** (needs a real debug session with a fixture, breakpoint hit, stepping, and console command) |

## Remaining for G50/G53 closure
Run a real debug session against a fixture (e.g. `evidence/g52_fixture/valid`):
launch, set a breakpoint, hit it, step, inspect a variable, execute a Debug Console
command, and confirm output. This is a GUI-interaction acceptance step; the
implementation is present in compiled sources.