# DEBUG_CONSOLE_GATE.md — FOUR_PANEL_COMPLETION_001 Track J

```
PROMOTE=0
TIP_CLIMB=HOLD
DEBUG_CONSOLE=FAIL_CLOSED
SOURCE_WIRED=1
RUNTIME_REACHED=PARTIAL
BACKEND=NativeDebuggerEngine (DbgEng COM)
PRODUCT_UI=Win32IDE_NativeDebugPanel.cpp / Win32IDE_Debugger*.cpp / DebuggerIntegration*
NO_CONSOLE_ONLY_MOCK=1
CANDIDATE_EXE_SHA256=873140373C0177611709897928FFCEA7B572E11F4D690D07FEB1312EA2E90941
HARNESS_EXE=bin/debug_console_gate.exe
HARNESS_SHA256=FF2F66CF408581A8B953CCFD25D399242E6DBA40C93768B99A8275A4B33F8515
DEBUG_FIXTURE_SHA256=8B57DBFF3225B9715A5168F79461C8B6BC4CFA15F92EC4740992CEA00336040F
```

## Backend determination
Native path is **DbgEng** via `src/core/native_debugger_engine.cpp` (`dbgeng.dll` LoadLibrary + COM). UI commands in `Win32IDE_NativeDebugPanel.cpp` (launch/attach/step/go/…). Not a console-only mock.

## Results
| Capability | Result |
|------------|--------|
| dbgeng.dll load | PASS (`DBGENG_DLL=1`) |
| debug fixture compile (/Zi) | PASS (`bin/debug_fixture.exe`) |
| launch/attach via product IDE | NOT_RUN (candidate HWND / NativeDebuggerEngine link-in-process not executed) |
| breakpoints / step / vars / stack | NOT_RUN |
| clean recovery / non-blocking UI | NOT_RUN |

## Required capabilities still missing at RUNTIME (FAIL_CLOSED)
launch, attach, breakpoints, continue/pause/stop/restart, step over/into/out, location, call stack/threads, vars/expressions, exceptions/exit codes, debugger I/O, clean recovery, non-blocking UI — all need candidate IDE process exercising NativeDebuggerEngine.

## Explicit
`SOURCE_WIRED != RUNTIME_REACHED != PASS`. No invented debugger PASS.
