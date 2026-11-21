# G52 — Output / Problems: real diagnostics verified (2026-11-21)

## Fixtures (`evidence/g52_fixture/`)
- `valid/main.cpp`: `int main() { return 0; }`
- `invalid/main.cpp`: `int main() { return undefined_symbol; }`

## Real compiler results (MSVC, Release)
```
VALID   : g52valid.vcxproj -> ...\Release\g52valid.exe      exit=0
INVALID : ...\invalid\main.cpp(2,12): error C2065:
          'undefined_symbol': undeclared identifier          exit=1
```
These are **genuine compiler diagnostics** (file, line 2, column 12, severity
error, message) — not synthetic.

## IDE pipeline (source-traced)
- Build commands: `IDM_BUILD_COMPILE` (5001), `IDM_BUILD_RUN` (5002),
  `IDM_BUILD_CLEAN` (5003), `IDM_BUILD_REBUILD` (5004) (`Win32IDE_CommandIDs.h`).
- Build invocation: `cmake --build "<dir>" --target <target> --config Release`
  (`Win32IDE_Commands.cpp:890`).
- Problems view: `Win32IDE::refreshProblemsView()` (`Win32IDE_ProblemsHelpers.cpp:2`).
- Output pane: compiler stdout/stderr is appended to the Output/Debug Console.

## Acceptance status
| Requirement | Status |
| --- | --- |
| Real compiler diagnostics (valid/invalid) | **PASS** |
| Build exit codes (0 / non-zero) | **PASS** |
| IDE build command handler present | **PASS** (source) |
| Output pane captures compiler output | Implemented (runtime pending) |
| Problems pane lists file/line/severity/text | Implemented (runtime pending) |
| Double-click navigates to source line | Implemented (runtime pending) |
| Obsolete diagnostics clear after fix+rebuild | Implemented (runtime pending) |

## Remaining for full G52 closure
Drive the IDE build (`IDM_BUILD_COMPILE`) against a fixture project and verify
the Output pane text, the Problems entries, source navigation, and diagnostic
clearing after a fix. This requires opening the fixture as the IDE project and
is the next runtime step.