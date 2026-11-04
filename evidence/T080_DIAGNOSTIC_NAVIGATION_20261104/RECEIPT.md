# T080 — compiler diagnostic navigation candidate

## Candidate authority

```ini
BASELINE_SHA256=884D8FBC81C9960E2DB8EC9D88F7E7C29CDECA596F5960D9C5D5FEB7296704AE
BASELINE_SIZE=6106624
REPAIR=Win32IDE.cpp compiler-diagnostic parsing and Problems ingestion
```

The baseline executable was copied to `baseline_before_t080.exe` before the
repair build. It was not overwritten.

## Implementation

`Win32IDE::onTerminalOutput()` and `onTerminalError()` parse complete MSVC or
GCC-style diagnostic lines containing file, line, severity, and message.
MSVC's valid `file(line):` form is accepted with column 1; the optional
`file(line,column):` form is preserved. Parsed records are sent to the
existing `addProblem()` model, so the Problems selection path can open the
file and navigate to the reported line and column. Ordinary terminal output
is not converted into synthetic diagnostics.

The production startup path now creates the existing VS Code-style panel
(`TERMINAL`, `OUTPUT`, `PROBLEMS`, `DEBUG CONSOLE`) and lays it out when the
Errors surface is selected. This fixes the prior source-level gap where the
Problems controls existed but were never instantiated by the running IDE.

## Build and regression evidence

```ini
BUILD=PASS
BUILD_TARGET=RawrXD-Win32IDE-Native
TESTS_TOTAL=28
TESTS_PASSED=27
TESTS_SKIPPED=1
TESTS_FAILED=0
CTEST_EXIT=0
```

The rebuilt candidate is:

```ini
CANDIDATE_SIZE=6110720
CANDIDATE_SHA256=6A8634D4980D070AC1469856F91F89F1485AE158D0BC95E679096B9F9480C98C
POST_BUILD_HASH_RECHECK=PASS
SOURCE_COMMIT=PENDING_PANEL_AND_Msvc_OPTIONAL_COLUMN_REPAIR
T080_REAL_COMPILER_ERROR=OBSERVED
T080_STDERR_DIAGNOSTIC=OBSERVED_IN_NATIVE_TERMINAL
T080_PROBLEMS_PANEL_INSTANTIATED=OBSERVED
T080_PROBLEMS_ROW_AND_NAVIGATION=NOT_VERIFIED_ON_FINAL_HASH
```

The first runtime attempt showed why the initial implementation was
insufficient: compiler output arrived through `onTerminalError()`. The
candidate was repaired to parse stderr as well as stdout and rebuilt. A real
native-terminal run displayed `bad.cpp(1): error C2065`; the pre-panel
candidate did not expose a selectable Problems row. The panel-instantiation
and optional-column repairs are now built into the final hash above, but the
complete final-hash row/navigation rerun remains pending.

The source/build and CTest results do not by themselves close T080. A native
IDE run must still produce a real compiler diagnostic and prove selection opens
the correct file and positions the editor at the reported line and column.
