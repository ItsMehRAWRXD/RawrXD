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

`Win32IDE::onTerminalOutput()` now parses only complete MSVC or GCC-style
diagnostic lines containing file, line, column, severity, and message. Parsed
records are sent to the existing `addProblem()` model, so the existing Problems
selection path can open the file and navigate to the reported line and column.
Ordinary terminal output is not converted into synthetic diagnostics.

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
CANDIDATE_SIZE=6109696
CANDIDATE_SHA256=AF870AFBC45140C1D49F633D0C7454C17B97E9338043F85EE17E26D416C480ED
POST_BUILD_HASH_RECHECK=PASS
SOURCE_COMMIT=PENDING_CURRENT_STDERR_REPAIR
T080_REAL_COMPILER_ERROR=OBSERVED
T080_STDERR_DIAGNOSTIC=OBSERVED_IN_NATIVE_TERMINAL
T080_PROBLEMS_ROW_AND_NAVIGATION=NOT_VERIFIED
```

The first runtime attempt showed why the initial implementation was
insufficient: compiler output arrived through `onTerminalError()`. The
candidate was repaired to parse stderr as well as stdout and rebuilt. The
second physical run displayed the real `bad.cpp(1): error C2065` diagnostic in
the native terminal, but the Problems panel did not expose a selectable row
in the captured accessibility state. T080 therefore remains open pending
verification of Problems-list insertion and exact editor navigation.

The source/build and CTest results do not by themselves close T080. A native
IDE run must still produce a real compiler diagnostic and prove selection opens
the correct file and positions the editor at the reported line and column.
