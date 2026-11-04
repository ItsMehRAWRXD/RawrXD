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
CANDIDATE_SIZE=6109184
CANDIDATE_SHA256=5D4C2FBBC45F0A122823CBAF32A531B7A055A5DC6E7F9E2AF4C36F2135E031BD
POST_BUILD_HASH_RECHECK=PENDING
T080_RUNTIME_FILE_LINE_COLUMN=NOT_YET_PHYSICALLY_VERIFIED
```

The source/build and CTest results do not by themselves close T080. A native
IDE run must still produce a real compiler diagnostic and prove selection opens
the correct file and positions the editor at the reported line and column.
