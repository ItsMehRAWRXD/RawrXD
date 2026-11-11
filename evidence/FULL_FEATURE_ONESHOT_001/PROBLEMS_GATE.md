# PROBLEMS_GATE — FULL_FEATURE_ONESHOT_001

ASOF_UTC=2026-11-09T09:45:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
TIP_CLIMB=HOLD

```
PROBLEMS_PANEL=PARTIAL_PASS
MSVC_PARSE_FIXTURE=PASS
ERROR_COUNT=3
LINKER_PARSE=PASS
CMAKE_PARSE=PASS
SPACES_IN_PATH=PASS
FILE_LINE_COL=PASS
SEVERITY_WARN=PASS
STALE_CLEAR=PASS
REFRESH_AFTER_CORRECT=PASS
CLICK_TO_LINE=SOURCE_WIRED
GUI_PROBLEMS_PANEL_E2E=NOT_RUN
T080_PRESERVED=1
FROZEN_A4F_UNTOUCHED=1
TIP_SHA256=D28128AECAA7C9E0301A227A9102A8922CEF8BC4BC79635228D93FD74C195529
RECEIPT=logs/problems_panel_receipt.txt
T080_RECEIPT=logs/problems_parse_receipt.txt
FIXTURE=fixtures/broken_multi.cpp
PROMOTE=0
```

## Measured parse

### Offline MSVC fixture (T080 preserved)

| Line | Code | Result |
|------|------|--------|
| 3 | C2065 | parsed |
| 4 | C2660 | parsed |
| 5 | C2440 | parsed |

Command: `cl /c` on `fixtures/broken_multi.cpp` via VsDevCmd → `logs/problems_cl.log`.
`logs/problems_parse_receipt.txt` unchanged historically; `T080_PRESERVED=1`.

### Extended parser (product `parseCompilerDiagnostic`)

| Case | Result |
|------|--------|
| Path with spaces + file:line:col | PASS |
| Linker `LNK2019` | PASS |
| CMake Error at file:line | PASS |
| Warning severity | PASS |
| Stale clear + corrected refresh model | PASS |
| `goToProblem` click-to-line | SOURCE_WIRED |
| GUI Problems panel E2E | **NOT_RUN** |

## Law

```
parse-only ≠ PROBLEMS_PANEL PASS
T080 sealed evidence unmodified
NOT_RUN ≠ PASS
PROMOTE=0
```

## Disposition

Parser + product wiring measured PARTIAL_PASS. GUI click-to-line E2E still open.
