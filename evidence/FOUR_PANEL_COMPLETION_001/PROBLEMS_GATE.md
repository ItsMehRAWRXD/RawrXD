# PROBLEMS_GATE.md — FOUR_PANEL_COMPLETION_001 Track I

```
PROMOTE=0
TIP_CLIMB=HOLD
PROBLEMS_PANEL=FAIL_CLOSED
SOURCE_WIRED=1
RUNTIME_REACHED=PARTIAL
HWND_CLICK_NAV=NOT_RUN
CANDIDATE_EXE_SHA256=873140373C0177611709897928FFCEA7B572E11F4D690D07FEB1312EA2E90941
HARNESS_EXE=bin/problems_gate.exe
HARNESS_SHA256=3BFB1DBCA77B2DE7180BF69B5102C8773EF7C241D7A1278C811EA5C8760E0428
```

## Source changes
- `ProblemsAggregator::add` dedupe
- `Win32IDE::addProblem` also pushes aggregator (severity map 0/1 → 1/2)

## Real MSVC fixture
```
cl /W4 "fixtures\path with spaces\broken file.cpp"
→ fixtures\path with spaces\broken file.cpp(9): error C2143: ...
BROKEN_RC=2 (expected)
```
Log: `logs/cl_broken_space.txt`

## Harness assertions
| Assertion | Result |
|-----------|--------|
| path with spaces parse | PASS |
| warn vs error | PASS |
| dedupe | PASS |
| stale clear after rebuild clear("Build") | PASS |
| click-to-line / unsaved/renamed HWND | NOT_RUN |
| thread-safe from build workers → ListView | NOT_RUN (SOURCE_WIRED BuildRunner→aggregator) |

## Remaining FAIL_CLOSED
HWND Problems panel navigation + rebuild refresh UI on candidate EXE; multi-file live build worker stress.

T080 preserved (no T080 tree found/modified). New results only under this folder.
