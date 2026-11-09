# FOUR_PANEL_INTEGRATION.md — FOUR_PANEL_COMPLETION_001

```
PROMOTE=0
TIP_CLIMB=HOLD
FOUR_PANEL_INTEGRATION=FAIL_CLOSED
RUNTIME_REACHED=NOT_RUN
CANDIDATE_EXE_SHA256=873140373C0177611709897928FFCEA7B572E11F4D690D07FEB1312EA2E90941
TIP_FREEZE_748B_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
748B_CLOBBER=0
P1_CANDIDATE_DIR=build-win32ide-p1-candidate (EXE absent; PDB only as of campaign)
```

## Combined scenario 1–10
| Step | Result |
|------|--------|
| 1 terminal build | FAIL_CLOSED (ConPTY pipe capture) |
| 2 output channels | NOT_RUN HWND |
| 3 problems populate | PARTIAL (parser harness only) |
| 4 click nav | NOT_RUN |
| 5 fixed build | PASS fixture `fixed.exe` outside IDE |
| 6 debugger launch | NOT_RUN |
| 7 hit BP | NOT_RUN |
| 8 exit cleanup | NOT_RUN |
| 9 panels usable | NOT_RUN |
| 10 IDE reopen no leaks | NOT_RUN |

## Integration blockers
1. ConPTY application stdout capture on OS 26300
2. Full Win32IDE candidate relink into `build-win32ide-p1-candidate\bin`
3. HWND E2E for Output/Problems/Debug panels on that EXE

## Status rollup
```
TERMINAL=FAIL_CLOSED
OUTPUT_PANEL=FAIL_CLOSED
PROBLEMS_PANEL=FAIL_CLOSED
DEBUG_CONSOLE=FAIL_CLOSED
FOUR_PANEL_INTEGRATION=FAIL_CLOSED
```
All five PASS **not** earned. PROMOTE=0 TIP_CLIMB=HOLD.
