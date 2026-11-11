# REAL_EDIT_7_RC_001 DISPOSITION

ASOF_UTC=2026-11-03T07:26:33Z
REAL_EDIT_7=RC_NOT_CERTIFIED
KNOWN_FAILING_SHA=3C750E19089BFC1DDC49793425503D6F07FD982E302C8BCB86588AD36A846CC5
NEW_CANDIDATE_SHA=EFC863F906E5DDF72B8DB87B720ADF5FF28DCCEAABDA393F2788B90A83F512CF
CANDIDATE_EXE=F:\rawrxd\build_real_edit7_rc\bin\RawrXD-Win32IDE-Native.exe
CANDIDATE_SIZE=1709568
GIT_HEAD=dace16621672f3bfff9af5522b839eda4006b266
BUILD_DIR=F:\rawrxd\build_real_edit7_rc
GATES_TOTAL=15
GATES_PASSED=6
GATES_FAILED=5
GATES_NOT_VERIFIED=4
SOAK_100_CYCLES=PASS
ATOMIC_SAVE=NOT_EQUIVALENT
PROMOTE=0
CERTIFIED=0

## Required disposition block

```
REAL_EDIT_7=RC_NOT_CERTIFIED
KNOWN_FAILING_SHA=3C750E19089BFC1DDC49793425503D6F07FD982E302C8BCB86588AD36A846CC5
NEW_CANDIDATE_SHA=EFC863F906E5DDF72B8DB87B720ADF5FF28DCCEAABDA393F2788B90A83F512CF
GATES_TOTAL=15
GATES_PASSED=6
GATES_FAILED=5
GATES_NOT_VERIFIED=4
SOAK_100_CYCLES=PASS
PROMOTE=0
CERTIFIED=0
```

## Gate matrix

| Gate | Result | Evidence | Notes |
|---:|---|---|---|
| 01 | PASS | gates/GATE_01.md | HEAD dace166216 + 30 TUs; EXE SHA recorded |
| 02 | PASS | gates/GATE_02.md | Typing/paste/replace enabled Save |
| 03 | PASS | gates/GATE_03.md | Save As completed; owner survived |
| 04 | PASS | gates/GATE_04.md | save/reopen SHA match; ATOMIC_SAVE=NOT_EQUIVALENT |
| 05 | FAIL | gates/GATE_05.md | CJK/emoji became `?` on disk (lossy path) |
| 06 | NOT_VERIFIED | gates/GATE_06.md | 10+ tabs opened; independent dirty buffers not confirmed |
| 07 | FAIL | gates/GATE_07.md | dirty=True pre-close; marker absent after cold restore |
| 08 | PASS | gates/GATE_08.md | undo/redo + dirty observed |
| 09 | FAIL | gates/GATE_09.md | no conflict detector; fail-closed |
| 10 | FAIL | gates/GATE_10.md | hard kill lost unsaved (no crash autosave) |
| 11 | NOT_VERIFIED | gates/GATE_11.md | no GhostText completion rendered |
| 12 | NOT_VERIFIED | gates/GATE_12.md | no revision-checked agent apply exercised |
| 13 | NOT_VERIFIED | gates/GATE_13.md | Build/Test posted; pane exit codes not captured |
| 14 | PASS | gates/GATE_14.md | 100 edit/save/tab cycles; process alive |
| 15 | FAIL | gates/GATE_15.md | not all 15 PASS on one SHA |

FAIL_CLOSED_LAW=NOT_RUN!=PASS
INVENT_PASS=0
SEAL_PROD_ABSORB=0
AAC10557_01_06_NOT_COPIED=1
