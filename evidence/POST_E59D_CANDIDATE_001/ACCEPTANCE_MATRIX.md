# ACCEPTANCE_MATRIX — FINISH_25 Phase4/5 (T16–T25)

ASOF_UTC=2026-11-03T14:55:40Z
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SIZE=6080512
SHA_MATCH=1
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
NOT_RUN_NE_PASS=1
AUTHORITY_RESULT=F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\PHASE4_5\phase4_5_result.json
AUTHORITY_RECEIPT=F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\PHASE4_5_RECEIPT.md

## Law

`NOT_RUN != PASS` · `BLOCKED != PASS` · `FAIL != PASS`  
Sealed cert EXE not rebuilt. Checklist marks ≠ receipts.

## Matrix T16–T25

| ID | Gate | Status | Evidence |
|----|------|--------|----------|
| T16 | Native Build/Test E2E | **PASS** | IDE Build/Test → `[RAWRXD_BUILD_RESULT] EXIT=0`, `[RAWRXD_TEST_RESULT] EXIT=0`; `PHASE4_5\mini_workspace\build\P45_*.txt` |
| T17 | Diagnostics / navigation | **FAIL** | Find **PASS**; focus **PASS**; errors panel present; File Open **FAIL** |
| T18 | 100-cycle soak | **BLOCKED** | Phase1 Request A crash / BATCH1_CANCEL_RECOVERY=FAIL |
| T19 | Memory / handles | **BLOCKED** | Soak-dependent; short sample only in `PHASE4_5\logs\memory_handles.csv` |
| T20 | Host stability | **PASS** | AMD OK×3; CrashDumpEnabled=2; dumps×3; `PHASE4_5\logs\t20_host.json` |
| T21 | Worktree/Git authority | **PASS** | Tip 70fe7cdaf7; worktree 57f4dd1f matches BINARY_AUTHORITY; `t21_git.json` |
| T22 | RC seal | **PASS** | Current SHA sealed; `PHASE4_5\RC_SEAL.txt`; NEW_SHA=0 |
| T23 | Acceptance matrix | **PASS** | This file — statuses distinguished; no invented PASS |
| T24 | Package / rollback | **NOT_RUN** | No installer/MSI/rollback for this CERT SHA |
| T25 | CERTIFIED / PROMOTE | **0 / 0** | Mandatory conjunction incomplete |

## Mandatory conjunction (T25)

```
PROMOTE_IF = T16..T24 all PASS (+ Phase1-3 mandatory as required)
ACTUAL: CERTIFIED=0 PROMOTE=0
```

## BLOCKERS

```
T17_FILE_OPEN_FAIL
T18_BLOCKED_PHASE1_REQUEST_A_CRASH
T19_BLOCKED_SOAK_DEPENDENT
T24_NO_PACKAGE_ARTIFACT
T25_MANDATORY_GATES_INCOMPLETE
BATCH1_CANCEL_RECOVERY=FAIL
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
```

## Counts (Phase4/5)

```
PASS=5      (T16,T20,T21,T22,T23)
FAIL=1      (T17)
BLOCKED=2   (T18,T19)
NOT_RUN=1   (T24)
T25=CERTIFIED=0 PROMOTE=0
```
