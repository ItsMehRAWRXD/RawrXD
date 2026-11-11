# PHASE4_5_RECEIPT — FINISH_25 T16–T25

ASOF_UTC=2026-11-03T14:55:40Z
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SHA_PRE=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SHA_POST=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SHA_MATCH=1
SIZE=6080512
PID=26948
HARNESS=PHASE4_5\harness_phase4_5.ps1
RESULT_JSON=PHASE4_5\phase4_5_result.json
RUNLOG=PHASE4_5\RUNLOG.txt
PROMOTE=0
CERTIFIED=0
REBUILD=HELD
INVENT_PASS=0

## Final T16–T25

```
T16=PASS
T17=FAIL
T18=BLOCKED
T19=BLOCKED
T20=PASS
T21=PASS
T22=PASS
T23=PASS
T24=NOT_RUN
T25_CERTIFIED=0
T25_PROMOTE=0
```

## Per-task notes

### T16 Build/Test E2E — PASS
- `RAWRXD_BUILD_DIR` → mini workspace (does not mutate cert EXE).
- Markers: `[RAWRXD_BUILD_RESULT] EXIT=0`, `[RAWRXD_TEST_RESULT] EXIT=0`.
- File stamps: `PHASE4_5\mini_workspace\build\P45_BUILD_RESULT.txt`, `P45_TEST_RESULT.txt`.
- Output panel: Native IDE test run started (workspace=F:\rawrxd).

### T17 Diagnostics/nav — FAIL
- Find dialog: PASS (title=Find).
- Editor focus: PASS.
- Errors/output panels present.
- File Open: FAIL — main title remained on prior session file (`gt_stale_GTSTALE_…`); navigation path not proven.

### T18 100-cycle soak — BLOCKED
- Governing: `BATCH1_CANCEL_RECOVERY=FAIL`, Request A crash (dump 092638).
- User rule: cancel portion BLOCKED if Phase1 A crash.
- Full soak (editor/tab/save/ChatWindow/**cancellation**) not executed.

### T19 Memory/handles — BLOCKED
- Requires soak-bound measurement across T18.
- Short sample captured (`logs\memory_handles.csv`): START PrivateMemory=14475264 GDI=51 USER=155 Threads=15.
- END sample unavailable (process exited before final sample). Short sample ≠ PASS.

### T20 Host stability — PASS
- Win11 Build 26300; AMD Radeon×3 Status=OK.
- CrashDumpEnabled=2; LocalCrashDumps present; evidence dumps×3 intact.
- `PHASE4_5\logs\t20_host.json`.

### T21 Worktree/Git — PASS
- `F:\rawrxd` HEAD=`70fe7cdaf73996ee03ecae2db78837cde7b8baf7` (DISPOSITION tip).
- `.worktrees\e59d_restore` HEAD=`57f4dd1f056959ad541db626d3684152b17fd9fb` (= BINARY_AUTHORITY SOURCE_COMMIT).
- Split trees reconciled; dirty porcelain present (WIP ≠ rebuild).

### T22 RC seal — PASS
- Current SHA sealed; NEW_SHA=0; `PHASE4_5\RC_SEAL.txt`.
- No rebuild authorized or performed.

### T23 Acceptance matrix — PASS
- `ACCEPTANCE_MATRIX.md` written with PASS/FAIL/BLOCKED/NOT_RUN distinction.

### T24 Package/rollback — NOT_RUN
- No MSI/Setup/uninstall/rollback artifact for CERT SHA 3B720981….
- Legacy dist/release Win32IDE.exe trees noted only — not package validation.

### T25 CERTIFIED/PROMOTE — 0
- Mandatory gates incomplete → CERTIFIED=0 PROMOTE=0.

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

## Paths

```
PHASE4_5\
  harness_phase4_5.ps1
  phase4_5_result.json
  RUNLOG.txt
  RC_SEAL.txt
  logs\harness_console.txt
  logs\memory_handles.csv
  logs\t16_output_panel.txt
  logs\t20_host.json
  logs\t21_git.json
  logs\t24_pkg_scan.txt
  mini_workspace\build\P45_BUILD_RESULT.txt
  mini_workspace\build\P45_TEST_RESULT.txt
ACCEPTANCE_MATRIX.md
PHASE4_5_RECEIPT.md
```
