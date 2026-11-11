# T17 File Open Isolation

ASOF_UTC=2026-11-08T22:30:25Z
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
ACTUAL_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SHA_MATCH=1
RESULT=PASS
AUTH=GRANTED_CONTINUE
METHOD=SAME_SHA_DIAGNOSTIC_RETEST

## Locus matrix

| Locus | Result | Notes |
|-------|--------|-------|
| Menu command (IDM_FILE_OPEN=2002) | PASS | Dialog titled Open appeared |
| Common dialog path bind | PASS | Title became t17_open_fixture.txt |
| Decoder / editor buffer | PASS | Sentinel present in RichEdit |
| Round-trip Save As | PASS | Sentinel survived output file |
| CLI lpCmdLine openDocumentPath | FAIL_OPEN | Untitled/empty — residual only |

```
CLI_OPEN=FAIL_OPEN
MENU_DIALOG_OPEN=PASS
CONTENT_INTEGRITY=PASS
ROUND_TRIP=PASS
FAILURE_LOCUS=CLI_OPEN_PATH_RESIDUAL_NON_CONTROLLING
PRODUCT_DEFECT=NOT_PROVEN_FOR_FILE_OPEN_MENU_GATE
CLI_RESIDUAL=OPEN
```

Prior Phase4/5 "title stuck on gt_stale" is consistent with session-contamination / harness fixture, not a File>Open decoder failure on this isolation run.

```
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
FAIL_CLOSED=NOT_RUN!=PASS
```

RUNLOG=`EDITOR\RUNLOG_T17_T07_T08_T10.txt`
HARNESS=`EDITOR\finish25_t17_t07_t08_t10.ps1`
WORKDIR=`EDITOR\workdir_retest`
