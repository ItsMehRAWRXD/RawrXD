# CC79_PROBLEMS_FOLLOWUP_LAW

ASOF_UTC=2026-11-09T11:26:00Z
MOTD_ACK=1

```
CC79_PROBLEMS_UI=FAIL
PROBLEMS_ITEMS=0
CLICK_TO_LINE=NOT_RUN
FIXTURE_IN_BINARY=0
RETEST_UNCHANGED_CC79=FORBIDDEN
CC79_UNRELATED_PASSES=STILL_VALID_FOR_CC79_SHA_ONLY
A4F_BASELINE=UNTOUCHED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```

## Required sequence

1. Preserve failed CC79 receipt + `candidates\tip_final_integ_002\` EXE.
2. Verify fixture source in Ext build (`Win32IDE_Commands.cpp` on `RawrXD-Win32IDE-Native-Ext`).
3. Bounded rebuild → new candidate SHA (`build_tip_final_integ_004_bounded.bat`).
4. Confirm `RAWRXD_PROBLEMS_FIXTURE` present in new EXE bytes.
5. HWND measure: `PROBLEMS_ITEMS > 0` on that SHA only.
6. Click-to-line to correct file/line.
7. Reconcile EA5D / CC79 / new candidate before changing controlling tip.

```
NEXT_PRODUCTIVE_ACTION=FRESH_BUILD_THEN_SHA_SPECIFIC_HWND
CONTROLLING_TIP_CHANGE=NOT_AUTHORIZED_UNTIL_RECONCILE
```
