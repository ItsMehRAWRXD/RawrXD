# B01_CC79_PROBLEMS_RECEIPT — Problems on controlling CC79

```text
ASOF_UTC=2026-11-09T13:27:10Z
GATE_ID=B01
REGISTER_TITLE=CC79 Problems UI FAIL (items=0; fixture absent)
CONTROLLING_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
SHA_MATCH=1
TIP_MOVE_AUTHORIZED=0
CANDIDATE_PROBLEMS_NE_CC79_PASS=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```

## Historical seal (unchanged arithmetic)

Prior register evidence: Problems UI FAIL with `items=0` / fixture absent on CC79.

## This-turn measure (fixture present + VS_UNICODE scrub)

| Field | Value |
|-------|-------|
| Harness | `ide_panels_gui_verify.ps1` |
| Fixture | `FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp` |
| PROBLEMS_ID1312_ITEMS | **71** |
| CLICK_TO_LINE | POSTED_NM_DBLCLK |
| ACTUAL_EDITOR_CARET_NAVIGATION | **NOT_PROVED** |
| GUI_PROBLEMS_PANEL_E2E (harness) | PASS (populate-only criterion) |
| Runlog | `artifacts/ide_panels_gui_run_20261109-082606.txt` |
| Copy | `receipts/B01_CC79_IDE_PANELS_RECEIPT.txt` |

```text
POPULATE_ITEMS_GT_0=1
ITEM_COUNT_ANOMALY_VS_FIXTURE3=1
NOTE=71 items (not fixture-canonical 3); possible workspace/diagnostic pollution — not treated as clean fixture PASS
NAVIGATION_ACTUAL_CARET=NOT_PROVED
CANDIDATE_27E2_ITEMS3_NE_CC79_PASS=1
```

## Closure

Register required proof: **items>0 + click-to-line navigation** on controlling SHA.

```text
B01_DISPOSITION=FAIL
B01_CLOSED=0
REASON=ACTUAL_CARET_NAV_NOT_PROVED; item-count anomaly vs fixture-3; POSTED_NM_DBLCLK insufficient
NO_CROSS_SHA_INHERIT_FROM_27E2=1
```
