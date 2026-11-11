# Screenshot observation — Problems populate (SHA-bound populate only)

```text
ASOF_UTC=2026-11-09T16:06:48Z
EVIDENCE_CLASS=USER_SCREENSHOT_PLUS_SHA_BIND
SHA_BOUND=1
BOUND_SHA256=1AE26B8F3A6BE63462C1C6F860B09153DB077786505D32F9A4C051E1D80F0CB5
BOUND_EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_rc_integ_001\RawrXD-Win32IDE-Native-Ext.exe
LIVE_EXE_PROCESS=0_AT_SEAL
POPULATE_ON_BOUND_SHA=PASS_ITEMS_3
B12_ON_BOUND_SHA=FAIL
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82%_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
CONTROLLING_TIP=CC79
LAW=POPULATE_VISIBLE_NE_B12_NE_INTEGRATED_ACCEPTANCE
```

## What the screenshot + remeasure establishes

| Observation | Disposition |
|-------------|-------------|
| Problems list shows 3 diagnostics for `broken_multi.cpp` | **VISIBLE_DIAGNOSTIC_POPULATION** |
| C2065 `y` undeclared @ line 3 | Matches fixture expectation |
| C2660 `undeclared_fn` arg count @ line 4 | Matches fixture expectation |
| C2440 string→float @ line 5 | Matches fixture expectation |
| Status text ≈ 3 errors, 0 warnings | Count agrees |
| Tabs visible: Terminal, Output, Problems, Debug Console | Tab chrome visible |
| Remeasure on `1AE26B8F…` Problems items=3 | **POPULATE PASS (that SHA only)** |

## What it does **not** establish

- B12 click-to-line / actual caret on lines **3, 4, 5** (measured **FAIL** on same SHA — see `B12_LINES_345_RECEIPT.md`)
- Fresh compiler capture vs stale cache distinction beyond items=3
- Four-panel integrated acceptance
- Tip-move / PROMOTE / CERTIFIED

## Tip hash notes

- tip_b02 expected `2CCAE57A…` → disk now `7B3C0ECB…` (B12 strings present; launch flaky)
- tip_006 `B50A2AB1…` → no B12 navigate strings
- Chosen measure image: tip_rc `1AE26B8F…`
