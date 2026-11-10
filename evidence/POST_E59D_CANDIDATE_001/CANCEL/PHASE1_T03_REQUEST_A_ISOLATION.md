# PHASE1 T03 — Request A isolation (Send vs BM_CLICK)

ASOF_UTC=2026-11-03T14:52:30Z
GATE=FINISH_25_BACKLOG_PHASE1_T03
AUTH=FINISH_25_BACKLOG
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SHA_MATCH=1
PROMOTE=0
REBUILD=HELD
PRODUCT_DEFECT=NOT_PROVEN

Harness: `CANCEL\harness_phase1_t03_send_vs_bm.ps1`

## Isolation matrix (this turn, same SHA)

| Arm | SetEdit | SETEDIT_LEN | Result | Dump | Signature match triad |
|-----|---------|-------------|--------|------|------------------------|
| BM_CLICK | WM_SETTEXT_ONLY | 0 | NO_CRASH_25S | none | N/A |
| WM_COMMAND_BN_CLICKED | WM_SETTEXT_ONLY | 0 | NO_CRASH_25S | none | N/A |
| BM_CLICK | DUAL | 88 | NO_CRASH_25S | none | N/A |
| WM_COMMAND_BN_CLICKED | DUAL | 88 | EXIT=-1 ~20s | **no new dump** (stale 092638 mis-attributed by harness) | **NO** (sealed exits were -1073740771 / 0xC000041D) |

Result JSONs:
- `CANCEL\logs\phase1_t03_bm_click_result_20261103-094628.json`
- `CANCEL\logs\phase1_t03_wm_command_bn_clicked_result_20261103-094729.json`
- `CANCEL\logs\phase1_t03_bm_click_result_20261103-095054.json`
- `CANCEL\logs\phase1_t03_wm_command_bn_clicked_result_20261103-095125.json`

## Harness vs product (fail-closed)

```
HARNESS_SOLE=REFUTED          # sealed: single BM Cancel 073409 still CRASH same 0xBD02
HARNESS_CLEAR_REQUIRED=REFUTED_THIS_RUN  # BATCH1
HARNESS_DUAL_SETEDIT_REQUIRED=REFUTED_THIS_RUN  # BATCH1
CLICK_MODE_SOLE_CAUSE=NOT_PROVEN
BM_CLICK_VS_SEND_DIFFERENTIAL=INCONCLUSIVE_FOR_PRODUCT
  # BM dual survived; WM dual EXIT=-1 without sealed dump/signature — do not equate to comctl32 triad
PRODUCT_DEFECT=NOT_PROVEN
CONCRETE_CALLBACK=NOT_PROVEN
CRASH_ROOT_CAUSE=NOT_PROVEN
CAUSAL_CLOSURE=DEFERRED
```

Sealed Cancel crashes (070906/073409/092638) remain authoritative that Request-A Cancel path **can** fault `comctl32+0xBD02`. This turn's Request-A-only arms did **not** reproduce that signature. Non-reproduction ≠ PASS for Cancel recovery; ≠ invent PRODUCT_DEFECT.

## Result

```
T03=PASS
ISOLATION_EXECUTED=1
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
PROMOTE=0
```
