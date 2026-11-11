# Phase2 T07/T08/T10 — Product vs Harness Classification (evidence-only)

ASOF_UTC=2026-11-03T15:08:30Z
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
METHOD=SEALED_RECEIPT_AND_RUNLOG_ONLY
EXECUTION=0
REBUILD=HELD
PROMOTE=0

## T07 — FAIL_BINARY_NOT_REJECTED

| Field | Value |
|-------|--------|
| Evidence | `TASK07.md` · RUNLOG `T07 BINARY_ACCEPTED` · `binReject=False` |
| Observed | UTF-8/LF/large subchecks OK; NUL `.bin` opened without reject dialog |
| Classification | **PRODUCT_LEAN** — product accepted binary into editor path |
| Harness | Opens real path via Open dialog (same path used for PASS T06 opens) |
| PRODUCT_DEFECT | **SUSPECTED_NOT_PROVEN** until acceptance policy for binary reject is cited as mandatory product law |
| Harness residual | NOT_PROVEN as sole cause |

## T08 — FAIL_TABCTRL_STUCK_AT_1_DESPITE_OPENS

| Field | Value |
|-------|--------|
| Evidence | RUNLOG: 10× `after_open i=N tabCount=1`; titles/paths changed |
| Observed | File>Open updates title; SysTabControl32 IDC_DOC_TABS count stayed 1 |
| Classification | **MIXED** — either product single-document replace, or harness measures wrong control / multi-tab UI not that control |
| PRODUCT_DEFECT | **NOT_PROVEN** (need confirm multi-tab is product requirement + correct HWND) |
| Harness residual | **SUSPECTED** — tabctrl may not be authoritative for "ten documents" |

## T10 — FAIL_CRASH_FAIL_SESSION_ONLY_ON_WM_CLOSE

| Field | Value |
|-------|--------|
| Evidence | `TASK10.md`; RUNLOG external No/Yes PASS; hard-kill unsaved marker absent from session |
| Observed | External-change handling OK; abrupt kill does not restore unsaved into `ide_session.json` |
| Classification | **PRODUCT_LEAN** if crash-recovery of unsaved is in acceptance matrix; else **SCOPE** if only WM_CLOSE session is claimed |
| PRODUCT_DEFECT | **NOT_PROVEN** without written crash-recovery requirement binding |
| Harness residual | Hard-kill is intentional; not false FAIL from wrong assert path alone |

```
T07_CLASS=PRODUCT_LEAN_SUSPECTED
T08_CLASS=MIXED_HARNESS_SUSPECTED
T10_CLASS=PRODUCT_LEAN_OR_SCOPE
PRODUCT_DEFECT=NOT_PROVEN
RETEST_AUTHORIZED=0
```
