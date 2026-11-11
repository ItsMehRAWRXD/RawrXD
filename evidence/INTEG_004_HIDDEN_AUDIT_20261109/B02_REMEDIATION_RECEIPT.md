# B02_REMEDIATION_RECEIPT — INTEG_004 residual close attempt

```text
ASOF_UTC=2026-11-09T14:30:00Z
GATE_ID=B02
MISSION=Close Chat + Terminal + B12 on one SHA (no invent PASS)
PRIOR_RECONCILED_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
REBUILD=1
MEASURED_SHA256=2CCAE57A02AEB778E8DB678BC8937C63512B296924E4784DB0FE9BCCEFD385DD
CANDIDATE_ROLE=NON_CONTROLLING tip_b02_remediation_001
TIP_EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_b02_remediation_001\RawrXD-Win32IDE-Native-Ext.exe
BUILD_DIR=F:\rawrxd\build_tip_debug_rel
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## Rebuild / identity

| Field | Value |
|-------|-------|
| tip_004 start hash | `27E2263E…` (unchanged; not overwritten) |
| Remediation image | `2CCAE57A02AEB778E8DB678BC8937C63512B296924E4784DB0FE9BCCEFD385DD` |
| Size | 6172672 |
| Sidecar | `...\tip_b02_remediation_001\SHA256.txt` MATCH |

Source deltas (F:\rawrxd product Native-Ext tree):

1. **B12** — `Win32IDE_VSCodeUI.cpp::goToProblem` → `openDocumentPath` + caret (`B12_NAV_OPENDOC_PATH`)
2. **Terminal** — `main_win32.cpp` write receipt then `--term-quit` `ExitProcess` **before** ConPTY `stop()`/dtor join
3. **Chat** — `createChatPanel` idempotent guard; Stop/Clear IDs already present (1205/1210)

## Matrix on `2CCAE57A…` only

| Gate | Disposition | Evidence |
|------|-------------|----------|
| Terminal `--term-smoke --term-quit` | **PASS** | EXIT=0 FORCE_KILL=0 MS=606; START/CONPTY/ALIVE=PASS; trace `term-quit ExitProcess from smoke` · `receipts/TERM_SMOKE_2CCA_RECEIPT.txt` |
| B12 caret nav | **FAIL** | Source in image; GUI HWND/caret **not** proved (`B12_CARET_NAV_RECEIPT.md`) |
| Chat stream/stop/clear | **FAIL** / BLOCKED | Stream **NOT_RUN**; GUI early-exit blocked AIM/stream harness; product has Send/Clear/Stop controls in source |
| Extension (B20 family) | **NOT_RUN** on 2CCA | Must not inherit 27E2 PASS |
| Output | **NOT_RUN** on 2CCA | Must not inherit 27E2 PASS |
| Debug-headless | **NOT_RUN** on 2CCA | Must not inherit 27E2 PASS |
| Problems populate | **NOT_RUN** on 2CCA | Must not inherit 27E2 items=3 |

```text
B02_CLOSED=0
B02_DISPOSITION=FAIL
REMAINING=B12_CARET_RUNTIME,CHAT_STREAM_STOP_CLEAR,[REVERIFY_EXT_OUTPUT_DEBUG_PROBLEMS_ON_2CCA]
TERMINAL_CLOSED_ON_2CCA=1
```

## Fail-closed footer

```text
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0
CONTROLLING=CC79
POSTED_NM_DBLCLK_NE_CARET=1
NOT_RUN_NE_PASS=1
INVENT_PASS=0
B01_CC79_CARET=NOT_CLAIMED
```
