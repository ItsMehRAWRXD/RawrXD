# Gate ? executable SHA bind

```text
ASOF_UTC=2026-11-09T16:06:48Z
LAW=HASH_MATCH_NE_RUNTIME_ACCEPTANCE
NO_CROSS_SHA_PASS_INHERITANCE=1
CONTROLLING_TIP=CC79
CONTROLLING_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
ENGINEERING_MATURITY=82%_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
FIRST_UNMET_DEPENDENCY=B12_ACTUAL_CARET_NAV
```

Identity source: `BINARY_IDENTITY_LEDGER.md` (freeze sweep).  
Disposition vocab: PASS | FAIL | NOT_RUN | HISTORICAL_ONLY | OPEN

## Bind table (evidence ? transferable)

| Gate | Bound SHA | Disposition | Receipt / note |
|------|-----------|-------------|----------------|
| Controlling tip identity | `CC79F6CD?` | IDENTITY only | tip_final_integ_002 |
| Phase A matrix (tip_004) | `27E2263E?` | FAIL overall | PHASE_A_SHA_MATRIX_27E2263E ? Ext/Output/Debug-hd/Problems populate PASS; Chat/Term/B12 FAIL |
| B20 Ext cleanup | `27E2263E?` | PASS (that SHA only) | B20_EXT_CLEANUP_RECEIPT |
| Terminal `--term-smoke` | `2CCAE57A?` | PASS (that SHA only) | B02_REMEDIATION / TERM_SMOKE_2CCA ? **image ABSENT on disk now** |
| tip_b02 disk now | `7B3C0ECB?` | IDENTITY | supersedes 2CCAE57A slot; B12 strings=1 |
| Terminal `--term-smoke` | `B50A2AB1?` | PASS (INTEG_006) | INTEG006_TERM_REVERIFY |
| Chat stream/Stop/Clear | `B50A2AB1?` | PASS 7/7 (INTEG_006) | INTEG006_CHAT_REMEASURE |
| Chat stream/Stop/Clear | `2CCAE57A?` | FAIL / NOT_RUN | B02_REMEDIATION |
| Chat stream/Stop/Clear | `27E2263E?` | FAIL | PHASE_A matrix |
| Problems populate | `27E2263E?` | PASS items=3 | PHASE_A |
| Problems populate | `B50A2AB1?` | PASS items=3 | INTEG006_PROBLEMS_UI ? click=`POSTED_NM_DBLCLK` only |
| **Problems populate** | `1AE26B8F?` | **PASS items=3** | tip_rc_integ_001 ? screenshot SHA-bound populate |
| **B12 caret (actual)** | `27E2263E?` | **FAIL** | B12_CARET_NAV_27E2 ? TITLE_AFTER empty |
| **B12 caret (actual)** | `2CCAE57A?` | **FAIL** | B12_CARET_NAV_RECEIPT ? source path present; GUI caret not proved |
| **B12 caret (actual)** | `B50A2AB1?` | **NOT_PROVED** | Problems UI PASS ? caret |
| **B12 caret (actual)** | `CC79F6CD?` | **FAIL / NOT_PROVED** | B01_CC79_PROBLEMS |
| **B12 lines 3/4/5 (actual)** | `1AE26B8F?` | **FAIL** | B12_LINES_345_RECEIPT ? LINE_3/4/5 FAIL; NAV ABSENT; caret stayed 1 |
| Debug-headless | `27E2263E?` | PASS | PHASE_A |
| Debug UI | `B50A2AB1?` | PASS (four-panel still FAIL_CLOSED) | INTEG006_DEBUG_UI |
| Terminal/Output/Debug smoke | `1AE26B8F?` | PASS (smoke) | B12_LINES_345 receipt panels |
| PowerShell panel `ls` | any | **OPEN / NOT_RUN** | POWERSHELL_PANEL_ROUTING_AUDIT |
| Sealed INTEG_004 Problems | `47451F24?` | HISTORICAL_ONLY | EXE ABSENT ? non-inheritable |
| B03 tip-move | process | HELD | AUTHORIZED=0 |
| Integrated workflow (freeze) | none yet | NOT_DEMONSTRATED | RELEASE_SCOPE_FREEZE |

## First unmet dependency (still open)

```text
ID=B12
REQUIREMENT=Problems click ? actual editor file + line + caret (lines 3,4,5)
FAIL_CLOSED=POSTED_NM_DBLCLK != PASS; cross-process pointer NM_NOTIFY insufficient
MEASURED_ON=1AE26B8F? FAIL
SOURCE_PATCH=case 1399 goToProblem(lParam) landed; rebuild not staged this seal
DOES_NOT_CLOSE=PROMOTE, tip-move, maturity bump, full B02
```

## Screenshot populate (updated)

User screenshot: Problems **3 errors** on `broken_multi.cpp` lines 3/4/5. Now **SHA_BOUND=1** to `1AE26B8F?` for **populate only**. B12 lines 3/4/5 remain **FAIL**. See `SCREENSHOT_PROBLEMS_POPULATE_OBSERVATION.md` + `B12_LINES_345_RECEIPT.md`.

## tip_rc_issue49_001 F87B4EE0 (2026-11-09T18:16Z)
Issue49 **3/11** on this SHA only. CHAT_INPUT PASS (EM_REPLACESEL). AgentSession+loop spawned. Tool/edit NOT_PROVED. E6CF 2/11 not inherited.


## tip_rc_issue49_002 C0ACE8FE (2026-11-09T18:52Z)
Issue49 **5/11**. PASS: 01,04,05,06,08. OPEN: 10–15. No inherit from F87B4EE0.


| Issue #49 tip_rc_issue49_004 | `A1C591A6…` | FAIL_CLOSED 5/11 SOURCE_EDITED=0 | ISSUE49_REMEASURE_A1C591A6 / TIP004_AUTHORITATIVE |
