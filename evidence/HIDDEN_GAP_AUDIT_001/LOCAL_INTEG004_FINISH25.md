# LOCAL_INTEG004_FINISH25 — Track A (local evidence only)

```
ASOF_UTC=2026-11-09T12:30:00Z
TRACK=A_LOCAL_EVIDENCE_ONLY
FAIL_CLOSED=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
A4F_IMMUTABLE=1
A4F_SHA256=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
ENGINEERING_MATURITY_ESTIMATE=82_PERCENT_UNCHANGED
ESTIMATE_CHANGE=0
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
INVENT=0
NOT_RUN_NE_PASS=1
NO_CROSS_SHA_PASS_INHERITANCE=1
MOTD_ACK=1
```

## 1) INTEG_004 lineage receipts (local)

### Receipt paths (PRESENT)

| Receipt | Path |
|---------|------|
| Lineage reconcile | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md` |
| Acceptance disposition | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md` |
| EXT reverify | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_EXT_REVERIFY_RECEIPT.md` |
| Problems UI (oneshot) | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\PROBLEMS_UI_CC79_RECEIPT.md` |
| HWND / panels receipt | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt` |
| Console | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\problems_ui_integ_004_console.txt` |
| IDE panels GUI | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\IDE_PANELS_GUI_RECEIPT.txt` |
| EXT runlog | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\logs\ext_smoke_tip_final_integ_004.txt` |
| Candidate dir | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\` |
| SHA256.txt (on-disk) | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\SHA256.txt` |
| Later compiler feed | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\IDE_COMPILER_FEED_RECEIPT.txt` |
| NEXT_ACTION (blocker) | `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\NEXT_ACTION.md` |

### Sealed candidate SHA in lineage receipts (Problems UI era)

```
SEALED_RECEIPT_SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
ROLE=Problems-UI candidate only (NOT controlling tip)
INTEG_004_PROBLEMS_UI=PASS (items=3, click-to-line POSTED_NM_DBLCLK)
CC79_PROBLEMS_UI=FAIL (items=0; fixture absent in CC79 image)
EXT_ON_SEALED=FAIL (EXT_CLEANUP=FAIL; EXTENSIONS=FAIL; FORCE_KILL=1)  # INTEG004_EXT_REVERIFY_RECEIPT
EXT_CHAT_TERM_OUTPUT_DEBUG=NEEDS_REVERIFY (at seal time; cross-SHA inherit forbidden)
TIP_MOVE_AUTHORIZED=0
AUTO_PROMOTE_INTEG_004=0
```

### Live on-disk integ_004 exe (Get-FileHash this audit)

```
EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe
SIZE_BYTES=6167040
MEASURED_SHA256=69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB
SHA256_TXT=69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB
MATCHES_SHA256_TXT=1
MATCHES_SEALED_RECEIPT_47451F24=0
47451F24_EXE_UNDER_CANDIDATES=ABSENT_LOCALLY
```

Reconciliation (fail-closed): lineage / Problems / EXT receipts seal to `47451F24…`. Live `tip_final_integ_004` image is now `69FE3D92…` (also recorded in `IDE_COMPILER_FEED_RECEIPT.txt`). Do **not** inherit Problems PASS from `47451F24…` onto `69FE3D92…`. Do **not** invent that `47451F24…` remains the candidate image.

### CC79 controlling image (measured)

```
EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
SIZE_BYTES=6152704
MEASURED_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
ALSO_AT=F:\rawrxd\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe
ALSO_AT=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe
ALSO_AT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe
```

### A4F immutable slim (measured)

```
EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
SIZE_BYTES=2601472
MEASURED_SHA256=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
```

## 2) Authoritative Finish-25 ledger

### Historical controlling (immutable arithmetic)

Authority: `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md`  
Agreement: `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_RECEIPT_AGREEMENT.md`

```
FINISH25_HISTORICAL=19/25
FINISH_25_REMAINING=6
HISTORICAL_UNACCEPTED_SIX=T05 · T07 · T08 · T18 · T19 · T25
PHASE1=4/5   # T05 NOT_RUN (historical controlling arithmetic)
PHASE2=3/5   # T07+T08 FAIL
PHASE3=5/5
PHASE4=3/5   # T18+T19 BLOCKED
PHASE5=4/5   # T24 CANDIDATE_PACKAGE_PASS; T25 CERTIFIED=0
PRE_T24_NARRATIVE=18/25
PROMOTE=0
CERTIFIED=0
```

Do not guess other six. Matrix sources above name exactly: **T05 · T07 · T08 · T18 · T19 · T25**.

### Current oneshot / final-completion recount (fail-closed; ≠ historical)

| Ledger | Path | CURRENT |
|--------|------|---------|
| Oneshot | `FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` | **4/25** (T10, T16_EXT_EA5D, T17_TERMINAL_EA5D, T20_CHAT_7of7) |
| Final completion | `FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` | **4/25** on CC79 (T10, T16, T17, T20) |

```
FINISH25_HISTORICAL=19/25
FINISH25_CURRENT=4/25
HISTORICAL_19/25 ≠ CURRENT_4/25 ≠ PRODUCT_PASS ≠ CERTIFIED ≠ PROMOTE
HISTORICAL_NOT_MUTATED=1
```

Note: later specialty seals (e.g. T05 on marker `0F054F01…`) are SHA-scoped and do **not** rewrite historical remaining-six arithmetic unless a controlling Finish-25 authority file updates — none measured that mutates the six.

## 3) 78-item acceptance register

```
78_ITEM_ACCEPTANCE_REGISTER=ABSENT_LOCALLY
NOT_IN_INDEXED_GITHUB=NOT_SEARCHED_THIS_WORKER  # Track A = local only
```

Local references that *mention* a prior ~78 register (not the register itself):

- `FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\AUDIT_LAW.md` (“Prior ~78-item acceptance register”)
- `FULL_FEATURE_ONESHOT_001\HIDDEN_GAP_AUDIT_001\DISPATCH.md` / `HIDDEN_GAP_AUDIT_DISPATCH.md`
- `HIDDEN_GAP_AUDIT_001\INTERIM_LOCAL_FINDINGS.md` (`78+120+45 ≠ ACCEPTANCE_COUNT`)

Nearby non-matches (not a 78-item acceptance register):

- `HIDDEN_GAP_AUDIT_001\MASTER_HIDDEN_GAP_REGISTER.md` — H01–H120 investigation scaffold (PENDING_WORKER)
- `RAWRXD_FULL_IDE_AUDIT_003\DEFECT_REGISTER.csv` — different defect CSV
- `POST_E59D_CANDIDATE_001\COMPLETENESS_ESTIMATE_2026_11_08.md` — “~78%” maturity estimate, not 78 items

## 4) tip005 HWND / OUTPUT_HWND / CC79 (ONESHOT + FINAL_COMPLETION)

### FULL_FEATURE_ONESHOT_001

| Fact | Measured value | Authority path |
|------|----------------|----------------|
| Controlling tip | CC79 / tip_final_005 | `OUTPUT_GATE.md`, `BASELINE_RECONCILIATION_001.md` |
| tip005 exe SHA | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | Get-FileHash + `tip005_hwnd_console.txt` |
| OUTPUT_HWND (gate verdict) | **FAIL** (chat mis-sampled as Build) | `OUTPUT_GATE.md`, `OUTPUT_PANEL_GATE.md` (tip006 remeasure also FAIL) |
| OUTPUT_HWND (raw tip005 harness) | `PARTIAL_CTRL_ONLY` | `artifacts\TIP005_OUTPUT_PROBLEMS_HWND_RECEIPT.txt`, `tip005_hwnd_console.txt` |
| BUILD_LINE_SAMPLE | chat `> User:` contamination | same |
| SELECT_BUILD_TAB4 | True | same |
| CC79_UNREPLACED | 1 | `TIP005_HWND_REPAIR.md`, `OUTPUT_PANEL_GATE.md` |
| tip006 repair SHA (receipt only) | `5A71CA26FEF42E927A53208A374FEF8BC4FD9D3F4BF6998C596FE2026CE80211` | `TIP005_HWND_REPAIR.md`, `MEASURED_TIP006_HWND_RETURN.txt` |
| tip006 exe on disk | **ABSENT_LOCALLY** | package\tip_final_006 paths checked |

### FULL_FEATURE_FINAL_COMPLETION_001

| Fact | Measured value | Authority path |
|------|----------------|----------------|
| CONTROLLING_TIP | CC79 | `FINAL_VERDICT.md`, `FOUR_PANEL_INTEGRATION.md`, `FINISH25_MATRIX.md` |
| OUTPUT_GUI on CC79 | PASS (sealed CC79 only) | `FOUR_PANEL_INTEGRATION.md`, `FINAL_VERDICT.md` |
| PROBLEMS on CC79 | OPEN / FAIL items=0 | `FOUR_PANEL_INTEGRATION.md`, `PROBLEMS_PANEL_GATE.md` |
| IDE_DEBUG_UI | FAIL | `FOUR_PANEL_INTEGRATION.md` |
| Four-panel integration | OPEN | `FOUR_PANEL_INTEGRATION.md` |
| tip005 HWND FAIL track | oneshot OUTPUT_HWND=FAIL does not rewrite sealed OUTPUT_GUI=PASS on CC79; separate harness axes | fail-closed separation |

```
ONESHOT_OUTPUT_HWND_FAIL ≠ FINAL_COMPLETION_OUTPUT_GUI_PASS_REWRITE
CC79_REMAINS_CONTROLLING=1
PROMOTE=0
```

## 5) Marker / freeze / EXT tip hashes (see also BASELINE_SHA_LEDGER.md)

| Label | Full SHA-256 | Live path measured |
|-------|--------------|--------------------|
| T05 marker 0F054F01 | `0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E` | `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe` (1484800) |
| T10 freeze 9C910599 | `9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8` | `...\candidates\tip_t10_9C910599\RawrXD-Win32IDE-Native.exe` (2592256); bak twin same hash |
| EXT tip_ext_host_001 | `272199BE27AF3959D44C741C4F0337E9833291FB73346389167CC62000C189B8` | `...\package\tip_ext_host_001\RawrXD-Win32IDE-Native.exe` (2220544) |

Later EXT tips measured: see `BASELINE_SHA_LEDGER.md`.

## Law

```
47451F24_SEAL ≠ 69FE3D92_LIVE ≠ CC79_CONTROLLING
INTEG_004_PROBLEMS_PASS ≠ CONTROLLING_TIP ≠ PRODUCT_PASS
FINISH25_HISTORICAL_19/25 ≠ FINISH25_CURRENT_4/25
78_REGISTER_ABSENT ≠ invent register
OUTPUT_HWND_FAIL (oneshot tip005/tip006) ≠ invent PRODUCT_PASS
MATURITY_82_PERCENT_UNCHANGED=1
PROMOTE=0
CERTIFIED=0
```
