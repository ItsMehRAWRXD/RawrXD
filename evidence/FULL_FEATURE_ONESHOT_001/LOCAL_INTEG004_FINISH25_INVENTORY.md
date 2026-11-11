# LOCAL_INTEG004_FINISH25_INVENTORY

```
ASOF_UTC=2026-11-09T12:42:00Z
MOTD_ACK=1
READ_ONLY=1
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ROOT_PRIMARY=F:\rawrxd
ROOT_COMPARE=G:\~dev\rawrxd
G_MIRROR_LINEAGE=ABSENT
```

Statuses below are **FOUND / ABSENT / PARTIAL** from on-disk file evidence only.
`NOT_RUN ≠ PASS`. Sealed receipt PASS ≠ current on-disk SHA match unless re-hashed.

---

## Executive return

| Question | Answer |
|----------|--------|
| INTEG_004 exists locally? | **FOUND** (candidate package + lineage receipts under `FULL_FEATURE_FINAL_COMPLETION_001`) |
| Finish-25 authority path | **FOUND** — HISTORICAL: `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` (**19/25**); CURRENT matrices: oneshot + final-completion `FINISH25_MATRIX.md` (**4/25**) |
| 78-item ACCEPTANCE_REGISTER | **ABSENT** as a named file; only referenced as prior input |
| CC79 controlling tip | **FOUND** — `tip_final_integ_002` SHA **CC79F6CD…** (measured match) |
| A4F immutable package | **FOUND** — confirmed SHA **A4F083DF…** |
| tip_chat_dispatch_001 rebuild | **PARTIAL** — package dir present; rebuild FAILED (`windows.h`); staged EXE is **EA5D** stale, not a sealed dispatch rebuild |

---

## 1) INTEG_004 / tip_final_integ_004 lineage — FOUND (PARTIAL SHA drift)

### Candidate package

| Field | Value | Status |
|-------|-------|--------|
| Path | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\` | FOUND |
| EXE | `...\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` (size 6167040) | FOUND |
| `SHA256.txt` / measured now | `69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB` | FOUND |
| Sealed Problems/EXT candidate SHA in receipts | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | FOUND (receipts) |
| On-disk vs sealed | **MISMATCH** — package rewritten after 47451F24 seal | PARTIAL |

Sibling tips under same candidates root:

| Tip dir | Role | SHA (file/measured) | Status |
|---------|------|---------------------|--------|
| `tip_final_integ_001` | prior integ | (dir FOUND; not rehashed this inventory) | FOUND |
| `tip_final_integ_002` | **CONTROLLING CC79** | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | FOUND (hash match) |
| `tip_final_integ_003` | intermediate | `SHA256.txt`=`DD60FFB8CFB5133ADC0C6E59124C4E4A199E26F310FD00C6A55EC9F7D8A9497C` | FOUND |
| `tip_final_integ_004` | Problems-UI candidate | sealed `47451F24…` / live `69FE3D92…` | PARTIAL |

### Key lineage / receipt files

| Path | Key fields | Status |
|------|------------|--------|
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md` | CONTROLLING_TIP=CC79; CANDIDATE=INTEG_004; sealed `47451F24…`; Problems PASS; TIP_MOVE=HELD; PROMOTE=0 | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md` | CANDIDATE_SHA=`47451F24…`; PROBLEMS_UI=PASS; EXT/CHAT/TERM/OUTPUT/DEBUG=NEEDS_REVERIFY; AUTOMATIC_PROMOTION=0 | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_EXT_REVERIFY_RECEIPT.md` | claims EXE_SHA256=`47451F24…` + SHA_MATCH=1 at run; EXT_LOAD/ACTIVATE PASS; EXT_CLEANUP=FAIL; EXTENSIONS=FAIL | FOUND (historical measure; live EXE now 69FE) |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt` | TIP_SHA256=`47451F24…`; PROBLEMS_ITEMS=3; CLICK=POSTED_NM_DBLCLK; CONTROLLING_TIP=CC79 | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\problems_ui_integ_004_console.txt` | same SHA | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\PROBLEMS_UI_CC79_RECEIPT.md` | CC79 Problems FAIL items=0; integ_004 measure PASS on 47451F24 | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\logs\ext_smoke_tip_final_integ_004.txt` | TIP_SHA256=`47451F24…` | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_bounded.log` | build log | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_followup_incr.log` | follow-up build | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_tip_final_integ_004_bounded.bat` | bounded rebuild harness | FOUND |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\IDE_COMPILER_FEED_RECEIPT.txt` | live candidate `69FE3D92…`; DIAGNOSTIC_FEED=NOT_VERIFIED; PROBLEMS_ITEMS=0 | FOUND |
| `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\INTERIM_LOCAL_FINDINGS.md` | records INTEG_004 PRESENT LOCALLY; still cites sealed `47451F24…` | FOUND |

```
INTEG_004_LOCAL=FOUND
INTEG_004_PACKAGE=FOUND
INTEG_004_SEALED_SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
INTEG_004_LIVE_SHA=69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB
INTEG_004_SHA_DRIFT=1
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
AUTO_PROMOTE_INTEG_004=0
```

---

## 2) Finish-25 ledger / matrix — FOUND

### Authority layers (as cited by CURRENT matrices)

| Layer | Path | Count / key | Status |
|-------|------|-------------|--------|
| **HISTORICAL (authoritative 19/25)** | `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` | FINISH_25_PASS=19; REMAINING=6 (T05 T07 T08 T18 T19 T25) | FOUND |
| Receipt agreement | `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_RECEIPT_AGREEMENT.md` | SUM=19/25; AGREEMENT=1 | FOUND |
| Phase4/5 acceptance matrix | `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\ACCEPTANCE_MATRIX.md` | T16–T25 historical matrix (older ASOF; not CURRENT oneshot) | FOUND |
| **CURRENT oneshot** | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` | HISTORICAL=19/25; CURRENT=4/25; FINAL_CANDIDATE=EA5D… | FOUND |
| **CURRENT on CC79 (final completion)** | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` | HISTORICAL=19/25; CURRENT=4/25; FINAL_CANDIDATE=CC79… | FOUND |
| Progression track | `F:\rawrxd\evidence\PROGRESSION_FINISH25_001\` (+ `DISPOSITION.md`) | FINISH_25_PASS=19 held; progression SHA 55BE19B7… | FOUND |
| Repair delta | `F:\rawrxd\evidence\REPAIR_FINISH25_001\FINISH_25_DELTA.md` | remains 19; no new PASS | FOUND |
| POST_E59D NEXT_ACTION | `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\NEXT_ACTION.md` | FINISH25_HISTORICAL=19/25; FINISH25_CURRENT=4/25; CONTROLLING_TIP=CC79 | FOUND |

```
FINISH25_HISTORICAL=19/25
FINISH25_CURRENT=4/25
FINISH25_AUTHORITY_HISTORICAL=F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md
FINISH25_AUTHORITY_CURRENT_ONESHOT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md
FINISH25_AUTHORITY_CURRENT_CC79=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md
SLIM_PASS ≠ FINISH25_CURRENT ≠ CERTIFIED ≠ PROMOTE
```

---

## 3) 78-item acceptance register — ABSENT

| Probe | Result |
|-------|--------|
| Glob `*ACCEPTANCE_REGISTER*` under `F:\rawrxd` | ABSENT |
| Glob `*78*REGISTER*` | ABSENT |
| Named file containing a sealed 78-row acceptance ledger | ABSENT |
| Mentions only | FOUND as narrative input in `HIDDEN_GAP_AUDIT_001\AUDIT_LAW.md`, `_parent_h120_extract.txt`, `INTERIM_LOCAL_FINDINGS.md` (`78+120+45 ≠ ACCEPTANCE_COUNT`) |
| Near-miss: `RAWRXD_FULL_IDE_AUDIT_003\DEFECT_REGISTER.csv` | FOUND but **15 data rows (D001–D015)** — not a 78-item acceptance register |
| Near-miss: `PR78_ACCEPTANCE_001\RECEIPT.md` | FOUND — PR #78 acceptance track, not 78-item register |
| Near-miss: `MASTER_HIDDEN_GAP_REGISTER.md` | FOUND — H01–H120 skeleton PENDING_WORKER |

```
ACCEPTANCE_REGISTER_78=ABSENT
REFERENCES_TO_PRIOR_78=FOUND
DO_NOT_TREAT_MENTION_AS_LEDGER=1
```

### GATE_BOARD files — FOUND (not a 78-register)

| Path | Notes |
|------|-------|
| `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\GATE_BOARD.md` | Slim A4F board; FINISH_25_HISTORICAL=19/25; SLIM_ACCEPTANCE=PASS; EXT OUT_OF_SCOPE |
| `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\GATE_BOARD.md` | package copy |
| `F:\rawrxd\evidence\REQUEST_A_DIAG_001\GATE_BOARD.md` | pre-A4F 9C91 diag board |

---

## 4) CC79 controlling receipts — FOUND

```
CC79_SHA=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_LABEL=tip_final_integ_002
EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
MEASURED_HASH_MATCH=1
SIZE=6152704
```

| Area | Path | Status |
|------|------|--------|
| Tip package + README | `...\candidates\tip_final_integ_002\` | FOUND |
| Master status | `...\FULL_FEATURE_FINAL_COMPLETION_001\MASTER_STATUS_CC79.md` | FOUND |
| Finish25 CURRENT on CC79 | `...\FINISH25_MATRIX.md` | FOUND |
| EXT / chat / term / debug artifacts | `artifacts\term_smoke_receipt_CC79.txt`, `CHAT_CTRL_ENTER_RECEIPT` (cited), `debug_backend_verify_CC79*.txt`, `CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.txt`, `four_panel_hwnd_probe_CC79*.txt` | FOUND |
| Problems on CC79 | FAIL items=0 (`PROBLEMS_UI_CC79_RECEIPT.md`, MASTER_STATUS) | FOUND |
| Under `DAILY_DRIVER_CLOSE_001` | No CC79 tip package (A4F slim only) | ABSENT (expected; CC79 lives under FULL_FEATURE_*) |
| Under ONESHOT | Multiple CC79-cited gates/receipts (`MASTER_STATUS.md`, `OUTPUT_GATE.md`, `BASELINE_RECONCILIATION_001.md`, etc.) | FOUND |

CC79 is **controlling tip**; unrelated subsystem PASSes are SHA-scoped to CC79 only. Do not inherit onto INTEG_004 live/sealed SHAs.

---

## 5) A4F immutable package — FOUND (confirmed)

| Field | Value |
|-------|-------|
| Authority doc | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\IMMUTABLE_SLIM_BASELINE_A4F083DF.md` |
| GATE_BOARD | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\GATE_BOARD.md` |
| Package path | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe` |
| SHA256 (file + measured) | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` |
| SIZE | 2601472 |
| PROFILE | SLIM_WIN32IDE_NATIVE |
| EXT | OUT_OF_SCOPE |
| IMMUTABLE / FROZEN_A4F_UNTOUCHED citations | widespread across FULL_FEATURE_* receipts | 

```
A4F_PACKAGE=FOUND
A4F_SHA_MATCH=1
OVERWRITE_FORBIDDEN=1
```

---

## 6) tip_chat_dispatch_001 rebuild — PARTIAL

| Artifact | Path | Status |
|----------|------|--------|
| Status seal | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\TIP_CHAT_DISPATCH_001_STATUS.txt` | FOUND — `STATUS=IN_PROGRESS`; `PACKAGE_tip_chat_dispatch_001=ABSENT` (ONESHOT view); `17_PROBE_RUN=NOT_RUN`; NINJA_WITHOUT_VCVARS=FAILED_windows.h |
| Build cmd log | `...\artifacts\TIP_CHAT_DISPATCH_001_BUILD_cmd.log` | FOUND — short copy/DONE; empty A4F_UNTOUCHED fields |
| Ninja log | `...\artifacts\TIP_CHAT_DISPATCH_001_NINJA.log` | FOUND — **FAILED** `windows.h` C1083 |
| Harness script | `...\harness\rebuild_tip_chat_dispatch_001.ps1` | FOUND — targets `DAILY_DRIVER_CLOSE_001\package\tip_chat_dispatch_001` |
| Package dir | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_chat_dispatch_001\` | FOUND |
| Staged EXE hash | `EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE` | FOUND — equals historical tip_final_004 / oneshot FINAL_CANDIDATE, **not** a verified dispatch rebuild seal |
| `build_tip_chat_dispatch_001` tree | ABSENT | ABSENT |
| ONESHOT `package\tip_chat_dispatch_001` | ABSENT | ABSENT |
| 17-probe | NOT_RUN per STATUS | ABSENT |

```
TIP_CHAT_DISPATCH_001=PARTIAL
REBUILD_COMPLETE=0
17_PROBE=NOT_RUN
STAGED_EXE_IS_EA5D_STALE=1
```

---

## G:\~dev\rawrxd compare root

| Check | Status |
|-------|--------|
| `G:\~dev\rawrxd` exists | FOUND |
| `...\evidence\FULL_FEATURE_ONESHOT_001` | ABSENT |
| `...\evidence\FULL_FEATURE_FINAL_COMPLETION_001` | ABSENT |
| `...\evidence\DAILY_DRIVER_CLOSE_001` | ABSENT |
| `...\evidence\POST_E59D_CANDIDATE_001` | ABSENT |
| `...\evidence\PROGRESSION_FINISH25_001` | ABSENT |

Lineage for this inventory is **local-only on F:\rawrxd** (unpushed / not mirrored to G compare tree). Explains GitHub indexed search miss.

---

## SHA list (measured or sealed)

| Label | SHA-256 | Provenance |
|-------|---------|------------|
| CC79 controlling | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | measured tip_final_integ_002 |
| A4F immutable | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | measured package + SHA256.txt |
| INTEG_004 sealed (Problems/EXT receipts) | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | receipts only |
| INTEG_004 live on disk | `69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB` | measured + SHA256.txt |
| tip_final_integ_003 SHA256.txt | `DD60FFB8CFB5133ADC0C6E59124C4E4A199E26F310FD00C6A55EC9F7D8A9497C` | SHA256.txt |
| EA5D / oneshot FINAL_CANDIDATE / stale dispatch EXE | `EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE` | oneshot matrix + measured tip_chat_dispatch_001 EXE |

---

## Path list (primary)

```
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_EXT_REVERIFY_RECEIPT.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\MASTER_STATUS_CC79.md
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\TIP_CHAT_DISPATCH_001_STATUS.txt
F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md
F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_RECEIPT_AGREEMENT.md
F:\rawrxd\evidence\PROGRESSION_FINISH25_001\
F:\rawrxd\evidence\REPAIR_FINISH25_001\FINISH_25_DELTA.md
F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\GATE_BOARD.md
F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\IMMUTABLE_SLIM_BASELINE_A4F083DF.md
F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_chat_dispatch_001\
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\LOCAL_INTEG004_FINISH25_INVENTORY.md
```

---

## Fail-closed close

```
INTEG_004=FOUND
FINISH25_AUTHORITY=FOUND
ACCEPTANCE_REGISTER_78=ABSENT
CC79=FOUND
A4F=FOUND
TIP_CHAT_DISPATCH_001=PARTIAL
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
```
