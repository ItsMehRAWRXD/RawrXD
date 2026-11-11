# INTEG_004_SEARCH — local evidence inventory (read-only)

```
ASOF_UTC=2026-11-09T12:40:00Z
SEARCH_ROOTS=F:\rawrxd\evidence ; G:\~dev\rawrxd\evidence
GH_AUTH=OK
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CROSS_SHA_PASS_INHERITANCE=0
```

## 1. Query targets

| Target | Result |
|--------|--------|
| INTEG_004 | **FOUND** on F:\rawrxd (not on GitHub as sealed issue/PR) |
| Finish-25 ledger | **FOUND** (multiple authority docs; controlling historical **19/25**) |
| DAILY_DRIVER_CLOSE_001 | **FOUND** (slim freeze A4F083DF; `SLIM_DAILY_DRIVER_ACCEPTANCE=PASS`) |
| FULL_FEATURE_ONESHOT_001 | **FOUND** (primary working tree; 764 files) |
| G:\~dev\rawrxd\evidence | **PRESENT** (312041 files); no `*INTEG_004*` name hits via glob in this pass — use F:\ as controlling for INTEG_004 |

---

## 2. INTEG_004 — identity and disposition

| Field | Measured value |
|-------|----------------|
| CANDIDATE | INTEG_004 |
| CANDIDATE_SHA | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` |
| CONTROLLING_TIP | CC79 = `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` |
| TIP_MOVE_AUTHORIZED | 0 |
| A4F baseline | IMMUTABLE `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` |
| INTEG_004_PROBLEMS_UI | **PASS** (items=3, click-to-line / POSTED_NM_DBLCLK) |
| CC79_PROBLEMS_UI | **FAIL** (fixture absent; items=0) |
| EXTENSIONS on 47451F24 | **FAIL** (EXT_CLEANUP=FAIL / FORCE_KILL=1; load/activate OK) |
| EXT/CHAT/TERM/OUTPUT/DEBUG on 47451F24 | **NEEDS_REVERIFY** (do not inherit CC79 passes) |
| PRODUCT_PASS | 0 |
| CERTIFIED | 0 |
| PROMOTE | 0 |
| ELIGIBLE_FOR_FURTHER_VERIFICATION | 1 |
| AUTOMATIC_PROMOTION | 0 |

Authority decision (sealed locally): Problems-UI evidence only — **not** controlling tip, **not** full-feature acceptance.

```
INTEG_004_PROBLEMS_PASS ≠ CONTROLLING_TIP ≠ PRODUCT_PASS ≠ CERTIFIED ≠ PROMOTE
```

---

## 3. INTEG_004 — file / directory hit list (F:\rawrxd)

### Candidate trees

| Path | Role |
|------|------|
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\` | Staged EXE candidate tree |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\problems_ui_integ_004\` | Problems UI run candidate / ollama_runtime.log |

### Disposition / lineage (markdown)

| Path | Role |
|------|------|
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md` | Acceptance disposition (Problems-only) |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md` | EA5D ↔ CC79 ↔ integ_004 lineage board |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_EXT_REVERIFY_RECEIPT.md` | Extensions reverify — CLEANUP FAIL |
| `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\INTERIM_LOCAL_FINDINGS.md` | Parent seed noting GitHub index miss ≠ absence |
| `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\NEXT_ACTION.md` | Points CANDIDATE=INTEG_004; EXT FORCE_KILL blocker |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\AUDIT_LAW.md` | Law: Problems PASS; Extensions CLEANUP FAIL |

### Receipts / logs / build artifacts

| Path | Role |
|------|------|
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt` | Problems UI measured receipt |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\problems_ui_integ_004_console.txt` | Console capture |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\ide_panels_gui_run_20261109-063546.txt` | Panels GUI runlog referenced by receipt |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\ext_smoke_summary_20261109-071737.json` | Ext smoke summary (FAIL cleanup) |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\logs\ext_smoke_tip_final_integ_004.txt` | Ext smoke alias log |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_bounded.log` | Bounded rebuild log |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_followup_incr.log` | Follow-up incremental build |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_tip_final_integ_004_bounded.bat` | Bounded rebuild launcher |
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\offline_cl_broken_multi_integ004.txt` | Offline cl fixture capture |

### Glob name hits (`*INTEG_004*` under F:\rawrxd\evidence)

```
HIT_COUNT_GLOB_INTEG_004=6 files (+ 2 candidate dirs)
  FULL_FEATURE_FINAL_COMPLETION_001\logs\ext_smoke_tip_final_integ_004.txt
  FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_followup_incr.log
  FULL_FEATURE_ONESHOT_001\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt
  FULL_FEATURE_ONESHOT_001\artifacts\problems_ui_integ_004_console.txt
  FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_bounded.log
  FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_tip_final_integ_004_bounded.bat
```

Additional content matches (INTEG_004 string in md/txt/json): disposition/lineage/NEXT_ACTION/AUDIT_LAW/oneshot dispatch — see Grep inventory in parent audit.

### G:\~dev\rawrxd\evidence

```
GLOB_*INTEG_004*=0 (this pass)
TREE_EXISTS=1
FILE_COUNT≈312041
NOTE=Do not invent INTEG_004 presence under G: from F: copies without path proof
```

---

## 4. Finish-25 ledger search

### Controlling historical ledger (authoritative 19/25)

| Path | Role |
|------|------|
| `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` | **Controlling progress 19/25**; remaining T05·T07·T08·T18·T19·T25 |
| `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_RECEIPT_AGREEMENT.md` | Receipt agreement; phase arithmetic sealed |

Historical SHA cited: `3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F`  
Progression note SHA: `55BE19B7…` (T17/T10 retest; T07/T08 still not credited).

### Current / oneshot matrices (do not overwrite historical)

| Path | Measured |
|------|----------|
| `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` | HISTORICAL 19/25; CURRENT **4/25** (T10, T16_EXT_EA5D, T17_TERMINAL_EA5D, T20_CHAT_7of7) |
| `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` | Mirror/companion matrix |

### Repair / progression / harness copies

| Path | Role |
|------|------|
| `F:\rawrxd\evidence\REPAIR_FINISH25_001\FINISH_25_DELTA.md` | Repair delta |
| `F:\rawrxd\evidence\REPAIR_FINISH25_001\EDITOR\finish25_t17_t07_t08_t10.ps1` | Editor harness |
| `F:\rawrxd\evidence\PROGRESSION_FINISH25_001\EDITOR\finish25_t17_t07_t08_t10.ps1` | Progression harness |
| `F:\rawrxd\evidence\PROGRESSION_FINISH25_001\DAILY_DRIVER_CLOSE_001_SEAL.md` | Pointer seal (earlier 9C91 narrative; superseded freeze is A4F) |
| `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\finish25_t17_t07_t08_t10.ps1` | Daily-driver harness copy |
| `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR\finish25_t17_t07_t08_t10.ps1` | Post-E59D harness |
| `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\_RECOVERY\parent_1263_FINISH_25_BACKLOG.md` | Recovery copy |
| `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\_RECOVERY\parent_1268_FINISH_25_BACKLOG.md` | Recovery copy |

### Finish-25 counts (fail-closed)

```
FINISH25_LEDGER_FILES_NAMED≥11
FINISH25_HISTORICAL_PASS=19
FINISH25_HISTORICAL_REMAINING=6
FINISH25_CURRENT_ONESHOT_PASS=4
FINISH25_CURRENT_NOT_RUN_OR_HELD=rest
FINISH25_CERTIFIED=0
FINISH25_NE_ISSUE57_45=1
FINISH25_NE_ISSUE49_30=1
```

No single file named exactly `FINISH_25_LEDGER.md` was required; **BACKLOG + RECEIPT_AGREEMENT** are the ledger pair.

---

## 5. DAILY_DRIVER_CLOSE_001 search

### Tree

```
PATH=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001
FILES≈240
PACKAGE_FREEZE=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
SIZE=2601472
PROFILE=SLIM_WIN32IDE_NATIVE
EXT=OUT_OF_SCOPE
SLIM_DAILY_DRIVER_ACCEPTANCE=PASS
FULL_FEATURE_DAILY_DRIVER=FAIL
IMMUTABLE=1
```

### Key docs

| Path | Role |
|------|------|
| `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\DAILY_DRIVER_FREEZE.md` | Freeze receipt |
| `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\DAILY_DRIVER_FREEZE.md` | Package copy |
| `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\GATE_BOARD.md` | Slim gate board (T05/T07/T08/T10/T16/T17/T18/T19 on A4F; EXT OOS) |
| `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\SLIM_DAILY_DRIVER_EXT_POLICY.md` | EXT out-of-scope policy |
| `F:\rawrxd\evidence\PROGRESSION_FINISH25_001\DAILY_DRIVER_CLOSE_001_SEAL.md` | Progression pointer (historical 9C91 — not current A4F freeze) |
| `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\DAILY_DRIVER_CLOSE_001_ASSESSMENT.md` | Assessment |

### Tip staging under package (non-exhaustive)

Multiple `package\tip_*` SHA/receipt trees exist (tip_final_003–005, tip_ext_host_*, tip_terminal_conpty_001, tip_chat_*, etc.). Tip experiments must not overwrite frozen A4F package exe (GATE_BOARD law).

```
SLIM_PASS ≠ FULL_FEATURE ≠ CERTIFIED ≠ PROMOTE ≠ ISSUE_49
FINISH_25_COUNT_UNCHANGED_ON_SLIM_FREEZE=19/25
```

---

## 6. FULL_FEATURE_ONESHOT_001 search

```
PATH=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
FILES=764
HIDDEN_GAP_AUDIT_001=PRESENT (this audit writes here)
PRODUCT_PASS=0
CERTIFIED=0
PROMOTE=0
```

### Notable gates / status docs (sample)

| Path | Note |
|------|------|
| `FINISH25_MATRIX.md` | Current 4/25 |
| `FINAL_INTEGRATION_GATE.md` | FINAL_INTEGRATION=NOT_RUN; PRODUCT_PASS=0 |
| `NATIVE_EDITOR_CHAT_GATE.md` | Chat evidence track |
| `TERMINAL_GATE.md` | Terminal / ConPTY |
| `PROBLEMS_PANEL_GATE.md` / `OUTPUT_PANEL_GATE.md` | Panel gates |
| `EXTENSIONHOST_GATE.md` | ExtensionHost |
| `DEBUG_CONSOLE_GATE.md` | Debug — often NOT_RUN on controlling tip |
| `artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt` | INTEG_004 Problems link |
| `HIDDEN_GAP_AUDIT_001\DISPATCH.md` | Audit dispatch |
| `HIDDEN_GAP_AUDIT_DISPATCH.md` | Parent dispatch pointer |

Controlling tip references in oneshot docs have **moved across SHAs** (EA5D, CC79, 1F60…, tip_hwnd_repair, tip_final_006). Fail-closed: each PASS is SHA-bound; no inheritance.

---

## 7. Evidence tree size counts (this pass)

| Tree | Files |
|------|------:|
| FULL_FEATURE_ONESHOT_001 | 764 |
| FULL_FEATURE_FINAL_COMPLETION_001 | 171 |
| DAILY_DRIVER_CLOSE_001 | 240 |
| POST_E59D_CANDIDATE_001 | 405 |
| PROGRESSION_FINISH25_001 | 181 |
| REPAIR_FINISH25_001 | 63 |
| G:\~dev\rawrxd\evidence | 312041 |

---

## 8. Gap list specific to INTEG_004 (not PASS)

1. EXT_CLEANUP / clean `--ext-quit` on SHA `47451F24…` still **FAIL** (FORCE_KILL).
2. CHAT / TERMINAL / OUTPUT_GUI / DEBUG_HEADLESS must be **remeasured on 47451F24…** before tip move.
3. CONTROLLING_TIP remains **CC79** until owner authorization + NEEDS_REVERIFY conjunction.
4. No GitHub PR HEAD among #75–#79 equals `47451F24…` in this audit — local candidate ≠ merged PR evidence.
5. Issue #49 product-final chain still **unproven** regardless of Problems UI PASS.

```
INTEG_004_SEARCH_STATUS=COMPLETE
GITHUB_INDEX_MISS≠LOCAL_ABSENCE=1
NEXT_GATE_HINT=NEEDS_REVERIFY_ON_47451F24_OR_OWNER_TIP_MOVE_AUTH
INVENT_PASS=0
```
