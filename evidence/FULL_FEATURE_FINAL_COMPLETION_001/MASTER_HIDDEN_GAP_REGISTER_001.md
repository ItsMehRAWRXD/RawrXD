# MASTER_HIDDEN_GAP_REGISTER_001

ASOF_UTC=2026-11-09T16:20:06Z
MOTD_ACK=1
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_LABEL=tip_final_integ_002
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
INVENT_CONFIRMED_DEFECT=0
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
ISSUE49_MILESTONE=NOT_DEMONSTRATED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
NO_CROSS_SHA_PASS_INHERITANCE=1
TIP_003_004_MUST_NOT_SUPERSEDE_CC79=1
TIP_005_UNIFIED_SHA=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
TIP_005_FROZEN=1
TIP_005_PROVE=FEED_PASS_CLICK_PARTIAL_DEBUG_PARTIAL
TIP_005_DELTA=NAV_TO_DIAG=0;SESSION_REAL=0;B12_STRINGS=0;VT_PASS;CMD_EXEC_POSTED_NO_CAPTURE;RESEAL_HELD;TIP_MOVE=0
TIP_008_CANDIDATE_SHA=49EF453847708045CE97B73D7EEFDA8C8AC5886D3D36403EFF606129FE26EE0F
TIP_008_DELTA=NAV_TO_DIAG=1;SESSION_REAL=1;vars6043=4;FOUR_PANEL=PASS;VT_PASS_NO_RAW_CSI;CMD_EXEC=POSTED_NO_CAPTURE;RESEAL_HELD;TIP_MOVE=0
TIP_004_FROZEN_STOP_OVERWRITE=1
TIP_MOVE=NOT_AUTHORIZED
GITHUB_FETCH=FETCHED (Issues #49/#50/#57 · PRs #75–79)
ABSORB_PASS=1 (additive merge; d3bda9f6 base retained; ABSORB_DELTA_VT + TIP005_UNIFY + TIP008_NAV_DEBUG appended)

## Law

```
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
NOT_RUN != PASS
H_INVESTIGATE != CONFIRMED_DEFECT
SEALED_PASS requires exact SHA evidence on CC79 (or named immutable A4F)
INTEG_004 Problems PASS != CONTROLLING_TIP
tip_final_integ_003 / tip_final_integ_004 / INTEG_004 MUST NOT SUPERSEDE CC79
tip_004 live 69FE3D92 != sealed 47451F24 Problems PASS (EXE churn; no inherit)
tip_004 lineage extends: 69FE3D92 → measured Problems PASS 35EFA9BA → drift 7504BAC4 → VT overwrite 27E2263E (no inherit; ≠CC79)
GUI VT CONSOLE_RENDER=FAIL on tip_hwnd_repair_001 B2AD7E9B ≠ CC79 term-smoke PASS
78+120+45 != ACCEPTANCE_COUNT (dedupe; do not arithmetically sum)
```

## Status vocabulary

| Status | Meaning |
|--------|---------|
| CONFIRMED | Local/gh evidence of failure or measured open blocker |
| UNVERIFIED | Required behavior not demonstrated on cited SHA |
| INVESTIGATE | Plausible mechanism; not assumed present |
| SEALED_PASS | Exact CC79 (or A4F immutable) receipt |
| OUT_OF_SCOPE | Outside approved Windows daily-driver 100% product spec |

## DEDUPE_STATS

```
INPUT_H120=120 (investigation targets; NOT 120 confirmed defects)
INPUT_PRIOR_78=RECONSTRUCTED_NOT_SINGLE_FILE
  PRIOR_78_NAMED_FILE=NOT_LOCATED
  PRIOR_78_COMPOSITION_HINT=Finish25(25)+Issue57(45)+CC79_board_gates(~8) ≈78 narrative inventory
  ALSO_SEEN=RAWRXD_FULL_IDE_AUDIT_003\DEFECT_REGISTER.csv (D001–D015 only; ≠78)
  ALSO_SEEN=POST_E59D COMPLETENESS_ESTIMATE ~78% maturity (≠ item register)
INPUT_FINISH25=25 historical + CURRENT ledger on CC79
INPUT_ISSUE57=45 (gh FETCHED; all unchecked)
INPUT_ISSUE49=1 milestone (gh FETCHED OPEN)
INPUT_ISSUE50=11 layers (gh FETCHED OPEN)
INPUT_PR75_79=5 (gh FETCHED OPEN; MERGE_AUTHORIZED=0)
INPUT_CC79_BOARD=FINAL_VERDICT + PROBLEMS_PANEL_GATE + DEBUG_CONSOLE_GATE + FOUR_PANEL_INTEGRATION
                + COMPILER_ROOT_CAUSE_001 + COMPILER_CAPTURE_ISOLATED_RECEIPT + FOLLOWUP_* + MASTER_STATUS_CC79
RETAINED_ROWS=198
  H01–H120 = 120
  + CC79/INTEG/F25/Issue/PR/A4F/D001 board rows = 75 (base)
  + ABSORB TIP004-LIVE-SHA-CHURN = +1
  + ABSORB_DELTA_VT G-CONSOLE-VT-RENDER + H-VT-RICHEDIT = +2
  (overlaps expressed via MapsTo; not double-counted as separate acceptance %)
ARITHMETIC_SUM_FORBIDDEN=1
OUT_OF_SCOPE_MULTI_PLATFORM=I57-B13,I57-B14,I57-B15,H114
ABSORBED_FIVE_LAYER_CONFIRMED=H01,H02,H13
ABSORBED_LOCAL_INTEG004_LINEAGE=TIP004-LIVE-SHA-CHURN
ABSORBED_VT_CONSOLE=G-CONSOLE-VT-RENDER,H-VT-RICHEDIT
```

## ABSORB_DELTA_TIP005_UNIFY (2026-11-09T13:10Z)

```
UNIFIED_CANDIDATE=tip_final_integ_005
UNIFIED_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
CONTAINS=NO_VCVARS_IN_PIPE+absolute_cl AND startNonInteractive+stripVtForRichEdit
LINEAGE_TABLE=
  35EFA9BA = Problems=3 + IDE_DEBUG_UI PASS + CLICK_TO_LINE=FAIL (measured tip_004)
  7504BAC4 = disk drift (not PASS)
  27E2263E = VT A+B rebuild; staged frozen tip_005; tip_004 stop-overwrite
  CC79F6CD = controlling tip_002 (sealed EXT/chat/term/Output/headless)
TIP005_PROVE_ATTEMPT=LAUNCH_FAIL EXIT=-1 TITLE empty BUILD_3014=False ITEMS=0
CLICK/DEBUG/FOUR/VT/CMD/RESEAL=NOT_RUN on tip_005
HOST_SHELL_WEDGE=1
RECEIPT=artifacts\TIP005_UNIFY_PROVE_RECEIPT.txt
TIP_MOVE=NOT_AUTHORIZED CONTROLLING=CC79 PROMOTE=0
NOT_RUN≠PASS NO_CROSS_SHA_INHERIT=1
```

## ABSORB_DELTA_TIP008_NAV_DEBUG (2026-11-09T16:20Z)

```
CANDIDATE=tip_final_integ_008
SHA256=49EF453847708045CE97B73D7EEFDA8C8AC5886D3D36403EFF606129FE26EE0F
TIP_005_UNTOUCHED=27E2263E… (B12 strings=0 on frozen EXE; not overwritten)
BUILD=build_tip_ext_host_001 (≠ chat build_tip_debug_rel)
PATCHES=Win32IDE_VSCodeUI.cpp goToProblem B12; Win32IDE_Debugger.cpp H02 ListView 1317+6043 mirror
MEASURED=
  COMPILER_FEED=PASS items=3
  NAV_TO_DIAG=1 CLICK=NAVIGATED_LINE_3 via WM_COMMAND_1312
  SESSION_REAL=1 vars6043=4
  FOUR_PANEL=PASS VT=PASS_NO_RAW_CSI
  CMD_EXEC=POSTED_NO_CAPTURE RESEAL=HELD
RECEIPT=artifacts\TIP008_NAV_DEBUG_PROVE_RECEIPT.txt
MATRIX=artifacts\TIP008_MATRIX_CONTINUE_RECEIPT.txt
B12_LOG=F:\rawrxd\evidence\B12_NAVIGATE_LATEST.log (line=3)
TIP_MOVE=0 CONTROLLING=CC79 PROMOTE=0
NO_CROSS_SHA_INHERIT=1
```

## OPEN_BLOCKERS_TOP (evidence-backed only)

```
0. TIP008-CMD-RESEAL — tip_008 NAV+SESSION_REAL closed; CMD_EXEC=POSTED_NO_CAPTURE; RESEAL held
   Evidence: artifacts\TIP008_NAV_DEBUG_PROVE_RECEIPT.txt · TIP008_MATRIX_CONTINUE_RECEIPT.txt
1. G-PROBLEMS — PROBLEMS_ITEMS=0 on CC79 (CONFIRMED); tip_008 NAV_TO_DIAG=1 candidate-only
   Evidence: FULL_FEATURE_FINAL_COMPLETION_001\PROBLEMS_PANEL_GATE.md · MASTER_STATUS_CC79.md
2. H27 / INTEG004-VSUNICODE-FIX — VS_UNICODE_OUTPUT stall CONFIRMED on CC79;
   tip_005/008 candidate ≠ CC79 controlling
   Evidence: artifacts\COMPILER_ROOT_CAUSE_001.txt · COMPILER_CAPTURE_ISOLATED_RECEIPT.txt
3. G-IDE-DEBUG-UI — IDE_DEBUG_CONSOLE_UI_E2E=FAIL on CC79 (CONFIRMED); tip_008 SESSION_REAL=1 candidate-only
   Evidence: DEBUG_CONSOLE_GATE.md · FINAL_VERDICT.md
4. G-FOUR-PANEL / H118 — tip_008 FOUR_PANEL=PASS candidate; CC79 controlling reseal held
   Evidence: FOUR_PANEL_INTEGRATION.md
5. INTEG004-EXT-CLEANUP / H51 — EXT_CLEANUP=FAIL FORCE_KILL on 47451F24 (CONFIRMED candidate SHA)
   Evidence: INTEG004_EXT_REVERIFY_RECEIPT.md
6. ISSUE49 / H120 — product-final single-SHA milestone NOT_DEMONSTRATED (UNVERIFIED)
   Evidence: gh ItsMehRAWRXD/RawrXD#49
7. H103 / I57-A01 — GHA runner_id=0 / empty steps (CONFIRMED from gh #57/#75/#76 bodies)
8. G-CONSOLE-VT-RENDER / H-VT-RICHEDIT — GUI ConPTY→RichEdit CSI litter CONSOLE_RENDER=FAIL;
   measured on tip_hwnd_repair_001 B2AD7E9B≠CC79; CMD_EXEC=UNVERIFIED; A+B SOURCE_WIRED; tip_004 rebuilt 27E2263E
   Evidence: artifacts\TERMINAL_VT_RENDER_FAIL_001.txt · TERMINAL_GATE.md · CONSOLE_RENDER_CSI_LITERAL_FAIL.md
```

## CERT_LADDER_STATUS (Issue #50 · layers 0–10)

```
L0  PARTIAL — provider isolated 32/32 PASS recorded; integration seal pending (#39)
L1  OPEN    — Deep2 integration & runtime closure BLOCKED (#40)
L2  UNKNOWN — pending individual gate-definition inspection (#41)
L3  UNKNOWN — pending (#42)
L4  UNKNOWN — pending (#43)
L5  UNKNOWN — pending (#44)
L6  UNKNOWN — pending (#45)
L7  UNKNOWN — pending (#46)
L8  UNKNOWN — pending (#47)
L9  OPEN    — Performance closure pending (#48)
L10 OPEN    — Product-final (#49); ISSUE49_MILESTONE=NOT_DEMONSTRATED
NOTE: No layer marked PASS — isolated provider tests ≠ L0 integration seal PASS
```

## Counts by status

```
CONFIRMED=15
UNVERIFIED=61
INVESTIGATE=108
SEALED_PASS=10
OUT_OF_SCOPE=4
TOTAL_RETAINED=198
ABSORB_DELTA=+1 TIP004-LIVE-SHA-CHURN; H01/H02/H13 INVESTIGATE->CONFIRMED
ABSORB_DELTA_VT=+2 G-CONSOLE-VT-RENDER + H-VT-RICHEDIT; TIP004-LIVE-SHA-CHURN lineage extended
```

## Finish25 snapshot

```
FINISH25_HISTORICAL=19/25  (POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md; rem T05 T07 T08 T18 T19 T25)
FINISH25_CURRENT_ON_CC79=4/25  (T10,T16,T17,T20) — FINISH25_MATRIX.md
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## GitHub fetch disposition

```
ISSUE49=FETCHED OPEN [LAYER-10] Product-Final Acceptance
ISSUE50=FETCHED OPEN Certification Ladder 0–10
ISSUE57=FETCHED OPEN 45 E2E gates (all unchecked)
PR75=FETCHED OPEN head=3bbda91366161c08c103cd1111dc413e92bdd25b
PR76=FETCHED OPEN head=e91b476b51902e26fd1b0c3678ffce84efe7057d
PR77=FETCHED OPEN head=9edf63fed82bdf427f734591bff262282f6fe822 MERGE_AUTHORIZED=0
PR78=FETCHED OPEN head=84b4725f798f329a31660e87820c2f57115247ce
PR79=FETCHED OPEN head=13c33a6f35c6493cd5bf60a9f5f0a21f6271ef8c
```

---

## Master register

| ID | Title | Status | MapsTo | ControllingSHA | EvidencePath | NextProof |
|----|-------|--------|--------|----------------|--------------|-----------|
| A4F-IMMUTABLE | Frozen slim daily-driver baseline must not be overwritten | SEALED_PASS | A4F;DAILY_DRIVER | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | DAILY_DRIVER_CLOSE_001\IMMUTABLE_SLIM_BASELINE_A4F083DF.md | Keep immutable; not product-final |
| G-EXT | ExtensionHost smoke PASS sealed on CC79 | SEALED_PASS | G-EXT;F25-T16;PR79;H43-H56 | `CC79F6CD…A22940C4` | MASTER_STATUS_CC79.md; FINAL_VERDICT.md | Preserve; re-prove on tip move. INTEG_004 cleanup separate |
| G-CHAT | Chat Ctrl+Enter send 7/7 PASS sealed on CC79 | SEALED_PASS | G-CHAT;F25-T20;Issue49-IDE_CHAT | `CC79F6CD…A22940C4` | MASTER_STATUS_CC79.md; FINAL_VERDICT.md | Preserve; no cross-SHA inherit |
| G-CHAT-EXACTLY-ONCE | Chat send EXACTLY_ONCE correlation (input→dispatch→backend→response→transcript) | UNVERIFIED | G-CHAT-EXACTLY-ONCE;G-CHAT;F25-T20 | button `7B3C0ECB…` (instrumented); ctrl_enter CC79 `CC79F6CD…` | artifacts\CHAT_EXACTLY_ONCE_001\ | EXACTLY_ONCE=NOT_VERIFIED; no multi-block under RXD_ONCE_*; sealed G-CHAT 7/7 untouched; PROMOTE=0 |
| G-TERM | Terminal PASS sealed on CC79 | SEALED_PASS | G-TERM;F25-T17;I57-A09;PR77 | `CC79F6CD…A22940C4` | MASTER_STATUS_CC79.md; artifacts\term_smoke_receipt_CC79.txt | Preserve; ConPTY product-path still under PR77; ≠ GUI VT render |
| G-CONSOLE-VT-RENDER | GUI console VT/CSI render FAIL (RichEdit litter; ≠ CC79 --term-smoke PASS) | CONFIRMED | G-CONSOLE-VT-RENDER;H-VT-RICHEDIT;G-TERM;TIP004-LIVE-SHA-CHURN | running `B2AD7E9B…` tip_hwnd_repair_001 ≠ CC79 | artifacts\TERMINAL_VT_RENDER_FAIL_001.txt; TERMINAL_GATE.md; CONSOLE_RENDER_CSI_LITERAL_FAIL.md | CONSOLE_RENDER=FAIL; CMD_EXEC=UNVERIFIED; A+B SOURCE_WIRED; GUI_VT_RETEST=NOT_RUN on tip_004 27E2263E |
| H-VT-RICHEDIT | PowerShell panel appendPowerShellOutput raw EM_REPLACESEL / CSI before strip | CONFIRMED | H-VT-RICHEDIT;G-CONSOLE-VT-RENDER | source `F:\rawrxd` + tip_004 POST `27E2263E…` | artifacts\TERMINAL_VT_RENDER_FAIL_001.txt; Win32IDE_PowerShellPanel.cpp stripVtForRichEdit | A+B SOURCE_WIRED (startNonInteractive+stripVtForRichEdit); RUNTIME_REACHED on repaired image NOT_RUN |
| G-OUTPUT | Output GUI PASS sealed on CC79 | SEALED_PASS | G-OUTPUT;PR77;FOUR_PANEL | `CC79F6CD…A22940C4` | FINAL_VERDICT.md; MASTER_STATUS_CC79.md | Preserve; four-panel still OPEN |
| G-DEBUG-HEADLESS | Debug backend headless PASS sealed on CC79 | SEALED_PASS | G-DEBUG-HEADLESS | `CC79F6CD…A22940C4` | DEBUG_CONSOLE_GATE.md; artifacts\debug_backend_verify_CC79_receipt.txt | Does NOT credit IDE_DEBUG_UI |
| G-PROBLEMS | Problems panel items=0 / click-to-line not measured on CC79 | CONFIRMED | G-PROBLEMS;H34-H36;F25-T17;PR77;I57-A11 | `CC79F6CD…A22940C4` | PROBLEMS_PANEL_GATE.md; MASTER_STATUS_CC79.md; FINAL_VERDICT.md | prove_ide_compiler_feed after rebuild; items>0 + click-to-line same SHA |
| G-IDE-DEBUG-UI | IDE Debug Console UI E2E FAIL (headless PASS ≠ UI PASS) | CONFIRMED | G-IDE-DEBUG-UI;F25-T21-T23;I57-A14;PR77 | `CC79F6CD…A22940C4` | DEBUG_CONSOLE_GATE.md; FINAL_VERDICT.md | Live BP/step/continue/stop UI with SESSION_REAL |
| G-FOUR-PANEL | Four-panel integration OPEN | CONFIRMED | G-FOUR-PANEL;H118;PR77 | `CC79F6CD…A22940C4` | FOUR_PANEL_INTEGRATION.md; FOLLOWUP_CC79_FOUR_PANEL.md | Close Problems + Debug UI then four-panel on one SHA |
| F25-T10 | Finish25 T10 session recovery CURRENT PASS on CC79 | SEALED_PASS | F25-T10;H26;H69 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | Preserve CURRENT; historical authority separate |
| F25-T16 | Finish25 T16 EXT CURRENT PASS on CC79 | SEALED_PASS | F25-T16;G-EXT | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | Preserve |
| F25-T17 | Finish25 T17 Terminal CURRENT PASS on CC79 | SEALED_PASS | F25-T17;G-TERM | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | Preserve |
| F25-T20 | Finish25 T20 Chat CURRENT PASS on CC79 | SEALED_PASS | F25-T20;G-CHAT | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | Preserve |
| F25-T05 | Finish25 T05 cancel/recovery CURRENT | UNVERIFIED | F25-T05;H58;H75 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md; POST_E59D FINISH_25_BACKLOG | Measure cancel Request-A on CC79/candidate |
| F25-T07 | Finish25 T07 unicode/binary open CURRENT | UNVERIFIED | F25-T07 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | Retest on controlling SHA |
| F25-T08 | Finish25 T08 multi-tab CURRENT (TIP_FIX=0) | UNVERIFIED | F25-T08 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | TIP_FIX=0; do not invent PASS |
| F25-T18 | Finish25 T18 soak CURRENT | UNVERIFIED | F25-T18;H101 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | NOT_RUN on CC79 |
| F25-T19 | Finish25 T19 memory/handles CURRENT | UNVERIFIED | F25-T19;H76 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | NOT_RUN on CC79 |
| F25-T24 | Finish25 T24 packaging CURRENT PARTIAL_STAGE_ONLY | UNVERIFIED | F25-T24;H98-H100;I57-C15 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | Installer/rollback E2E |
| F25-T25 | Finish25 T25 CERTIFIED/PROMOTE conjunction | UNVERIFIED | F25-T25;H106;Issue49 | `CC79F6CD…A22940C4` | FINISH25_MATRIX.md | CERTIFIED=0 PROMOTE=0 held |
| INTEG004-PROBLEMS | INTEG_004 Problems UI items=3 + click-to-line PASS (candidate only) | UNVERIFIED | INTEG004-PROBLEMS;H27;H36;G-PROBLEMS | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | INTEG004_ACCEPTANCE_DISPOSITION.md; LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md | NO_CROSS_SHA_INHERIT; reverify EXT/CHAT/TERM/OUTPUT/DEBUG before tip move |
| TIP004-LIVE-SHA-CHURN | tip_final_integ_004 EXE churn lineage vs sealed INTEG_004 Problems/EXT measure SHA | CONFIRMED | TIP004-LIVE-SHA-CHURN;INTEG004-PROBLEMS;LOCAL_INTEG004;G-CONSOLE-VT-RENDER | sealed `47451F24…` → live `69FE3D92…` → measured Problems PASS `35EFA9BA…` → drift `7504BAC4…` → VT overwrite `27E2263E…` | LOCAL_INTEG004_FINISH25_LOCATOR.md; candidates\tip_final_integ_004\; SHA256_MEASURED_COMPILER_FEED.txt; FROZEN_STOP_OVERWRITE.txt; artifacts\TERMINAL_VT_RENDER_FAIL_001.txt; candidates\tip_final_integ_005\FROZEN.txt | NO_CROSS_SHA_INHERIT; tip_003/004 MUST NOT SUPERSEDE CC79; tip_005 unify IN_FLIGHT (folder present; owner 973ed563 — do not fight) |
| INTEG004-EXT-CLEANUP | INTEG_004 --ext-quit FORCE_KILL / EXT_CLEANUP=FAIL | CONFIRMED | INTEG004-EXT-CLEANUP;H51;PR79 | `47451F24…DC274F` | INTEG004_EXT_REVERIFY_RECEIPT.md | Clean quit without FORCE_KILL; Extensions=PASS same SHA |
| INTEG004-VSUNICODE-FIX | VS_UNICODE_OUTPUT scrub fix SOURCE_WIRED on INTEG_004 lineage | UNVERIFIED | INTEG004-VSUNICODE-FIX;H27 | `47451F24…DC274F` | artifacts\COMPILER_CAPTURE_ISOLATED_RECEIPT.txt; LINEAGE_RECONCILE_… | SOURCE_WIRED≠RUNTIME_REACHED on CC79 until IDE rebuild measured |
| ISSUE49 | Product-Final single-SHA autonomous coding loop | UNVERIFIED | ISSUE49;H120;F25-T25;Layer10 | `CC79F6CD…A22940C4` | gh:ItsMehRAWRXD/RawrXD#49 | ISSUE49_MILESTONE=NOT_DEMONSTRATED |
| PR75 | Native compiler/CMake/PE-COFF pipeline (37 adapter PASS; 16 linker unexecuted; CI empty) | UNVERIFIED | PR75;H41;H42;I57-B;H103 | `3bbda91366161c08c103cd1111dc413e92bdd25b` | gh:#75 | Native linker tests + Windows PE runtime; CI steps>0 |
| PR76 | Deep2 + native compiler consolidation (draft; CI BlobNotFound) | UNVERIFIED | PR76;H10;H104 | `e91b476b51902e26fd1b0c3678ffce84efe7057d` | gh:#76 | Reconcile divergence/conflicts; CI before merge |
| PR77 | IDE product path ConPTY/inference UI/Problems/output | UNVERIFIED | PR77;G-PROBLEMS;G-FOUR-PANEL;G-TERM | `9edf63fed82bdf427f734591bff262282f6fe822` | gh:#77 | SHA-specific four-panel evidence; MERGE_AUTHORIZED=0 |
| PR78 | AgentSession GUI lifecycle/cancel/cleanup | UNVERIFIED | PR78;H57-H72 | `84b4725f798f329a31660e87820c2f57115247ce` | gh:#78 | Session start/stop/kill/restore proof on branch EXE |
| PR79 | ExtensionHost runtime host/worker IPC/shutdown/crash recovery | UNVERIFIED | PR79;H43-H56;INTEG004-EXT-CLEANUP | `13c33a6f35c6493cd5bf60a9f5f0a21f6271ef8c` | gh:#79 | Real extension load/execute + clean shutdown |
| D001 | Historical DEFECT_REGISTER debugger UI-simulation claim | INVESTIGATE | D001;G-IDE-DEBUG-UI;G-DEBUG-HEADLESS | `CC79F6CD…A22940C4` | RAWRXD_FULL_IDE_AUDIT_003\DEFECT_REGISTER.csv | Reconcile stub claim vs CC79 headless PASS + UI FAIL |
| I57-A01 | Resolve GHA runner_id=0 empty steps; successful Linux+Windows run | CONFIRMED | I57-A01;H103;PR75;PR76 | n/a-ci | gh:#57;#75;#76 | Capture Actions run with steps>0 |
| I57-A02 | Re-run source-only per-file SHA-256 inventory; archive JSON | UNVERIFIED | I57-A02;H01;H12 | `CC79F6CD…A22940C4` | gh:#57 | Machine-readable inventory receipt |
| I57-A03 | Re-run CMake literal-source admission; disposition missing paths | UNVERIFIED | I57-A03;H01;H05 | `CC79F6CD…A22940C4` | gh:#57 | Admission disposition log |
| I57-A04 | Strict no-external-dependencies scan; quarantine Qt/nlohmann | UNVERIFIED | I57-A04;H04 | `CC79F6CD…A22940C4` | gh:#57 | Scan receipt |
| I57-A05 | Frozen manifest feature→TU→call site | UNVERIFIED | I57-A05;H01-H03 | `CC79F6CD…A22940C4` | gh:#57 | Manifest artifact |
| I57-A06 | Rebuild real native Win32 IDE clean checkout no-Qt | UNVERIFIED | I57-A06;H06;H12 | `CC79F6CD…A22940C4` | gh:#57 | Clean-build EXE SHA |
| I57-A07 | Rebuild rawr.exe and snapshot/agent targets same checkout | UNVERIFIED | I57-A07 | `CC79F6CD…A22940C4` | gh:#57 | Target SHA receipts |
| I57-A08 | Launch Win32 IDE save/close/reopen compare file SHA-256 | UNVERIFIED | I57-A08;H26 | `CC79F6CD…A22940C4` | gh:#57 | Roundtrip SHA compare |
| I57-A09 | Verify terminal start/output/exit/cancel/cleanup | UNVERIFIED | I57-A09;G-TERM;F25-T17 | `CC79F6CD…A22940C4` | gh:#57; term_smoke_receipt_CC79 | Full cancel/cleanup beyond sealed smoke |
| I57-A10 | Verify native PowerShell panel lifecycle | UNVERIFIED | I57-A10 | `CC79F6CD…A22940C4` | gh:#57 | Panel lifecycle receipt |
| I57-A11 | Verify native LSP JSON-RPC handshake/diagnostics/defs/completion | UNVERIFIED | I57-A11;H107 | `CC79F6CD…A22940C4` | gh:#57 | LSP E2E receipt |
| I57-A12 | Verify GhostText display/accept/cancel real model adapter | UNVERIFIED | I57-A12;H108 | `CC79F6CD…A22940C4` | gh:#57 | GhostText E2E on tip SHA |
| I57-A13 | Verify native browser rendering/origin isolation/lifecycle | UNVERIFIED | I57-A13;H109 | `CC79F6CD…A22940C4` | gh:#57 | Browser isolation receipt |
| I57-A14 | Verify debugger BP/step/watch/vars in real debuggee | UNVERIFIED | I57-A14;G-IDE-DEBUG-UI | `CC79F6CD…A22940C4` | gh:#57; DEBUG_CONSOLE_GATE | IDE UI E2E (headless ≠ credit) |
| I57-A15 | Prove IDE agent edit→build→test→snapshot rollback | UNVERIFIED | I57-A15;ISSUE49;H120 | `CC79F6CD…A22940C4` | gh:#57;#49 | Product-final loop on one SHA |
| I57-B01 | Recover slingshot braid format owners with hashes | UNVERIFIED | I57-B01;PR75 | `CC79F6CD…A22940C4` | gh:#57 | Hash-identified sources |
| I57-B02 | SBraid emitter/read-back roundtrip + corrupt rejection | UNVERIFIED | I57-B02 | `CC79F6CD…A22940C4` | gh:#57 | Roundtrip receipt |
| I57-B03 | Review SlingshotGuard concurrency before Deep2 integration | UNVERIFIED | I57-B03 | `CC79F6CD…A22940C4` | gh:#57 | Review disposition |
| I57-B04 | Replace SlingshotPOC simulated VRAM if promoted | UNVERIFIED | I57-B04;H84 | `CC79F6CD…A22940C4` | gh:#57 | Real allocator measure if promoted |
| I57-B05 | Reconcile legacy slingshot vs Deep2 residency/loader | UNVERIFIED | I57-B05;PR76 | `CC79F6CD…A22940C4` | gh:#57 | No speculative blind merge |
| I57-B06 | Recover compiler/linker source inventory MASM/native | UNVERIFIED | I57-B06;PR75 | `CC79F6CD…A22940C4` | gh:#57 | Inventory receipt |
| I57-B07 | Prove native C frontend compiles representative programs | UNVERIFIED | I57-B07;H42 | `CC79F6CD…A22940C4` | gh:#57 | Compile+run receipt |
| I57-B08 | Prove native C++20 frontend templates/exceptions/ABI | UNVERIFIED | I57-B08;H42 | `CC79F6CD…A22940C4` | gh:#57 | Compile+run receipt |
| I57-B09 | Prove MASM x86/x64 COFF interoperability with oracle | UNVERIFIED | I57-B09 | `CC79F6CD…A22940C4` | gh:#57 | Oracle compare |
| I57-B10 | Prove NASM x86/x64 object interoperability with oracle | UNVERIFIED | I57-B10 | `CC79F6CD…A22940C4` | gh:#57 | Oracle compare |
| I57-B11 | Prove rawrxd native linker PE32/PE32+ | UNVERIFIED | I57-B11;H41;PR75 | `CC79F6CD…A22940C4` | gh:#57;#75 | PE link+execute (16 tests still unexecuted) |
| I57-B12 | Prove compile→link→execute without external compiler | UNVERIFIED | I57-B12;H42 | `CC79F6CD…A22940C4` | gh:#57 | End-to-end native toolchain |
| I57-B13 | ELF/Linux capability vs host-toolchain fallback + smoke | OUT_OF_SCOPE | I57-B13;H114 | n/a | gh:#57 | Outside Windows daily-driver 100% spec unless expanded |
| I57-B14 | Mach-O/macOS/iOS contracts with macOS runner evidence | OUT_OF_SCOPE | I57-B14;H114 | n/a | gh:#57 | Outside Windows daily-driver 100% spec unless expanded |
| I57-B15 | Android ABI/ELF/APK contracts with device evidence | OUT_OF_SCOPE | I57-B15;H114 | n/a | gh:#57 | Outside Windows daily-driver 100% spec unless expanded |
| I57-C01 | Deterministic reference model/quant baseline receipts | UNVERIFIED | I57-C01 | `CC79F6CD…A22940C4` | gh:#57 | Tokenizer/logits/token archive |
| I57-C02 | Verify ffn_gate_up multi-token GPU path before perf promote | UNVERIFIED | I57-C02 | `CC79F6CD…A22940C4` | gh:#57 | GPU path receipt |
| I57-C03 | Verify Deep2 Q4_K/Q5_K/Q6_K/F32 fused GEMV vs oracles | UNVERIFIED | I57-C03;H79;PR76 | `CC79F6CD…A22940C4` | gh:#57 | Numerical oracle |
| I57-C04 | Compare four fused GEMV paths submit/fence wait counts | UNVERIFIED | I57-C04 | `CC79F6CD…A22940C4` | gh:#57 | Fence-count compare |
| I57-C05 | Lane-state restoration success/error/fallback/dual-GPU | UNVERIFIED | I57-C05;H82 | `CC79F6CD…A22940C4` | gh:#57 | Lane restore matrix |
| I57-C06 | Measure R9700 single-GPU TPS 32/128/256 | UNVERIFIED | I57-C06;H88 | `CC79F6CD…A22940C4` | gh:#57 | Paired control measure |
| I57-C07 | Measure RX7800 XT single-GPU TPS 32/128/256 | UNVERIFIED | I57-C07;H88 | `CC79F6CD…A22940C4` | gh:#57 | Paired control measure |
| I57-C08 | Measure dual-GPU full-model TPS both devices | UNVERIFIED | I57-C08;H82;H83 | `CC79F6CD…A22940C4` | gh:#57 | No-fallback counters |
| I57-C09 | Attribute GPU0 fence waits and GPU1 overlap | UNVERIFIED | I57-C09;H83 | `CC79F6CD…A22940C4` | gh:#57 | Timestamp/PCIe receipts |
| I57-C10 | Certify GGUF shard/index/quant/arch on supported matrix | UNVERIFIED | I57-C10;H89 | `CC79F6CD…A22940C4` | gh:#57 | Matrix parse receipts |
| I57-C11 | Nemotron SSM Q4_K NaN/residual parity | UNVERIFIED | I57-C11;H79 | `CC79F6CD…A22940C4` | gh:#57 | Residual parity receipt |
| I57-C12 | Benchmark real-model 150+ single-stream decode TPS if attainable | UNVERIFIED | I57-C12;H88;H115 | `CC79F6CD…A22940C4` | gh:#57 | Real decode only; no synthetic kernel TPS |
| I57-C13 | Identical model/sampling/seed/context/clocks for perf A/B | UNVERIFIED | I57-C13 | `CC79F6CD…A22940C4` | gh:#57 | A/B control receipt |
| I57-C14 | Apply 25×20=500-cell feature matrix with real evidence | UNVERIFIED | I57-C14;F25;H117 | `CC79F6CD…A22940C4` | gh:#57 | Do not prefill certification |
| I57-C15 | Certify signed/reproducible packaging/security/rollback/release | UNVERIFIED | I57-C15;F25-T24;H98-H106 | `CC79F6CD…A22940C4` | gh:#57 | Signed package E2E |

### H01–H120 investigation register

Default status INVESTIGATE unless overridden by local evidence above. MapsTo includes Finish25 / Issue / PR aliases where overlap exists.

| ID | Title | Status | MapsTo | ControllingSHA | EvidencePath | NextProof |
|----|-------|--------|--------|----------------|--------------|-----------|
| H01 | AgentSession / rawrxd_agentic_backend implemented but NOT linked into RawrXD-Win32IDE-Native-Ext | CONFIRMED | H01;PR78;ISSUE49;FIVE_LAYER | `CC79F6CD…A22940C4` | FIVE_LAYER_SOURCE_AUDIT_001.md; CMakeLists.txt:4084-4111 vs :5547-5554 | Link agentic backend into Ext product path; then AgentSession E2E on same SHA |
| H02 | Debugger IDC namespace split (Win32IDE.cpp 1313+ vs Win32IDE_Debugger.cpp 2100+ createDebuggerUI) | CONFIRMED | H02;G-IDE-DEBUG-UI;I57-A14;FIVE_LAYER | `CC79F6CD…A22940C4` | FIVE_LAYER_SOURCE_AUDIT_001.md; Win32IDE.cpp:1435-1453; Win32IDE_Debugger.cpp:21-36 | Unify IDC schema; remeasure IDE Debug UI SESSION_REAL |
| H03 | Stub functions silently replacing production functionality | INVESTIGATE | H03;D001 | `CC79F6CD…A22940C4` | parent H-register | Symbol audit + runtime |
| H04 | Feature flags disabling important components in release builds | INVESTIGATE | H04;I57-A04 | `CC79F6CD…A22940C4` | parent H-register | Release-config audit |
| H05 | Missing source dependencies concealed by incremental builds | INVESTIGATE | H05;I57-A03 | `CC79F6CD…A22940C4` | parent H-register | Clean rebuild admission |
| H06 | Stale object files producing apparently successful builds | INVESTIGATE | H06;I57-A06 | `CC79F6CD…A22940C4` | parent H-register | Clean rebuild |
| H07 | Debug and Release configurations behaving differently | INVESTIGATE | H07 | `CC79F6CD…A22940C4` | parent H-register | Config A/B |
| H08 | Incorrect compiler definitions or inherited environment variables | UNVERIFIED | H08;H27 | `CC79F6CD…A22940C4` | COMPILER_ROOT_CAUSE_001.txt | Broader env-poison audit beyond VS_UNICODE |
| H09 | Unresolved symbols hidden behind optional build paths | INVESTIGATE | H09 | `CC79F6CD…A22940C4` | parent H-register | Link-map audit |
| H10 | Different branches containing incompatible implementations | INVESTIGATE | H10;PR76;H104 | `CC79F6CD…A22940C4` | gh:#76 | Branch reconcile |
| H11 | Generated headers or resources missing from clean checkout | INVESTIGATE | H11 | `CC79F6CD…A22940C4` | parent H-register | Clean-checkout build |
| H12 | Non-reproducible binaries despite identical source revisions | INVESTIGATE | H12;I57-A02 | `CC79F6CD…A22940C4` | parent H-register | Repro SHA compare |
| H13 | Menu/command ID drift: F:\ 3014=Build vs PR77 tip 3014=GGUF; Core File 1001 vs menu 2001 | CONFIRMED | H13;H10;PR77;FIVE_LAYER | `CC79F6CD…A22940C4` | FIVE_LAYER_SOURCE_AUDIT_001.md; Win32IDE_CommandIDs.h:51; PR77_ACCEPTANCE_001\RECEIPT.md | Freeze single command-ID SSOT before harness/four-panel binds 3014 |
| H14 | Toolbar buttons displaying but not executing | INVESTIGATE | H14 | `CC79F6CD…A22940C4` | parent H-register | Toolbar invoke audit |
| H15 | Keyboard shortcuts bypassing correct command path | INVESTIGATE | H15 | `CC79F6CD…A22940C4` | parent H-register | Accelerator path audit |
| H16 | HWND references surviving after window destruction | INVESTIGATE | H16;PR78 | `CC79F6CD…A22940C4` | parent H-register | Stale-HWND tests |
| H17 | Worker threads modifying Win32 controls directly | INVESTIGATE | H17;PR77 | `CC79F6CD…A22940C4` | parent H-register | Cross-thread dispatch audit |
| H18 | Posted messages arriving after session cancellation | INVESTIGATE | H18;H58 | `CC79F6CD…A22940C4` | parent H-register | Cancel+stale-message tests |
| H19 | Reentrant window procedures corrupting application state | INVESTIGATE | H19 | `CC79F6CD…A22940C4` | parent H-register | Reentrancy stress |
| H20 | Focus switching between panels breaking keyboard input | INVESTIGATE | H20 | `CC79F6CD…A22940C4` | parent H-register | Focus matrix |
| H21 | Incorrect DPI scaling or panel geometry | INVESTIGATE | H21 | `CC79F6CD…A22940C4` | parent H-register | DPI geometry measure |
| H22 | Resize operations destroying or obscuring controls | INVESTIGATE | H22 | `CC79F6CD…A22940C4` | parent H-register | Resize stress |
| H23 | Modal dialogs blocking active background operations | INVESTIGATE | H23 | `CC79F6CD…A22940C4` | parent H-register | Modal+bg interaction |
| H24 | UI thread deadlocks during compiler or model execution | INVESTIGATE | H24;H27 | `CC79F6CD…A22940C4` | parent H-register | Hang reproduction |
| H25 | Unhandled exceptions inside message dispatch | INVESTIGATE | H25 | `CC79F6CD…A22940C4` | parent H-register | Fault injection |
| H26 | Window recreation losing application state | INVESTIGATE | H26;F25-T10 | `CC79F6CD…A22940C4` | parent H-register; F25-T10 sealed | Beyond T10 recovery scope |
| H27 | Compiler subprocess inheriting incompatible env (VS_UNICODE_OUTPUT stall) | CONFIRMED | H27;G-PROBLEMS;COMPILER_ROOT_CAUSE;PR75;PR77 | `CC79F6CD…A22940C4` | PROBLEMS_PANEL_GATE.md; artifacts\COMPILER_ROOT_CAUSE_001.txt; COMPILER_CAPTURE_ISOLATED_RECEIPT.txt | IDE rebuild measure; items>0. Fix SOURCE_WIRED≠RUNTIME_REACHED on CC79 |
| H28 | Stdout/stderr pipe backpressure causing deadlocks | INVESTIGATE | H28;H27 | `CC79F6CD…A22940C4` | COMPILER_ROOT_CAUSE secondary note | Concurrent output stress |
| H29 | Compiler child processes surviving cancellation | INVESTIGATE | H29;H30 | `CC79F6CD…A22940C4` | parent H-register | Cancel descendant proof |
| H30 | Timeout terminating parent but not descendants | INVESTIGATE | H30;PR75 | `CC79F6CD…A22940C4` | gh:#75 Windows taskkill pending | Descendant kill proof |
| H31 | Diagnostics parsed incorrectly when paths contain spaces | INVESTIGATE | H31 | `CC79F6CD…A22940C4` | parent H-register | Spaced-path fixture |
| H32 | Unicode diagnostic text corrupted | INVESTIGATE | H32;H27 | `CC79F6CD…A22940C4` | parent H-register | Unicode diag fixture |
| H33 | Compiler warnings mistaken for errors | INVESTIGATE | H33 | `CC79F6CD…A22940C4` | parent H-register | Warning/error classify |
| H34 | Duplicate Problems entries from repeated builds | INVESTIGATE | H34;G-PROBLEMS | `CC79F6CD…A22940C4` | PROBLEMS_PANEL_GATE (items=0 blocks) | After feed works: dedupe proof |
| H35 | Old diagnostics remaining after successful rebuild | INVESTIGATE | H35;G-PROBLEMS | `CC79F6CD…A22940C4` | PROBLEMS_PANEL_GATE | Clear-on-success proof |
| H36 | Problems click-to-line without actual navigation | UNVERIFIED | H36;G-PROBLEMS;INTEG004-PROBLEMS | `CC79F6CD…A22940C4` | PROBLEMS_PANEL_GATE.md (CLICK_TO_LINE=NOT_RUN) | Measure on CC79; INTEG_004 PASS not inherited |
| H37 | Incorrect line/column offsets | INVESTIGATE | H37 | `CC79F6CD…A22940C4` | parent H-register | Offset oracle |
| H38 | Multiple projects mixing diagnostic ownership | INVESTIGATE | H38 | `CC79F6CD…A22940C4` | parent H-register | Multi-project fixture |
| H39 | Linker errors missing from Problems | INVESTIGATE | H39;H41 | `CC79F6CD…A22940C4` | parent H-register | Linker-error feed |
| H40 | Failed builds reporting success because artifacts exist | INVESTIGATE | H40 | `CC79F6CD…A22940C4` | parent H-register | Stale-artifact negative |
| H41 | Native PE/COFF linker accepting malformed relocations | INVESTIGATE | H41;PR75;I57-B11 | `CC79F6CD…A22940C4` | gh:#75 (negative tests exist; runtime not certified) | Execute native linker negative suite |
| H42 | Compiler adapter PASS while native compiler incomplete | UNVERIFIED | H42;PR75;I57-B07-B12 | `CC79F6CD…A22940C4` | gh:#75 | Adapter≠native frontend completeness |
| H43 | Extension discovery works but activation never executes | INVESTIGATE | H43;G-EXT;PR79 | `CC79F6CD…A22940C4` | MASTER_STATUS_CC79 EXT PASS | Lifecycle beyond smoke |
| H44 | Worker starts without completing IPC handshake | INVESTIGATE | H44;PR79 | `CC79F6CD…A22940C4` | parent H-register | IPC handshake proof |
| H45 | IPC messages lack framing or size validation | INVESTIGATE | H45;PR79 | `CC79F6CD…A22940C4` | parent H-register | Framing fuzz |
| H46 | Extension commands execute on wrong thread | INVESTIGATE | H46;H17 | `CC79F6CD…A22940C4` | parent H-register | Thread affinity |
| H47 | Host and worker disagree on protocol version | INVESTIGATE | H47 | `CC79F6CD…A22940C4` | parent H-register | Version negotiate |
| H48 | Extension crashes terminate entire IDE | INVESTIGATE | H48;PR79 | `CC79F6CD…A22940C4` | parent H-register | Crash isolation |
| H49 | Unloading leaves callbacks registered | INVESTIGATE | H49 | `CC79F6CD…A22940C4` | parent H-register | Unload leak |
| H50 | Reloading creates duplicate commands/subscriptions | INVESTIGATE | H50 | `CC79F6CD…A22940C4` | parent H-register | Reload dup |
| H51 | Extension process survives IDE shutdown | CONFIRMED | H51;INTEG004-EXT-CLEANUP;PR79 | `47451F24…DC274F` | INTEG004_EXT_REVERIFY_RECEIPT.md (FORCE_KILL=1) | Clean --ext-quit; recheck CC79 separately |
| H52 | Crashed workers cannot restart cleanly | INVESTIGATE | H52;PR79 | `CC79F6CD…A22940C4` | parent H-register | Crash-restart |
| H53 | Extension filesystem access bypasses permissions | INVESTIGATE | H53;H91 | `CC79F6CD…A22940C4` | parent H-register | Permission fence |
| H54 | Extension event handlers block the UI | INVESTIGATE | H54 | `CC79F6CD…A22940C4` | parent H-register | Handler latency |
| H55 | Extension state corrupts across projects | INVESTIGATE | H55 | `CC79F6CD…A22940C4` | parent H-register | Project switch |
| H56 | Test extension passes but real extensions fail | INVESTIGATE | H56;PR79 | `CC79F6CD…A22940C4` | parent H-register | Real VSIX E2E |
| H57 | Agent session lifetime not owned by single controller | INVESTIGATE | H57;PR78 | `CC79F6CD…A22940C4` | gh:#78 | Ownership proof |
| H58 | Cancelled agent continues executing tools | INVESTIGATE | H58;F25-T05;PR78 | `CC79F6CD…A22940C4` | parent H-register | Cancel tool stop |
| H59 | Old tool results injected into newer conversation | INVESTIGATE | H59 | `CC79F6CD…A22940C4` | parent H-register | Result-epoch check |
| H60 | Model-generated tool calls parsed incorrectly | INVESTIGATE | H60 | `CC79F6CD…A22940C4` | parent H-register | Parse fixtures |
| H61 | Tool permission checks bypassed by alternate entry points | INVESTIGATE | H61;H92 | `CC79F6CD…A22940C4` | parent H-register | Authz matrix |
| H62 | Agent edits wrong workspace or file | INVESTIGATE | H62 | `CC79F6CD…A22940C4` | parent H-register | Path bind proof |
| H63 | Partial writes leave corrupted source | INVESTIGATE | H63 | `CC79F6CD…A22940C4` | parent H-register | Atomic write proof |
| H64 | Failed edits cannot be rolled back | INVESTIGATE | H64;H111;I57-A15 | `CC79F6CD…A22940C4` | parent H-register | Snapshot rollback |
| H65 | Agent reports build success without executable evidence | INVESTIGATE | H65;H102 | `CC79F6CD…A22940C4` | parent H-register | Evidence-gated success |
| H66 | Agent loops indefinitely after repeated failures | INVESTIGATE | H66 | `CC79F6CD…A22940C4` | parent H-register | Loop bound |
| H67 | Tool execution blocks model streaming | INVESTIGATE | H67;PR77 | `CC79F6CD…A22940C4` | parent H-register | Stream+tool overlap |
| H68 | Concurrent agents overwrite one another's changes | INVESTIGATE | H68 | `CC79F6CD…A22940C4` | parent H-register | Concurrency fence |
| H69 | Agent state cannot recover after application restart | INVESTIGATE | H69;F25-T10 | `CC79F6CD…A22940C4` | parent H-register | Restart recovery |
| H70 | Review agent approves untested changes | INVESTIGATE | H70;ISSUE49 | `CC79F6CD…A22940C4` | gh:#49 | Reviewer gate |
| H71 | Git commit includes unrelated modifications | INVESTIGATE | H71;H110 | `CC79F6CD…A22940C4` | parent H-register | Commit scope |
| H72 | Agent reports completion before final tests finish | INVESTIGATE | H72;ISSUE49 | `CC79F6CD…A22940C4` | gh:#49 | Test-before-complete |
| H73 | Model selector points to wrong model or backend | INVESTIGATE | H73 | `CC79F6CD…A22940C4` | parent H-register | Backend identity receipt |
| H74 | Ollama streaming parser mishandles fragmented JSON | INVESTIGATE | H74 | `CC79F6CD…A22940C4` | parent H-register | Fragment fixtures |
| H75 | Inference cancellation leaves active GPU work | INVESTIGATE | H75;F25-T05 | `CC79F6CD…A22940C4` | parent H-register | GPU cancel proof |
| H76 | Backend shutdown leaks threads or memory | INVESTIGATE | H76;F25-T19 | `CC79F6CD…A22940C4` | parent H-register | Leak trend |
| H77 | Model loading succeeds but inference produces invalid output | INVESTIGATE | H77 | `CC79F6CD…A22940C4` | parent H-register | Finite logits/gen |
| H78 | GPU offload counters differ from actual executed ops | INVESTIGATE | H78;I57-C06-C09 | `CC79F6CD…A22940C4` | parent H-register | Counter vs GPU trace |
| H79 | Quantized kernels produce incorrect numerical results | INVESTIGATE | H79;I57-C03;I57-C11 | `CC79F6CD…A22940C4` | parent H-register | Oracle parity |
| H80 | KV-cache rollback corrupts subsequent generations | INVESTIGATE | H80 | `CC79F6CD…A22940C4` | parent H-register | Rollback fixture |
| H81 | Long-context allocation exceeds available VRAM/RAM | INVESTIGATE | H81 | `CC79F6CD…A22940C4` | parent H-register | OOM disposition |
| H82 | Multi-GPU partitioning causes incorrect tensor placement | INVESTIGATE | H82;I57-C08 | `CC79F6CD…A22940C4` | parent H-register | Placement receipt |
| H83 | GPU sync serializes supposedly parallel execution | INVESTIGATE | H83;I57-C09 | `CC79F6CD…A22940C4` | parent H-register | Overlap timestamps |
| H84 | Fallback paths silently execute on CPU | INVESTIGATE | H84;I57-B04 | `CC79F6CD…A22940C4` | parent H-register | No-silent-CPU proof |
| H85 | Driver incompatibility mistaken for model defect | INVESTIGATE | H85 | `CC79F6CD…A22940C4` | parent H-register | Driver classify |
| H86 | Model switching retains stale tokenizer/sampler state | INVESTIGATE | H86 | `CC79F6CD…A22940C4` | parent H-register | Switch flush |
| H87 | GPU device loss cannot recover without IDE restart | INVESTIGATE | H87 | `CC79F6CD…A22940C4` | parent H-register | Device-loss recovery |
| H88 | Benchmark throughput excludes prefill/waits/transfers undisclosed | INVESTIGATE | H88;I57-C12;H115 | `CC79F6CD…A22940C4` | parent H-register | Disclose methodology |
| H89 | GGUF shard validation accepts corrupt data | INVESTIGATE | H89;I57-C10 | `CC79F6CD…A22940C4` | parent H-register | Corrupt reject |
| H90 | Local-only operation depends on external services | INVESTIGATE | H90 | `CC79F6CD…A22940C4` | parent H-register | Offline proof |
| H91 | Workspace path traversal through agent/extension tools | INVESTIGATE | H91;H53 | `CC79F6CD…A22940C4` | parent H-register | Traversal negatives |
| H92 | Untrusted model output bypasses tool authorization | INVESTIGATE | H92;H61 | `CC79F6CD…A22940C4` | parent H-register | Authz bypass attempt |
| H93 | Shell argument handling allows unintended command execution | INVESTIGATE | H93 | `CC79F6CD…A22940C4` | parent H-register | Argv injection |
| H94 | Sensitive values leak into logs or crash dumps | INVESTIGATE | H94 | `CC79F6CD…A22940C4` | parent H-register | Secret scan |
| H95 | Extension IPC accepts unauthorized commands | INVESTIGATE | H95;H45 | `CC79F6CD…A22940C4` | parent H-register | IPC authz |
| H96 | Downloaded/installed extensions lack validation | INVESTIGATE | H96 | `CC79F6CD…A22940C4` | parent H-register | Install validate |
| H97 | Security-sensitive paths use placeholder cryptography | INVESTIGATE | H97 | `CC79F6CD…A22940C4` | parent H-register | Crypto audit |
| H98 | Release binaries depend on undeclared DLLs | INVESTIGATE | H98;F25-T24 | `CC79F6CD…A22940C4` | parent H-register | Dependency walk |
| H99 | Installer writes outside intended directories | INVESTIGATE | H99;F25-T24 | `CC79F6CD…A22940C4` | parent H-register | Install path audit |
| H100 | Uninstall/rollback destroys user data | INVESTIGATE | H100;F25-T24 | `CC79F6CD…A22940C4` | parent H-register | Rollback safety |
| H101 | Crash recovery replays unsafe/incomplete operations | INVESTIGATE | H101;F25-T18 | `CC79F6CD…A22940C4` | parent H-register | Recovery replay |
| H102 | Build artifacts/receipts accepted without provenance | INVESTIGATE | H102;H65;H106 | `CC79F6CD…A22940C4` | parent H-register | Provenance gate |
| H103 | GitHub Actions reports success without executing mandatory tests | CONFIRMED | H103;I57-A01;PR75;PR76 | n/a-ci | gh:#57;#75;#76 (empty steps / BlobNotFound) | Successful run with steps>0 |
| H104 | LFS or branch divergence leaves release source incomplete | INVESTIGATE | H104;PR76;H10 | `CC79F6CD…A22940C4` | gh:#76 | Source completeness |
| H105 | Signed artifact differs from tested executable | INVESTIGATE | H105;I57-C15 | `CC79F6CD…A22940C4` | parent H-register | Sign≠test detect |
| H106 | Final release certified using evidence from multiple SHAs | UNVERIFIED | H106;ISSUE49;F25-T25;LINEAGE | `CC79F6CD…A22940C4` | LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md | Single-SHA product-final only |
| H107 | LSP handshake succeeds but diagnostics/completion fail | INVESTIGATE | H107;I57-A11 | `CC79F6CD…A22940C4` | parent H-register | LSP functional E2E |
| H108 | GhostText accept/cancel edits wrong range | INVESTIGATE | H108;I57-A12 | `CC79F6CD…A22940C4` | parent H-register | Range oracle |
| H109 | Native browser lacks origin/navigation isolation | INVESTIGATE | H109;I57-A13 | `CC79F6CD…A22940C4` | parent H-register | Isolation E2E |
| H110 | Git operations modify unintended repo/branch | INVESTIGATE | H110;H71 | `CC79F6CD…A22940C4` | parent H-register | Repo bind |
| H111 | Snapshot restoration fails after partial edit | INVESTIGATE | H111;H64;I57-A15 | `CC79F6CD…A22940C4` | parent H-register | Partial-edit restore |
| H112 | Settings persist but not applied to active components | INVESTIGATE | H112 | `CC79F6CD…A22940C4` | parent H-register | Apply-on-change |
| H113 | Feature registry advertises commands with no real backend | INVESTIGATE | H113;H13 | `CC79F6CD…A22940C4` | parent H-register | Registry→impl |
| H114 | Cross-platform functionality claimed without native execution | OUT_OF_SCOPE | H114;I57-B13-B15 | n/a | Issue57 B13–B15 + scope law | OOS unless Windows daily-driver spec expands |
| H115 | Performance tests use synthetic kernels instead of real decode | INVESTIGATE | H115;I57-C12;H88 | `CC79F6CD…A22940C4` | parent H-register | Real-decode only |
| H116 | Release docs describe capabilities absent from binary | INVESTIGATE | H116 | `CC79F6CD…A22940C4` | parent H-register | Doc↔binary audit |
| H117 | Acceptance tests omit negative and recovery scenarios | INVESTIGATE | H117;I57-C14 | `CC79F6CD…A22940C4` | parent H-register | Negative suite |
| H118 | Multiple passing components fail when operated simultaneously | CONFIRMED | H118;G-FOUR-PANEL | `CC79F6CD…A22940C4` | FOUR_PANEL_INTEGRATION.md (OPEN) | Integrated four-panel on one SHA |
| H119 | Test fixtures conceal environment/dependency requirements | INVESTIGATE | H119 | `CC79F6CD…A22940C4` | parent H-register | Fixture transparency |
| H120 | Final product acceptance omits complete autonomous coding loop | UNVERIFIED | H120;ISSUE49 | `CC79F6CD…A22940C4` | gh:#49 | ISSUE49_MILESTONE=NOT_DEMONSTRATED |

---

## Optional CSV

Companion matrix (same columns): `MASTER_HIDDEN_GAP_REGISTER_001.csv` (write if generator available; MD is authoritative).

## Authority footnotes

```
CONTROLLING_TIP=CC79 tip_final_integ_002
CANDIDATE_INTEG_004_SEALED=47451F24… (Problems UI PASS; EXT_CLEANUP FAIL; EXE ABSENT)
CANDIDATE_TIP004_LIVE_LINEAGE=
  69FE3D92… (post-incr overwrite)
  35EFA9BA… (measured Problems PASS / IDE_DEBUG_UI; pre-drift)
  7504BAC4… (intermediate disk drift; not measured PASS inherit)
  27E2263E… (VT A+B rebuild of tip_004; FROZEN_STOP_OVERWRITE)
TIP_005_UNIFY=IN_FLIGHT (candidates\tip_final_integ_005 present; owner 973ed563; do not fight)
TIP_003_004_MUST_NOT_SUPERSEDE_CC79=1
EA5D_MUST_NOT_SUPERSEDE=1
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82% (unchanged; Issue #49 single-SHA milestone NOT measured)
```

## ABSORB_DELTA

```
ABSORB_ASOF_UTC=2026-11-09T12:55:00Z
BASE=d3bda9f6-2dad-4b6f-878c-d126fc6af20b MASTER_HIDDEN_GAP_REGISTER_001.md (195 rows retained as base)
MODE=ADDITIVE_MERGE_ONLY (no wholesale replace)
PROMOTE=0
CONTROLLING_TIP=CC79
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0

ADDED_IDS=
  TIP004-LIVE-SHA-CHURN = CONFIRMED
    cite: LOCAL_INTEG004_FINISH25_LOCATOR.md
    fact: tip_004 live 69FE3D92… overwrote sealed 47451F24… image; CROSS_SHA_PASS_INHERIT=0

STATUS_UPGRADES (CONFIRMED evidence was missing on base INVESTIGATE rows):
  H01 INVESTIGATE -> CONFIRMED (AgentSession not linked into Ext)
    cite: FIVE_LAYER_SOURCE_AUDIT_001.md
  H02 INVESTIGATE -> CONFIRMED (debugger IDC 1313+ vs 2100+)
    cite: FIVE_LAYER_SOURCE_AUDIT_001.md
  H13 INVESTIGATE -> CONFIRMED (3014 / File ID menu drift)
    cite: FIVE_LAYER_SOURCE_AUDIT_001.md

NOT_ADDED=
  TERMINAL_VT_RENDER_FAIL_001 = ABSENT (no dedicated VT row; condition not met)
  GITHUB_ACCEPTANCE_RECONCILE_001 = already covered by ISSUE49/50/57 + PR75-79 board rows (no missing CONFIRMED/lineage row)
  Wholesale rewrite of H03-H120 / I57 / F25 boards = forbidden this absorb

COUNTS_AFTER=
  CONFIRMED=13 UNVERIFIED=61 INVESTIGATE=108 SEALED_PASS=10 OUT_OF_SCOPE=4 TOTAL_RETAINED=196
```

## ABSORB_DELTA_VT

```
ABSORB_ASOF_UTC=2026-11-09T13:03:05Z
PRIOR_ABSORB=54ce37f3 Merge audits preserve master (TERMINAL_VT marked ABSENT)
MODE=ADDITIVE_ONLY (no wholesale rewrite; do not fight tip_005 rebuild owned by 973ed563)
PROMOTE=0
CONTROLLING_TIP=CC79
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0

RECEIPT_NOW_PRESENT=
  artifacts\TERMINAL_VT_RENDER_FAIL_001.txt
  fact: tip_hwnd_repair_001 RUNNING_SHA B2AD7E9B… ≠ CC79
  CONSOLE_RENDER=FAIL; CMD_EXEC=UNVERIFIED
  A+B SOURCE_WIRED (startNonInteractive + stripVtForRichEdit)
  tip_004 rebuilt POST_PATCH 27E2263E… (CC79 untouched)

ADDED_IDS=
  G-CONSOLE-VT-RENDER = CONFIRMED (FAIL)
  H-VT-RICHEDIT = CONFIRMED

UPDATED_IDS=
  TIP004-LIVE-SHA-CHURN lineage extended beyond 69FE3D92/47451F24:
    + measured Problems PASS tip_004 35EFA9BA…
    + drift 7504BAC4…
    + VT overwrite 27E2263E…
    + tip_005 unify IN_FLIGHT (candidates\tip_final_integ_005 folder present; owner 973ed563)

NOT_TOUCHED=
  tip_005 rebuild ownership / unify content (973ed563)
  Sealed CC79 / A4F / INTEG_004 47451F24 acceptance claims
  Wholesale H03–H120 / I57 / F25 rewrite

COUNTS_AFTER=
  CONFIRMED=15 UNVERIFIED=61 INVESTIGATE=108 SEALED_PASS=10 OUT_OF_SCOPE=4 TOTAL_RETAINED=198
```

END_REGISTER

## ABSORB_DELTA G-CHAT-EXACTLY-ONCE

```
ABSORB_ASOF_LOCAL=2026-11-09T11:08-05
ADDED_ID=G-CHAT-EXACTLY-ONCE
STATUS=UNVERIFIED
EXACTLY_ONCE=NOT_VERIFIED
BUTTON_SHA=7B3C0ECB46A2AF063D626057111B0EF6730607AC839B40A805A121ABF1756655
CTRL_ENTER_SHA=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
MULTI_BLOCK_REPRODUCED=0
SEALED_G_CHAT_7_7=UNCHANGED
TIP_005_UNTOUCHED=1
PROMOTE=0
MATURITY_HELD=82
EVIDENCE=artifacts\CHAT_EXACTLY_ONCE_001\
```
