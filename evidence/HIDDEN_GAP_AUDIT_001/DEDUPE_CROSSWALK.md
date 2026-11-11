# DEDUPE_CROSSWALK — HIDDEN_GAP_AUDIT_001

```
ASOF_UTC=2026-11-09T12:50:00Z
WORKER=W5
NO_ARITHMETIC_78_PLUS_120_PLUS_45=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
78_ITEM_ACCEPTANCE_REGISTER=ABSENT_LOCALLY
RULES=DEDUPE_RULES.md
```

Identity-merge only. Counts must not be summed across inventories.

---

## 1) H-ID ↔ Finish-25 Txx

| H-ID(s) | Finish-25 | Merge note |
|---------|-----------|------------|
| H16, H13–H15 (adj.) | T07 / T08 residual (historical FAIL) | HWND/tab/output axes adjacent; tip005/tip006 OUTPUT_HWND FAIL is **oneshot** evidence — do not rewrite historical T07/T08 seals |
| H27, H31–H36 | Compiler/Problems family (not a single Txx) | CC79 Problems FAIL ≠ Finish-25 rewrite |
| H43–H56, H51 | **T16** EXT | Historical/current T16 PASS on named tips ≠ INTEG004 cleanup FAIL; no cross-SHA |
| H29, terminal cancel | **T17** Terminal | T17 smoke PASS ≠ cancel/orphan proof |
| H18, H57–H58, chat stop | **T20** Chat | T20 AIM 7/7 ≠ AgentSession cancel |
| H69, H101 | **T10** recovery | T10 PASS ≠ PR78 AgentSession restore |
| H99–H100, H105 | **T24** packaging | T24 PARTIAL / candidate package ≠ installer PASS |
| H106, H120, CERTIFIED | **T25** | T25 CERTIFIED=0 held |
| H57–H72, H120 | T11–T15 agent tools (Phase3 historical) | Historical Phase3 ≠ current oneshot 4/25; PR78 NOT_RUN |
| — | Historical remaining six: **T05·T07·T08·T18·T19·T25** | Residual set — **not** added to H CONFIRMED count |
| — | Current oneshot **4/25**: T10, T16, T17, T20 | Annotate `sha_scope`; do not clear H118/#49 |

```
FINISH25_HISTORICAL=19/25
FINISH25_CURRENT=4/25
HISTORICAL ≠ CURRENT ≠ H_CONFIRMED_CARDINALITY
```

---

## 2) H-ID ↔ Issue #49 / #50 / #57

### Issue #49 (product-final) receipt keys

| #49 key / step | Primary H-IDs |
|----------------|---------------|
| CLEAN_CLONE / STRICT_BUILD | H11, H12, H119 |
| LOCAL_MODEL_LOAD / GPU_* / GENERATION | H73–H79, H84, H90 |
| TOOL_AUTHORITY / REAL_TOOL_CALL / REINJECTION / CONTINUATION | H57–H67, H91–H93 |
| REAL_SOURCE_EDIT / BUILD_FAILURE_RECOVERY / FINAL_BUILD / FINAL_TESTS | H62–H65, H72, H120 |
| MULTI_AGENT_REVIEW | H68, H70 |
| IDE_CHAT / EDITOR / TERMINAL / GIT | H13–H26, H71, H110, H118 |
| STUB_*=0 / SYNTHETIC_RECEIPTS=0 | H03, H84, H97, H102, H115–H116 |
| CI / CLEAN_MACHINE | H98–H106, H103 |
| Full autonomous loop / VERDICT | **H120** (decisive) |

### Issue #50 ladder (sequencing ≠ +11 blockers)

| Layer | Alias into |
|-------|------------|
| L0–L1 provider/Deep2 | H73–H90; PR76 |
| L2 GPU runtime | H75–H84; #57 C |
| L3 agent authority | H57–H72; PR78 |
| L4 edit/build/test | H62–H65, H120; #57 A15 |
| L5 multi-agent | H68, H70; H82/H83 OUT_OF_SCOPE daily-driver |
| L6 IDE surface | H13–H56, H107–H113; PR77/79 |
| L7 repo/CMake | H01–H12; #57 A |
| L8 CI/release | H98–H106; #57 A01/C15 |
| L9 performance | H88, H115 |
| L10 product-final | **H120** / #49 |

### Issue #57 (45 gates) — alias, do not add

| #57 | H / PR alias | Daily-driver |
|-----|--------------|--------------|
| A01 CI runners | H103 | In-scope INVESTIGATE |
| A02–A05 inventory/CMake/deps/manifest | H01, H05, H09, H11 | In-scope |
| A06–A07 clean builds | H06, H12 | In-scope |
| A08–A10 save/terminal/PS | H26, terminal family | In-scope |
| A11 LSP | H107 | In-scope UNVERIFIED |
| A12 GhostText | H108; D004–D006 | In-scope UNVERIFIED |
| A13 browser | H109 | In-scope UNVERIFIED |
| A14 debugger | H03; DEBUG_CONSOLE_GATE | In-scope (UI FAIL measured) |
| A15 agent rollback | H64, H111, H120 | In-scope UNVERIFIED |
| B01–B12 compiler/Slingshot/PE | H41–H42; PR75 | In-scope UNVERIFIED |
| **B13–B15** ELF/Mach-O/Android | **H114** | **OUT_OF_SCOPE** daily-driver |
| C01–C07, C10–C15 GPU/release | H73–H81, H84–H90, H98–H106 | In-scope UNVERIFIED/INVESTIGATE |
| **C08–C09** dual/multi-GPU | **H82, H83** | **OUT_OF_SCOPE** daily-driver |

---

## 3) H-ID ↔ PR #75–#79

| PR | State (gh) | H-band | Acceptance receipt |
|----|------------|--------|--------------------|
| **#75** | OPEN DRAFT MERGEABLE | H41–H42, H39, compiler; #57 B | No local `PR75_ACCEPTANCE_001`; 16 linker tests NOT_EXECUTED |
| **#76** | OPEN DRAFT CONFLICTING | H10, H73–H90, H104 | HELD; DO NOT MERGE |
| **#77** | OPEN CONFLICTING head `9edf63fe…` | H13–H42, H16/H27 adj., four-panel, ConPTY | `PR77_ACCEPTANCE_001` MERGE_READY=0; EXE NOT_BUILT |
| **#78** | OPEN CONFLICTING head `84b4725f…` | H57–H72 | `PR78_ACCEPTANCE_001` all runtime NOT_RUN |
| **#79** | OPEN CONFLICTING head `13c33a6f…` | H43–H56, H95–H96 | `PR79_ACCEPTANCE_001` MERGE_READY=0; CC79 EXT ≠ PR79 tip |

```
PR_OPEN + CONFLICTING = integration_blocker_state
PR_OPEN + CONFLICTING ≠ Hxx CONFIRMED
```

Integration order per PR bodies: **#77 → #78 → #79** → unified candidate → Finish-25 → release audit.

---

## 4) Prior ~78-register / D00x

| Source | Local state | Crosswalk |
|--------|-------------|-----------|
| Prior ~78-item acceptance register | **ABSENT_LOCALLY** | Cannot row-map H↔78 ids; law forbids inventing 78 rows or summing 78+120+45 |
| `RAWRXD_FULL_IDE_AUDIT_003\DEFECT_REGISTER.csv` | **D001–D015** present | Defect CSV ≠ 78-register |

### D00x → H / notes

| D00x | Maps toward | Status interaction |
|------|-------------|--------------------|
| D001 Debugger stub | H03; #57 A14 | INVESTIGATE stub claim vs current NativeDebug; CC79 IDE_DEBUG_UI FAIL is separate runtime |
| D002 Qt OFF / Native default | H04 | INVESTIGATE flags |
| D003 Dirty tree | H12 / release hygiene | UNVERIFIED clean authority tip |
| D004–D006 GhostText seals | H108 | Candidate-scoped ≠ product; UNVERIFIED |
| D007 Qwen GDN parity OPEN | H77–H79 | UNVERIFIED |
| D008 Swarm/PathB absent | H68 / agentic matrix | INVESTIGATE / NOT_PRESENT |
| D009 Installer no E2E | H99; T24 | INVESTIGATE |
| D010 Absent headers inventory | hygiene only | not H CONFIRMED |
| D011 asm_stubs | H02 | INVESTIGATE |
| D012 Compare-tree mix | H10 | Do not mix `G:\~dev\rawrxd` into F:\ authority |
| D013 Missing E2E seals | H118, H120 | UNVERIFIED |
| D014 if(FALSE) targets | H01 | INVESTIGATE |
| D015 Tool cert ≠ IDE product | H102, H106 | INVESTIGATE provenance |

---

## 5) INTEG_004 / oneshot gate aliases

| Signal | H | Law |
|--------|---|-----|
| INTEG004 Problems PASS `47451F24` | H27/H36 candidate-only | ≠ CC79; ≠ live `69FE3D92`/`35EFA9BA` drift |
| CC79 Problems FAIL | H27 CONFIRMED | Controlling tip |
| OUTPUT_HWND FAIL tip005/006 | H16 CONFIRMED | Repair continues; A4F untouched |
| INTEG004 EXT_CLEANUP FAIL | H51 CONFIRMED (SHA-scoped) | CC79 EXT PASS unchanged |
| FOUR_PANEL OPEN | H118 | NOT_DEMONSTRATED |
| Autonomous coding NOT_RUN | H120 | #49 yardstick |

---

## 6) Blocker set (post-dedupe) — W5 fail-closed master

```
DAILY_DRIVER_CONFIRMED =
  H01 (Core.cpp / AgentSession not in IDE CMake link set; orphans)
  H04 (RAWRXD_NATIVE_IDE_EXT default OFF)
  H16 (OUTPUT_HWND FAIL tip005/tip006)
  H27 (CC79 Problems / VS_UNICODE)
  H51 (INTEG004 EXT_CLEANUP FAIL — SHA-scoped 47451 only)
  H57 (AgentSession dual ownership structural)
  H87 (specialty DEVICE_LOSS_HANDLING=0 with VERDICT=PASS — ≠ product GPU PASS)
  H113 (explicit stub headers in tree)

DEDUPE_STATUS_ROWS = H08 → H27 ; H35 → H27
OUT_OF_SCOPE_DAILY = H82, H83, H114 (+ #57 B13–B15, C08–C09 aliases)
W5_DEMOTED_FROM_SIBLING_CONFIRMED = H08, H10, H35, H103, H106
```

UNVERIFIED rows (including **H120**) drive execution order toward Issue #49 without being counted as proven bugs.

```
CROSSWALK=RECORDED
W5_RECONCILE=1
ARITHMETIC_78_120_45=FORBIDDEN
PROMOTE=0
```
