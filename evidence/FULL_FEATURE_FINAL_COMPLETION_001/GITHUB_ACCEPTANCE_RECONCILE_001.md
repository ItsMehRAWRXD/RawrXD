# GITHUB_ACCEPTANCE_RECONCILE_001 — GitHub-authority slice

```
ASOF_UTC=2026-11-09T12:40:00Z
MOTD_ACK=1
REPO=ItsMehRAWRXD/RawrXD
FETCHED_VIA=gh CLI (exit 0)
DUMP=artifacts\gh_accept_dump\{issue_49,issue_50,issue_57,pr_75..pr_79}.json
CROSS_REF=..\HIDDEN_GAP_AUDIT_001\GITHUB_PR_ISSUE_INVENTORY.md
CONTROLLING_TIP=CC79
TIP_LABEL=tip_final_integ_002
TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_EXE=candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
ISSUE49_MILESTONE=NOT_DEMONSTRATED
NO_CROSS_SHA_PASS_INHERITANCE=1
A4F_IMMUTABLE=1
NOT_RUN≠PASS
```

Authority role: **GitHub acceptance inventory ↔ local CC79 measurement**. Master-register workers may cite this file as the GitHub-authority slice. This file does **not** invent PASS, does **not** move CONTROLLING_TIP, and does **not** change the 82% maturity estimate.

---

## 1. Issue #49 — Product-Final Acceptance

| Field | Value |
|-------|-------|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/49 |
| Title | `[LAYER-10] Product-Final Acceptance` |
| GH state | **OPEN** |
| Milestone | **null** (no GitHub milestone attached) |
| Cert target | `=== RAWRXD_PRODUCT_FINAL_001 ===` |
| Depends on | #48 (Layer 9 — Performance Closure) |
| Labels | `certification`, `layer-10` |

### 1.1 Mandatory E2E scenario (from issue body)

Fresh clone · no hidden env · no stubs · no pre-created receipt:

`launch → local model → R9700 → open project → agent "Find the bug, fix it, build it and test it." → agent reads → GPU reasons → CPU Tool Authority → source edit → build fails once → model diagnoses → second edit → build succeeds → tests succeed → reviewer GPU reviews → agent reports evidence → Git commit`

**Local vs CC79:** scenario end-to-end = **NOT_RUN**. No product-final receipt exists under this evidence tree claiming the full chain on one SHA.

```
ISSUE49_MILESTONE=NOT_DEMONSTRATED
ISSUE49_E2E_SCENARIO=NOT_RUN
```

### 1.2 Mandatory final-receipt checklist → LOCAL / CC79

Status vocabulary: `PASS` | `PARTIAL` | `OPEN` | `NOT_RUN` | `UNKNOWN`  
Evidence paths are relative to `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\` unless noted.

| #49 receipt key | LOCAL vs CC79 | Evidence / notes |
|-----------------|---------------|------------------|
| CLEAN_CLONE | NOT_RUN | No fresh-clone product-final run recorded here |
| STRICT_BUILD | PARTIAL | Local RelWithDebInfo builds exist (`artifacts\TIP_FINAL_INTEG_BUILD_9798.log`, candidates); ≠ #49 clean-clone strict |
| DEEP2_LAYER0 | OPEN | #50 Layer 0 integration seal pending; not closed on CC79 IDE tip |
| DEEP2_INTEGRATION | OPEN | #50 Layer 1 BLOCKED (#40); ladder holds #49 |
| GPU_RUNTIME | NOT_RUN | Not sealed on CC79 controlling tip for #49 |
| LOCAL_MODEL_LOAD | UNKNOWN | Candidate `gui_probe_logs\ollama_*.log` exist on non-controlling tips; ≠ #49 PASS on CC79 |
| GPU_FORWARD | NOT_RUN | |
| FINITE_LOGITS | NOT_RUN | |
| GENERATION | NOT_RUN | Chat Ctrl+Enter ≠ GPU generation cert |
| AGENT_REASONING | NOT_RUN | PR #78 AgentSession gates NOT_RUN |
| TOOL_AUTHORITY | NOT_RUN | |
| REAL_TOOL_CALL | NOT_RUN | |
| RESULT_REINJECTION | NOT_RUN | |
| AGENT_CONTINUATION | NOT_RUN | |
| REAL_SOURCE_EDIT | NOT_RUN | |
| BUILD_FAILURE_RECOVERY | NOT_RUN | Compiler-capture root-cause ≠ agent recover loop (`PROBLEMS_PANEL_GATE.md`) |
| FINAL_BUILD | NOT_RUN | |
| FINAL_TESTS | NOT_RUN | |
| MULTI_AGENT_REVIEW | NOT_RUN | Dual-GPU reviewer (#44 / #57 C) not run |
| IDE_CHAT | **PASS** (CC79 only) | `FINAL_VERDICT.md`; chat Ctrl+Enter 7/7; `artifacts\chat_ctrl_enter_run_*.txt` |
| IDE_EDITOR | PARTIAL | Editor HWND present in probes; #49 editor+agent-edit not proven |
| IDE_TERMINAL | **PASS** (CC79 only) | `TERMINAL_GATE.md`; `artifacts\term_smoke_receipt_CC79.txt` |
| IDE_GIT | NOT_RUN | |
| STUB_PROVIDERS=0 | UNKNOWN | No zero-stub seal for product-final on CC79 |
| STUB_FALLBACKS=0 | UNKNOWN | |
| SYNTHETIC_RECEIPTS=0 | OPEN | Fail-closed law forbids synthetic; not positively sealed for #49 |
| UNRESOLVED_EXTERNALS=0 | UNKNOWN | #57 A03–A04 still OPEN on GH |
| CI_REPRODUCIBLE | OPEN | #57 A01 / PR CI empty-runner / BlobNotFound |
| CLEAN_MACHINE_REPRODUCIBLE | NOT_RUN | |
| VERDICT | OPEN | Must stay non-PASS |

**Supporting CC79 IDE seals (≠ #49 product-final):**

| Local gate | CC79 status | Evidence |
|------------|-------------|----------|
| EXTENSIONHOST | PASS | `FINAL_VERDICT.md`; `logs\ext_smoke_run_*.txt` |
| OUTPUT_GUI | PASS | `OUTPUT_PANEL_GATE.md`; `MASTER_STATUS_CC79.md` |
| DEBUG_HEADLESS | PASS | `DEBUG_CONSOLE_GATE.md`; `artifacts\debug_backend_verify_CC79_receipt.txt` |
| PROBLEMS_UI | OPEN/FAIL on CC79 | `PROBLEMS_PANEL_GATE.md`; items=0. INTEG_004 Problems PASS is **other SHA** (`LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md`) — not inherited |
| IDE_DEBUG_UI | FAIL/OPEN | `DEBUG_CONSOLE_GATE.md`; `FOUR_PANEL_INTEGRATION.md` |
| FOUR_PANEL | OPEN | `FOUR_PANEL_INTEGRATION.md` |

```
ISSUE49_MILESTONE=NOT_DEMONSTRATED
CC79_IDE_PARTIAL_SEALS ≠ RAWRXD_PRODUCT_FINAL_001
PROMOTE=0
```

### 1.3 Exact remaining conjunction — single-SHA product-final

All of the following must be **PASS / 0** on **one** executable SHA (no cross-SHA inheritance), with revision-specific receipts:

```text
SINGLE_SHA_PRODUCT_FINAL_IFF =
    CLEAN_CLONE
  ∧ STRICT_BUILD
  ∧ DEEP2_LAYER0
  ∧ DEEP2_INTEGRATION
  ∧ GPU_RUNTIME
  ∧ LOCAL_MODEL_LOAD
  ∧ GPU_FORWARD
  ∧ FINITE_LOGITS
  ∧ GENERATION
  ∧ AGENT_REASONING
  ∧ TOOL_AUTHORITY
  ∧ REAL_TOOL_CALL
  ∧ RESULT_REINJECTION
  ∧ AGENT_CONTINUATION
  ∧ REAL_SOURCE_EDIT
  ∧ BUILD_FAILURE_RECOVERY
  ∧ FINAL_BUILD
  ∧ FINAL_TESTS
  ∧ MULTI_AGENT_REVIEW
  ∧ IDE_CHAT
  ∧ IDE_EDITOR
  ∧ IDE_TERMINAL
  ∧ IDE_GIT
  ∧ STUB_PROVIDERS=0
  ∧ STUB_FALLBACKS=0
  ∧ SYNTHETIC_RECEIPTS=0
  ∧ UNRESOLVED_EXTERNALS=0
  ∧ CI_REPRODUCIBLE
  ∧ CLEAN_MACHINE_REPRODUCIBLE
  ∧ VERDICT=PASS
  ∧ (PROBLEMS_UI items>0 ∧ click-to-line)   // currently OPEN on CC79
  ∧ IDE_DEBUG_UI_E2E                         // currently FAIL on CC79
  ∧ FOUR_PANEL_INTEGRATION                   // currently OPEN
  ∧ EXTENSIONHOST                            // PASS on CC79 only; must re-prove if tip moves
  ∧ OUTPUT_GUI                               // PASS on CC79 only; must re-prove if tip moves
  ∧ DEBUG_HEADLESS                           // PASS on CC79 only; must re-prove if tip moves
```

Prerequisite ladder (GitHub): Layers 0–9 (#39–#48) must not remain BLOCKED/PENDING before Layer 10 can close.  
`INTEG_004` Problems PASS on `47451F24…` does **not** satisfy the conjunction until EXT/CHAT/TERM/OUTPUT/DEBUG_HEADLESS are re-proven on that same SHA **or** owner-authorized tip move + remeasure.

```
ISSUE49_MILESTONE=NOT_DEMONSTRATED
PRODUCT_PASS=0
CERTIFIED=0
PROMOTE=0
```

---

## 2. Issue #50 — Certification Ladder layers 0–10

| Field | Value |
|-------|-------|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/50 |
| Title | `[MASTER] RawrXD Certification Ladder — 0-to-10 Tracking` |
| GH state | **OPEN** |
| Labels | `certification`, `master-tracking` |

| Layer | GH status (#50) | Child | LOCAL vs CC79 | Notes / evidence |
|-------|-----------------|-------|---------------|------------------|
| 0 | IN PROGRESS | #39 | PARTIAL | Provider isolated 32/32 cited on GH; **integration seal pending**. Not product-final on CC79 |
| 1 | BLOCKED | #40 | OPEN | Deep2 integration & runtime closure; blocks ladder |
| 2 | PENDING | #41 | NOT_RUN | GPU/Runtime Execution Closure |
| 3 | PENDING | #42 | NOT_RUN | Agent Reasoning + Tool Authority |
| 4 | PENDING | #43 | NOT_RUN | Autonomous Edit/Build/Test Loop |
| 5 | PENDING | #44 | NOT_RUN | Multi-Agent / Dual-GPU |
| 6 | PENDING | #45 | PARTIAL | IDE surfaces: CHAT/TERM/OUTPUT/EXT PASS on CC79; Problems/Debug UI/four-panel OPEN (`MASTER_STATUS_CC79.md`) — ≠ Layer-6 seal |
| 7 | PENDING | #46 | OPEN | Repo/CMake convergence |
| 8 | PENDING | #47 | OPEN | CI/Release Authority |
| 9 | PENDING | #48 | NOT_RUN | Performance Closure (blocks #49) |
| 10 | PENDING | #49 | NOT_DEMONSTRATED | This file §1 |

```
ISSUE50_LADDER=OPEN
LAYER0_INTEGRATION_SEAL=PENDING
LAYERS_1_TO_10=NOT_CLOSED
CC79_IDE_PARTIAL ≠ LADDER_PASS
PROMOTE=0
```

---

## 3. Issue #57 — 45 gates (Windows daily-driver vs OUT_OF_SCOPE)

| Field | Value |
|-------|-------|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/57 |
| Title | RawrXD batch 024: 45 E2E native IDE, Slingshot/compiler and GPU release gates |
| GH state | **OPEN** |
| Framing | Open acceptance gates, not 45 accomplished fixes; all checkboxes unchecked on fetch |

Scope rule for this reconcile: **Windows daily-driver mandatory** = required for local Win32 IDE agentic daily use / #49 path on Windows. **OUT_OF_SCOPE** = multi-OS compilers, non-Windows packaging, or explicitly non-daily-driver until product-final Windows conjunction closes.

### Group A — Native IDE E2E (15)

| ID | Gate (compressed) | Scope | LOCAL vs CC79 |
|----|-------------------|-------|---------------|
| A01 | GitHub Actions runner_id=0 / real Linux+Windows CI | OUT_OF_SCOPE for daily-driver runtime; **mandatory for CI_REPRODUCIBLE** (#49) | OPEN |
| A02 | Per-file SHA-256 inventory JSON | Windows mandatory (provenance) | NOT_RUN / OPEN |
| A03 | CMake literal-source admission | Windows mandatory | OPEN |
| A04 | No-external-deps (Qt/nlohmann quarantine) | Windows mandatory | OPEN |
| A05 | Frozen feature→TU→callsite manifest | Windows mandatory | OPEN |
| A06 | Rebuild native Win32 IDE clean, no-Qt | Windows mandatory | PARTIAL (local tips built; ≠ clean-clone #49) |
| A07 | Rebuild rawr.exe / snapshot/agent same checkout | Windows mandatory | OPEN / PARTIAL |
| A08 | Launch IDE save/close/reopen SHA compare | Windows mandatory | NOT_RUN |
| A09 | Terminal start/stream/exit/cancel/cleanup | Windows mandatory | **PASS** on CC79 (`TERMINAL_GATE.md`) |
| A10 | Native PowerShell panel lifecycle | Windows mandatory | NOT_RUN / PARTIAL vs A09 |
| A11 | LSP JSON-RPC diagnostics/defs/completion | Windows mandatory | NOT_RUN |
| A12 | GhostText + real model adapter | Windows mandatory | NOT_RUN |
| A13 | Native browser isolation/lifecycle | Windows mandatory | NOT_RUN |
| A14 | Debugger BP/step/watch/vars/stack UI | Windows mandatory | PARTIAL: headless PASS; IDE UI FAIL (`DEBUG_CONSOLE_GATE.md`) |
| A15 | Agent edit→build→test→rollback + evidence | Windows mandatory (#49 core) | NOT_RUN |

### Group B — Slingshot / compiler / cross-platform (15)

| ID | Gate (compressed) | Scope | LOCAL vs CC79 |
|----|-------------------|-------|---------------|
| B01 | Recover slingshot braid sources + hashes | Windows mandatory (if slingshot in product path) | OPEN |
| B02 | SBraid roundtrip + corrupt rejection | Windows mandatory (same) | OPEN |
| B03 | SlingshotGuard concurrency review | Windows mandatory | OPEN |
| B04 | Replace simulated VRAM in SlingshotPOC | Windows mandatory if promoted | OPEN |
| B05 | Legacy vs Deep2 tensor residency reconcile | Windows mandatory | OPEN |
| B06 | Compiler/linker source inventory | Windows mandatory | PARTIAL (PR #75 inventory claims; not CC79 seal) |
| B07 | Native C frontend portable programs | Windows mandatory | OPEN / PR #75 local claims unverified here |
| B08 | Native C++20 frontend | Windows mandatory | OPEN |
| B09 | MASM x86/x64 + COFF oracle | Windows mandatory (sovereign toolchain) | OPEN |
| B10 | NASM x86/x64 interoperability | **OUT_OF_SCOPE** for Win daily-driver (alt assembler) | OPEN / OOS |
| B11 | Native linker PE32/PE32+ | Windows mandatory | OPEN (PR #75: 16 native-linker tests UNEXECUTED) |
| B12 | Compile→link→execute no external compiler | Windows mandatory (subset) | OPEN |
| B13 | ELF/Linux capability + smoke | **OUT_OF_SCOPE** multi-OS | OPEN / OOS |
| B14 | Mach-O / macOS / iOS signing contracts | **OUT_OF_SCOPE** multi-OS | OPEN / OOS |
| B15 | Android ABI / APK / device | **OUT_OF_SCOPE** multi-OS | OPEN / OOS |

### Group C — GPU / TPS / Top-25 / release (15)

| ID | Gate (compressed) | Scope | LOCAL vs CC79 |
|----|-------------------|-------|---------------|
| C01 | Deterministic reference model baseline | Windows mandatory (#49 GPU path) | NOT_RUN |
| C02 | ffn_gate_up multi-token GPU | Windows mandatory | NOT_RUN |
| C03 | Deep2 Q4/Q5/Q6/F32 fused GEMV oracles | Windows mandatory | NOT_RUN |
| C04 | Fused GEMV path fence/submit compare | Windows mandatory | NOT_RUN |
| C05 | Lane-state restore success/error/fallback/dual | Windows mandatory | NOT_RUN |
| C06 | R9700 single-GPU TPS 32/128/256 | Windows mandatory (#49 R9700) | NOT_RUN |
| C07 | RX7800 XT single-GPU TPS | Windows mandatory for dual-agent; else deferred | NOT_RUN |
| C08 | Dual-GPU full-model TPS | Windows mandatory for #49 MULTI_AGENT_REVIEW | NOT_RUN |
| C09 | GPU0 fence / GPU1 overlap attribution | Windows mandatory if C08 in scope | NOT_RUN |
| C10 | GGUF shard/quant/arch user matrix | Windows mandatory | NOT_RUN / PARTIAL elsewhere |
| C11 | Nemotron SSM Q4_K NaN/residual | Experimental / not daily-driver default | OPEN (PROMOTE=0; experimental SSM track separate) |
| C12 | Real-model 150+ TPS (no synthetic) | Performance Layer 9; not IDE daily smoke | NOT_RUN |
| C13 | Strict A/B thermal/residency controls | Performance Layer 9 | NOT_RUN |
| C14 | 25×20=500 cell feature matrix | Release / cert breadth | OPEN (Finish-25 historical 19/25 ≠ this) |
| C15 | Signed/repro package + cross-platform release | Cross-platform portion **OUT_OF_SCOPE**; Windows package PARTIAL_STAGE | PARTIAL / OOS mix (`FINISH25_MATRIX.md` T24) |

```
ISSUE57_CHECKED_ON_GH=0/45
WINDOWS_DAILY_DRIVER_MANDATORY≈A02–A15,B01–B09,B11–B12,C01–C10 (+ A01/C14/C15 as cert/release)
OUT_OF_SCOPE_MULTI_OS=B10,B13,B14,B15 (+ C15 cross-platform clause)
CC79_CLOSES_FROM_57=A09 (+ partial A06/A14); not A15 / not Group C
PROMOTE=0
```

---

## 4. PRs #75–#79 — state, proofs, CC79 overlap

Sources: live `gh` dump + `..\PR_INTEGRATION_TRACK_001\MERGE_READINESS.md` + `..\PR7{7,8,9}_ACCEPTANCE_001\RECEIPT.md` + inventory.

| PR | GH state | Reconcile disposition | Required proofs still open | CC79 already seals (local only; ≠ PR head) | Still open vs CC79 / PR |
|----|----------|----------------------|----------------------------|--------------------------------------------|-------------------------|
| **#75** Native compiler/linker | OPEN + **DRAFT**; mergeable=MERGEABLE | **HELD** (draft; MERGE_AUTHORIZED=0) | Execute 16 native-linker CTests; Windows PE execute; CI runner real steps; IDE menu/tool registration; T05/T24/T25 | Compiler **isolated** scrub capture verified (`artifacts\COMPILER_CAPTURE_ISOLATED_RECEIPT.txt`); IDE feed pending | IDE compiler→Problems feed OPEN on CC79; PR head EXE not CC79 |
| **#76** Deep2 consolidation | OPEN + **DRAFT**; CONFLICTING | **HELD** (DO NOT MERGE; conflicts + CI) | Conflict resolve vs main; CI that executes; certification review | None as consolidation PASS | Entire PR open; ≠ CC79 tip authority |
| **#77** IDE product path | OPEN; CONFLICTING | **OPEN** / PARTIAL source-wire | Four-panel E2E on **PR77 SHA**; ConPTY; async inference UI; Problems+Output on that SHA; conflict resolve; test-plan unchecked | On **CC79** (different SHA): TERM PASS, OUTPUT_GUI PASS, EXT PASS, chat PASS; Problems OPEN; Debug UI FAIL; four-panel OPEN | PR77 RUNTIME=NOT_RUN; MERGE_READY=0; no inherit from CC79 |
| **#78** AgentSession GUI | OPEN; CONFLICTING | **OPEN** | Session lifecycle/cancel/cleanup/restore on **PR78 SHA**; no inherit from #77 | Nothing AgentSession-complete on CC79 | All AgentSession #49 keys NOT_RUN |
| **#79** ExtensionHost runtime | OPEN; CONFLICTING | **OPEN** / PARTIAL source-wire | Real load/activate/execute/shutdown/crash-recovery on **PR79 SHA** | EXT INIT∧LOAD∧ACTIVATE∧CMD **PASS on CC79 only** | PR79 EXE NOT_BUILT; CC79 EXT ≠ PR79 PASS |

```
PR75=HELD_DRAFT
PR76=HELD_DRAFT_CONFLICTING
PR77=OPEN_CONFLICTING
PR78=OPEN_CONFLICTING
PR79=OPEN_CONFLICTING
MERGED=0
MERGE_AUTHORIZED=0
CC79_PASS ≠ PR_HEAD_PASS
PROMOTE=0
```

Integration order per PR bodies: **#77 → #78 → #79** → unified candidate → Finish-25 → release audit. Finish-25 historical remains **19/25**; CURRENT on CC79 measured **4/25** (`FINISH25_MATRIX.md`: T10,T16,T17,T20) — not certification.

---

## 5. Summary table (cite-ready)

| Authority item | GH | LOCAL / CC79 | Decisive status |
|----------------|----|--------------|-----------------|
| Issue #49 Product-Final | OPEN | Scenario NOT_RUN; IDE_CHAT/IDE_TERMINAL PASS only | **ISSUE49_MILESTONE=NOT_DEMONSTRATED** |
| Issue #50 Ladder 0–10 | OPEN | L0 PARTIAL; L1–10 not closed; L6 PARTIAL IDE | OPEN |
| Issue #57 / 45 gates | OPEN 0/45 | A09 PASS on CC79; multi-OS B13–B15 OOS | OPEN |
| PR #75 | OPEN DRAFT MERGEABLE | HELD; isolated compiler proof ≠ IDE | HELD |
| PR #76 | OPEN DRAFT CONFLICTING | HELD | HELD |
| PR #77 | OPEN CONFLICTING | OPEN; CC79 seals TERM/OUTPUT/EXT/CHAT ≠ this head | OPEN |
| PR #78 | OPEN CONFLICTING | OPEN; AgentSession NOT_RUN | OPEN |
| PR #79 | OPEN CONFLICTING | OPEN; CC79 EXT ≠ PR79 | OPEN |
| CONTROLLING_TIP | — | CC79 `CC79F6CD…` | Unchanged |
| Maturity % | — | **82%** | **ESTIMATE_CHANGE=0** |
| PROMOTE | — | 0 | Held |

```
GITHUB_ACCEPTANCE_RECONCILE=RECORDED
ISSUE49_MILESTONE=NOT_DEMONSTRATED
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
CONTROLLING_TIP=CC79
PRODUCT_PASS=0
CERTIFIED=0
PROMOTE=0
INVENT_PASS=0
SLICE=GITHUB_AUTHORITY_FOR_MASTER_REGISTER
```

---

## 6. Paths

| Artifact | Path |
|----------|------|
| **This reconcile** | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\GITHUB_ACCEPTANCE_RECONCILE_001.md` |
| gh JSON dump | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\gh_accept_dump\` |
| Prior GH inventory | `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\GITHUB_PR_ISSUE_INVENTORY.md` |
| CC79 master status | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\MASTER_STATUS_CC79.md` |
| Final verdict | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINAL_VERDICT.md` |
| Lineage (INTEG_004 ≠ tip) | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md` |
