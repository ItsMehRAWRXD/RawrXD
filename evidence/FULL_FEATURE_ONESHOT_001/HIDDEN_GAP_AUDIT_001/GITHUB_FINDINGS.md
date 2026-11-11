# GITHUB_FINDINGS — RawrXD acceptance surface vs local evidence

```
ASOF_UTC=2026-11-09T12:40:00Z
REPO=ItsMehRAWRXD/RawrXD
GH_AUTH=OK (ItsMehRAWRXD; scopes=gist,read:org,repo,workflow)
GH_FETCH=OK (issues #49 #50 #57; PRs #75–#79)
COMMENTS_FETCHED=OK (issue comments count=0 for #49/#50/#57)
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MOTD_ACK=1
WORKSPACE_PRIMARY=F:\rawrxd\evidence
WORKSPACE_SECONDARY=G:\~dev\rawrxd\evidence (PRESENT; large tree)
```

## Law (fail-closed)

```
NOT_RUN != PASS
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
NO_CROSS_SHA_PASS_INHERITANCE=1
ISSUE_CHECKBOX_UNCHECKED != LOCAL_PARTIAL_PASS
PR_OPEN != ACCEPTANCE
CI_FAILURE_BEFORE_STEPS != COMPILER_FAIL_EVIDENCE
SLIM_DAILY_DRIVER_PASS != FULL_FEATURE != PRODUCT_FINAL (#49)
FINISH25_HISTORICAL_19/25 != FINISH25_CURRENT != CERTIFIED
INTEG_004_PROBLEMS_PASS != CONTROLLING_TIP != PRODUCT_PASS
```

---

## 1. Issue #49 — Product-Final Acceptance (LAYER-10)

| Field | Measured |
|-------|----------|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/49 |
| Title | `[LAYER-10] Product-Final Acceptance` |
| State | **OPEN** |
| Labels | `certification`, `layer-10` |
| Created | 2026-09-24T02:34:34Z |
| Updated | 2026-09-24T02:35:33Z |
| Comments | **0** |
| Depends on | #48 (Layer 9 — Performance Closure) |
| Blocks | None (final layer) |

### Acceptance scenario (required chain)

Fresh clone → launch → select local model → select R9700 → open project → agent “Find the bug, fix it, build it and test it.” → agent reads → GPU reasons → CPU Tool Authority → source edit → build fails once → diagnose → second edit → build succeeds → tests succeed → reviewer GPU reviews → agent reports evidence → Git commit.

### Final receipt checklist (30 named gates — all **UNPROVEN on GitHub**; issue body lists target `=PASS` / `=0` values, not measured seals)

| # | Gate | GitHub evidence | Local reconcile (F:\rawrxd) |
|---|------|-----------------|-----------------------------|
| 1 | CLEAN_CLONE | NOT_SHOWN | NOT found as product-final seal |
| 2 | STRICT_BUILD | NOT_SHOWN | Partial local builds exist; ≠ #49 |
| 3 | DEEP2_LAYER0 | NOT_SHOWN | Ladder #50 says Layer0 integration seal **pending** |
| 4 | DEEP2_INTEGRATION | NOT_SHOWN | Layer1 BLOCKED on #50 |
| 5 | GPU_RUNTIME | NOT_SHOWN | Issue #57 Group C still open |
| 6 | LOCAL_MODEL_LOAD | NOT_SHOWN | Local Ollama/runtime logs exist; ≠ #49 seal |
| 7 | GPU_FORWARD | NOT_SHOWN | OPEN |
| 8 | FINITE_LOGITS | NOT_SHOWN | OPEN |
| 9 | GENERATION | NOT_SHOWN | Local chat/token paths partial; ≠ #49 |
| 10 | AGENT_REASONING | NOT_SHOWN | OPEN |
| 11 | TOOL_AUTHORITY | NOT_SHOWN | OPEN |
| 12 | REAL_TOOL_CALL | NOT_SHOWN | OPEN |
| 13 | RESULT_REINJECTION | NOT_SHOWN | OPEN |
| 14 | AGENT_CONTINUATION | NOT_SHOWN | OPEN |
| 15 | REAL_SOURCE_EDIT | NOT_SHOWN | OPEN |
| 16 | BUILD_FAILURE_RECOVERY | NOT_SHOWN | OPEN |
| 17 | FINAL_BUILD | NOT_SHOWN | OPEN |
| 18 | FINAL_TESTS | NOT_SHOWN | OPEN |
| 19 | MULTI_AGENT_REVIEW | NOT_SHOWN | OPEN |
| 20 | IDE_CHAT | NOT_SHOWN | Local T20 chat 7/7 on EA5D path (oneshot matrix) — **≠ #49 SHA / clean-clone** |
| 21 | IDE_EDITOR | NOT_SHOWN | Finish-25 / slim partial — **≠ product-final** |
| 22 | IDE_TERMINAL | NOT_SHOWN | Local T17 ConPTY PASS on specific SHAs — **≠ #49** |
| 23 | IDE_GIT | NOT_SHOWN | OPEN |
| 24 | STUB_PROVIDERS=0 | NOT_SHOWN | OPEN |
| 25 | STUB_FALLBACKS=0 | NOT_SHOWN | OPEN |
| 26 | SYNTHETIC_RECEIPTS=0 | NOT_SHOWN | OPEN |
| 27 | UNRESOLVED_EXTERNALS=0 | NOT_SHOWN | OPEN |
| 28 | CI_REPRODUCIBLE | NOT_SHOWN | PRs #75–79 CI largely FAILURE / runner issues |
| 29 | CLEAN_MACHINE_REPRODUCIBLE | NOT_SHOWN | OPEN |
| 30 | VERDICT | **NOT PASS** | Local `PRODUCT_PASS=0` / `CERTIFIED=0` / `PROMOTE=0` |

### Issue #49 counts

```
CHECKLIST_GATES=30
GITHUB_MEASURED_PASS=0
GITHUB_MEASURED_FAIL=0
GITHUB_UNPROVEN=30
LOCAL_FULL_CHAIN_PASS=0
ISSUE_49_STATUS=OPEN_BLOCKED_BY_LAYER9_AND_UNMET_RECEIPT
```

---

## 2. Issue #50 — Certification Ladder (layers 0–10)

| Field | Measured |
|-------|----------|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/50 |
| Title | `[MASTER] RawrXD Certification Ladder — 0-to-10 Tracking` |
| State | **OPEN** |
| Labels | `certification`, `master-tracking` |
| Created | 2026-09-24T02:36:56Z |
| Updated | 2026-09-24T03:09:37Z |
| Comments | **0** |
| Body note | Ends at `**Latest authority commit:**` with **empty value** (no SHA recorded in issue body) |

### Provider isolated tests (as stated on issue; not re-executed this audit)

| Provider | Tests | Issue claim | Commit cited |
|----------|-------|-------------|--------------|
| ProductionProfiler | 7 | PASS | 75a302ad |
| NVMeStream | 5 | PASS | 1ee4a755 |
| BP16Streamer | 6 | PASS | faac5d52 |
| CompressedKVCache | 6 | PASS | de4de28a |
| MARSController | 8 | PASS | 06d76700 |
| **Total** | **32/32** | Issue says DONE | — |

`PROVIDER_ISOLATED_CLAIM=32/32` on GitHub text ≠ Layer-0 integration seal ≠ Layer-10 product-final.

### Layer board (from issue body — GitHub status only)

| Layer | GitHub status | Linked issue | Notes from #50 |
|-------|---------------|--------------|----------------|
| 0 | IN PROGRESS | #39 | Provider isolated PASS; **Integration seal pending** |
| 1 | BLOCKED | #40 | Deep2 integration & runtime closure |
| 2 | PENDING | #41 | Blocked by #40 |
| 3 | PENDING | #42 | Blocked by #41 |
| 4 | PENDING | #43 | Blocked by #42 |
| 5 | PENDING | #44 | Blocked by #43 |
| 6 | PENDING | #45 | Blocked by #44 |
| 7 | PENDING | #46 | Blocked by #45 |
| 8 | PENDING | #47 | Blocked by #46 |
| 9 | PENDING | #48 | Blocked by #47 |
| 10 | PENDING | #49 | Blocked by #48 |

### Layer counts

```
LAYERS_TOTAL=11 (0–10)
LAYERS_PASS_SEALED_ON_ISSUE=0
LAYERS_IN_PROGRESS=1 (Layer 0; integration still pending)
LAYERS_BLOCKED=1 (Layer 1)
LAYERS_PENDING=9 (Layers 2–10)
PROVIDER_ISOLATED_CLAIMED=32/32
INTEGRATION_SEAL=PENDING
PRODUCT_FINAL_LAYER10=PENDING
```

Local evidence (Deep2 / scoreboard / experimental SSM under F:\rawrxd and G:\~dev\rawrxd) does **not** rewrite this GitHub ladder to PASS. Local AGENTS/performance seals retain `PROMOTE=0` / `TIP_CLIMB=HOLD`.

---

## 3. Issue #57 — 45 gates (Batch 024)

| Field | Measured |
|-------|----------|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/57 |
| Title | `RawrXD batch 024: 45 E2E native IDE, Slingshot/compiler and GPU release gates` |
| State | **OPEN** |
| Updated | 2026-10-24T11:28:25Z |
| Comments | **0** |
| Framing | **Open acceptance gates, not 45 accomplished fixes** |
| Checkbox scan | All `[ ]` — **0 checked** |

### Group inventory

#### Group A — Native IDE E2E and source/dependency closure (15)

| ID | Gate (short) | Checkbox | Finish-25 overlap |
|----|--------------|----------|-------------------|
| A01 | GitHub Actions runner_id=0 / successful Linux+Windows run | OPEN | Indirect (CI ≠ Finish-25 task IDs) |
| A02 | Per-file SHA-256 inventory JSON | OPEN | Weak / provenance |
| A03 | CMake literal-source admission | OPEN | Weak / build graph |
| A04 | No-external-deps scan (Qt/nlohmann) | OPEN | Weak |
| A05 | Frozen feature→TU/call-site manifest | OPEN | Weak |
| A06 | Rebuild native Win32 IDE clean, no-Qt | OPEN | **OVERLAP** Finish-25 build/package track |
| A07 | Rebuild rawr.exe + snapshot/agent targets | OPEN | **OVERLAP** tool/agent path |
| A08 | Launch IDE save/close/reopen SHA compare | OPEN | **OVERLAP** T10 / editor persistence |
| A09 | Terminal start/stream/exit/cancel/cleanup | OPEN | **OVERLAP** T17 terminal |
| A10 | Native PowerShell panel lifecycle | OPEN | **OVERLAP** terminal/shell family |
| A11 | LSP JSON-RPC handshake/diagnostics/def/completion | OPEN | Adjacent (not classic T01–T25 ID) |
| A12 | GhostText inline completion + real model adapter | OPEN | Adjacent / chat-adjacent |
| A13 | Native browser rendering/isolation/lifecycle | OPEN | Adjacent |
| A14 | Debugger breakpoints/step/watch/stack | OPEN | **OVERLAP** debug console / IDE debug gates |
| A15 | IDE agent edit→build→test→snapshot rollback | OPEN | **OVERLAP** Issue #49 product-final + agent session |

#### Group B — Slingshot / native compiler-linker / cross-platform (15)

| ID | Gate (short) | Checkbox | Finish-25 overlap |
|----|--------------|----------|-------------------|
| B01–B05 | Slingshot braid/guard/POC/Deep2 reconcile | OPEN | Low direct Finish-25; compiler/GPU family |
| B06 | Compiler/linker source inventory | OPEN | **OVERLAP** PR #75 toolchain |
| B07 | Native C frontend | OPEN | **OVERLAP** PR #75 / Issue #57 compiler |
| B08 | Native C++20 frontend | OPEN | **OVERLAP** PR #75 |
| B09 | MASM x86/x64 + oracle | OPEN | **OVERLAP** PR #75 / Sovereign path |
| B10 | NASM x86/x64 + oracle | OPEN | **OVERLAP** PR #75 (banner ≠ impl noted in issue) |
| B11 | Native linker PE32/PE32+ | OPEN | **OVERLAP** PR #75 |
| B12 | Compile→link→execute no external compiler | OPEN | **OVERLAP** PR #75 |
| B13 | ELF/Linux capability + smoke | OPEN | **OVERLAP** PR #75 (partial local ELF claims) |
| B14 | Mach-O/macOS/iOS contracts + runner evidence | OPEN | Outside Finish-25 Win32 scope |
| B15 | Android ABI/APK contracts + device evidence | OPEN | Outside Finish-25 Win32 scope |

#### Group C — GPU correctness, 150 TPS, Top-25 parity, release (15)

| ID | Gate (short) | Checkbox | Finish-25 overlap |
|----|--------------|----------|-------------------|
| C01–C05 | Reference model, ffn_gate_up, fused GEMV, lane-state | OPEN | Low Finish-25; Deep2/GPU ladder |
| C06–C09 | R9700 / RX7800 / dual-GPU TPS + attribution | OPEN | Layer 9 / perf; not Finish-25 T-IDs |
| C10–C11 | GGUF matrix + Nemotron SSM parity | OPEN | Experimental SSM local ≠ certified |
| C12–C13 | 150+ TPS + A/B controls | OPEN | Perf; issue forbids synthetic kernel TPS |
| C14 | 25 IDE × 20 capability = 500-cell matrix | OPEN | **OVERLAP** Finish-25 / Top-25 language; **not same ledger** |
| C15 | Signed/reproducible packaging + release acceptance | OPEN | **OVERLAP** T24/T25 packaging/cert |

### Issue #57 vs Finish-25 overlap summary

```
ISSUE57_GATES=45
ISSUE57_CHECKED=0
ISSUE57_OPEN=45

FINISH25_AUTHORITY_LOCAL=19/25 historical (POST_E59D FINISH_25_BACKLOG + RECEIPT_AGREEMENT)
FINISH25_CURRENT_ONESHOT=4/25 measured PASS items (T10,T16_EXT_EA5D,T17_TERMINAL_EA5D,T20_CHAT_7of7)
FINISH25_REMAINING_HISTORICAL=6 (T05,T07,T08,T18,T19,T25)

OVERLAP_STRONG≈18  (A06–A10,A14–A15, B06–B13, C14–C15) — thematic/family overlap, NOT automatic credit
OVERLAP_WEAK≈12    (A01–A05,A11–A13, B01–B05)
OVERLAP_NONE_OR_OUTSIDE≈15 (B14–B15, C01–C13 mostly GPU/perf ladder)

DO_NOT_DOUBLE_COUNT:
  45 + 25 + 30(#49) != acceptance progress
  Issue #57 C14 "Top-25 / 500 cell" != Finish-25 19/25 seal
```

Provenance cited on #57 (not revalidated this pass): baseline `7d5106b3…`, REAP `3083edf6…` draft PR #53, fused GEMV `fa503b4a…` draft PR #55; Actions run #40089650136 failed in ~3s with `runner_id=0`, `steps=[]`.

---

## 4. PRs #75–#79 — OPEN / PARTIAL / HELD + SHA evidence still needed

Fetch: `gh pr view` JSON OK for all five. Check rollup counted from API conclusions.

### Disposition table

| PR | State | Draft | Mergeable | MergeState | Disposition | HEAD (git) | Base |
|----|-------|-------|-----------|------------|-------------|------------|------|
| **#75** | OPEN | **True** | MERGEABLE | **UNSTABLE** | **PARTIAL** | `3bbda91366161c08c103cd1111dc413e92bdd25b` | `fd906cc7…` (`fix/deep2-multimodel-safety-20261025`) |
| **#76** | OPEN | **True** | **CONFLICTING** | **DIRTY** | **HELD** | `e91b476b51902e26fd1b0c3678ffce84efe7057d` | `033a8acb…` (`main`) |
| **#77** | OPEN | False | **CONFLICTING** | **DIRTY** | **OPEN/HELD** (gates unchecked) | `9edf63fed82bdf427f734591bff262282f6fe822` | `033a8acb…` (`main`) |
| **#78** | OPEN | False | **CONFLICTING** | **DIRTY** | **HELD** | `84b4725f798f329a31660e87820c2f57115247ce` | `033a8acb…` (`main`) |
| **#79** | OPEN | False | **CONFLICTING** | **DIRTY** | **HELD** | `13c33a6f35c6493cd5bf60a9f5f0a21f6271ef8c` | `033a8acb…` (`main`) |

### CI check counts (API rollup; not invented PASS)

| PR | pass | fail | skip | total | Note |
|----|------|------|------|-------|------|
| #75 | 0 | 32 | 7 | 39 | Body: CI fails **before runner assignment** (empty runner / 0 steps) — ≠ toolchain PASS |
| #76 | 0 | 119 | 0 | 119 | Body: BlobNotFound; draft to prevent unverified promotion |
| #77 | 1 | 5 | 0 | 6 | Only Cursor Security Reviewer SUCCESS; native-build/analyze/hexmag FAILURE |
| #78 | 1 | 5 | 0 | 6 | Same pattern as #77 |
| #79 | 1 | 5 | 0 | 6 | Same pattern as #77 |

`gh pr view --json changedFiles,additions,deletions` returned `files=0 +/- 0/0` for #76–#79 (likely conflict/diff unavailable) and `files=15 +/- 1465/71` for #75.

### PR #75 — PARTIAL — still needs SHA evidence

- Title: WIP native compiler / CMake builder / PE/COFF linker pipeline
- Branch: `feature/native-toolchain-compiler-builder-linker-20261106`
- Body claims: **37/37 local Python black-box PASS**; tool blob SHAs `1636ca47…`, test blob `426e9f66…`
- Explicit non-claims: own-linker COFF→PE tests **committed but not executed**; Windows PE execution/CRT **not** claimed; IDE menu/tool registration **not** done; T05/T24/T25 remain OPEN
- **Still needs:** CI run with assigned runner + executed steps on HEAD `3bbda913…`; executed native-linker CTest on real toolchain; Windows PE execute smoke; IDE/agent tool registration evidence; reconcile with advancing main before merge

### PR #76 — HELD — still needs SHA evidence

- Title: Consolidate Deep2 + native compiler into main (certification pending)
- Branch: `fix/deep2-multimodel-safety-20261025` → `main`
- **CONFLICTING**; draft; DO NOT MERGE per body
- **Still needs:** conflict resolution; any green CI on resolved HEAD; certification receipts tied to post-resolve SHA (none present)

### PR #77 — OPEN / HELD (product path) — still needs SHA evidence

- Title: P0 IDE product path — ConPTY, inference UI, Problems/output wiring
- Branch: `feature/ide-agentic-product-path-20261026`
- Test plan: **all unchecked**
- Explicit: `PROMOTE=0`, `CERTIFIED=0`, Finish-25 remains **19/25**, no cross-SHA PASS inheritance; preserve A4F083DF…
- Local parallel: INTEG_004 Problems UI PASS on `47451F24…` ≠ this PR HEAD `9edf63fe…`; CONTROLLING_TIP still CC79
- **Still needs:** SHA-specific clean build+link of PR HEAD; ConPTY start/stop/resize/interrupt; async inference UI marshal; Problems aggregator + Output routing; no-regression vs A4F; sealed receipt naming HEAD exe SHA

### PR #78 — HELD — still needs SHA evidence

- Title: P1 AgentSession GUI — lifecycle, cancellation, cleanup
- Branch: `feature/agent-session-gui-20261026`
- Test plan unchecked; must not inherit PASS from #77
- **Still needs:** HEAD-SHA build; session start/stop/kill/restore/proof; cancel/cleanup without orphan threads; A4F no-regression; independent sealed evidence

### PR #79 — HELD — still needs SHA evidence

- Title: P2 ExtensionHost runtime — host/worker, IPC, shutdown, crash recovery
- Branch: `feature/extensionhost-runtime-clean-20261102`
- Compile/link alone ≠ ExtensionHost PASS (body)
- Local parallel: INTEG_004 EXT_LOAD/ACTIVATE PASS but **EXT_CLEANUP=FAIL** / `EXTENSIONS=FAIL` on `47451F24…` — not PR HEAD credit
- **Still needs:** HEAD-SHA host/worker handshake; real extension load/execute; shutdown + crash-recovery fail-closed; clean quit without FORCE_KILL; A4F no-regression

### PR summary counts

```
PRS_QUERIED=5
PRS_OPEN=5
PRS_DRAFT=2 (#75,#76)
PRS_READY_FOR_REVIEW_FLAG=3 (#77–#79; still not merge-ready)
PRS_MERGEABLE=1 (#75) but UNSTABLE
PRS_CONFLICTING=4 (#76–#79)
PRS_DISPOSITION_PARTIAL=1 (#75)
PRS_DISPOSITION_HELD=4 (#76–#79)
PRS_WITH_PRODUCT_FINAL_PASS=0
SHA_EVIDENCE_GAPS_OPEN=5/5
```

---

## 5. Local evidence anchors (reconcile pointers)

| Topic | Authority path(s) | GitHub relation |
|-------|-------------------|-----------------|
| INTEG_004 | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\` (+ oneshot receipts) | **Not indexed as GitHub issue/PR seal**; local-only candidate |
| Finish-25 ledger | `POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` + `FINISH_25_RECEIPT_AGREEMENT.md`; matrices under ONESHOT/FINAL | Overlaps #57 A/C and PR #77 prose; **19/25 ≠ closed** |
| DAILY_DRIVER_CLOSE_001 | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\` (A4F083DF slim freeze) | Cited by PRs #77–#79 as immutable baseline; slim PASS ≠ #49 |
| FULL_FEATURE_ONESHOT_001 | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\` (764 files) | Working surface for panels/chat/terminal; `PRODUCT_PASS=0` |
| G:\~dev\rawrxd\evidence | PRESENT (312041 files counted) | Secondary mirror; this audit’s controlling citations use **F:\rawrxd** |

Detail search: `INTEG_004_SEARCH.md` (sibling).

---

## 6. Cross-surface verdict (no invented PASS)

```
GITHUB_ACCEPTANCE_SURFACE=OPEN
ISSUE49_PRODUCT_FINAL=NOT_DEMONSTRATED
ISSUE50_LADDER=0_INTEGRATION_PENDING__1_TO_10_NOT_SEALED
ISSUE57_45=0/45_CHECKED
PRS75_79=NO_MERGE_READY_CERTIFICATION
LOCAL_SLIM_DAILY_DRIVER=PASS (A4F only; EXT OUT_OF_SCOPE)
LOCAL_FINISH25_HISTORICAL=19/25
LOCAL_FINISH25_CURRENT_ONESHOT=4/25
LOCAL_INTEG_004=PROBLEMS_UI_PASS + EXT_CLEANUP_FAIL + NEEDS_REVERIFY
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```

### Auth / fetch notes

- `gh auth status`: **OK**
- Issue/PR primary fetch: **OK**
- Issue comments API: **OK** (0 comments each)
- Transient MOTD pre-tool hook cancellations occurred mid-session; final payloads written from successful `gh` outputs in `%TEMP%\rawrxd_issue*.json` / `rawrxd_pr*_summary.txt`
- No GitHub search API failure on the targeted issue/PR IDs

---

## 7. Summary counts (machine-readable)

```
ISSUES=3
ISSUE49_GATES_UNPROVEN=30
ISSUE50_LAYERS_UNSEALED=11
ISSUE50_PROVIDER_ISOLATED_CLAIMED=32
ISSUE57_GATES=45
ISSUE57_OPEN=45
ISSUE57_FINISH25_STRONG_OVERLAP≈18
PRS=5
PRS_PARTIAL=1
PRS_HELD=4
PRS_CONFLICTING=4
CI_SUCCESS_CHECKS_NON_SECURITY≈0
LOCAL_EVIDENCE_TREES_PRIMARY=6
INVENT_PASS=0
```
