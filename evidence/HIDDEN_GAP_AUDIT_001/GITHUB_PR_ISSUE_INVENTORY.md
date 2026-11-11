# AUDIT TRACK B — GitHub PR/Issue Acceptance Inventory

```
TRACK=B
REPO=ItsMehRAWRXD/RawrXD
FETCHED_VIA=gh CLI
FETCH_DATE=2026-11-09
PROMOTE=0
CERTIFIED=0
FAIL_CLOSED=1
INVENTED_PASS=0
RECONCILIATION=unfinished_acceptance_work_evidence_NOT_proof_every_impl_defective
GITHUB_SEARCH_MISS_NOTE=INTEG_004/Finish-25 code search returned 0 hits; miss ≠ local absence
```

---

## Reconciliation (governing)

These GitHub PRs/issues are **unfinished acceptance / certification inventory**. They do **not** prove that every underlying implementation is defective. Absence of a GitHub code-search hit for `INTEG_004` / `Finish-25` is a **search miss**, not evidence that local artifacts are absent.

`NOT_RUN ≠ PASS`. `OPEN ≠ FAIL_IMPL`. `CI FAILURE before runner assignment ≠ compiler defect`. Merge authorization is **not** implied by PR existence.

---

## PR inventory (exact state)

### PR #77 — IDE Product Path (ConPTY, async inference UI, Problems, Output, four-panel)

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/pull/77 |
| Title | P0: IDE product path — ConPTY, inference UI, Problems/output wiring |
| State | **OPEN** (not draft) |
| Merged | **NO** (`mergedAt=null`, `mergeCommit=null`) |
| Mergeable | **CONFLICTING** (`mergeable=false`) |
| Base / Head refs | `main` ← `feature/ide-agentic-product-path-20261026` |
| Head SHA | `9edf63fed82bdf427f734591bff262282f6fe822` |
| Base SHA | `033a8acb55d46d2fc22a84428e81f3167a0c3897` |
| Explicit non-claims | `PROMOTE=0`, `CERTIFIED=0`; opening does **not** authorize merge; Finish-25 remains **19/25** until SHA-specific evidence |
| Test plan checkboxes | All **unchecked** (OPEN): clean build/link; ConPTY start/stop/resize/interrupt; async inference UI marshal; Problems+Output; no regression vs `A4F083DF…`; SHA-specific evidence |
| CI rollup (observed) | FAILURE: Analyze (actions), Analyze C/C++ (cpp), native-build, Analyze (javascript-typescript), hexmag-certification; SUCCESS: Cursor Security Agent |
| Required evidence still OPEN | Four-panel IDE E2E on this head SHA; ConPTY paths; async inference UI (no worker HWND); Problems aggregator + Output routing; baseline non-regression receipt; merge conflict resolution |

---

### PR #78 — AgentSession GUI

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/pull/78 |
| Title | P1: AgentSession GUI — lifecycle, cancellation, and cleanup |
| State | **OPEN** (not draft) |
| Merged | **NO** |
| Mergeable | **CONFLICTING** |
| Base / Head refs | `main` ← `feature/agent-session-gui-20261026` |
| Head SHA | `84b4725f798f329a31660e87820c2f57115247ce` |
| Base SHA | `033a8acb55d46d2fc22a84428e81f3167a0c3897` |
| Explicit non-claims | `PROMOTE=0`, `CERTIFIED=0`; do **not** inherit PASS from PR #77 or another executable; Finish-25 **19/25** held |
| Test plan checkboxes | All **unchecked** (OPEN): build/link; session ownership/transitions; cancel/cleanup; kill/restore/proof; baseline non-regression; SHA-specific evidence |
| CI rollup (observed) | FAILURE: Analyze (actions), Analyze C/C++ (cpp), native-build, Analyze (javascript-typescript), hexmag-certification; SUCCESS: Cursor Security Agent |
| Required evidence still OPEN | AgentSession lifecycle E2E on this head SHA; cancel/cleanup orphan-free proof; independent of PR #77 PASS; merge conflict resolution |

---

### PR #79 — ExtensionHost Runtime

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/pull/79 |
| Title | P2: ExtensionHost runtime — host/worker, IPC, shutdown, crash recovery |
| State | **OPEN** (not draft) |
| Merged | **NO** |
| Mergeable | **CONFLICTING** |
| Base / Head refs | `main` ← `feature/extensionhost-runtime-clean-20261102` |
| Head SHA | `13c33a6f35c6493cd5bf60a9f5f0a21f6271ef8c` |
| Base SHA | `033a8acb55d46d2fc22a84428e81f3167a0c3897` |
| Explicit non-claims | `PROMOTE=0`, `CERTIFIED=0`; compile/link alone is **not** ExtensionHost PASS; no PASS inheritance from #77/#78 |
| Test plan checkboxes | All **unchecked** (OPEN): build/link Win32IDE+worker; host→worker IPC handshake; **real** extension load/execute (not stub-only); shutdown + crash-recovery fail-closed; baseline non-regression; SHA-specific evidence |
| CI rollup (observed) | FAILURE: Analyze (actions), Analyze C/C++ (cpp), native-build, Analyze (javascript-typescript), hexmag-certification; SUCCESS: Cursor Security Agent |
| Required evidence still OPEN | Real extension load/execute receipt on this head SHA; IPC/shutdown/crash-recovery; merge conflict resolution |

**Integration order (per PR bodies):** #77 → #78 → #79 → only then unified full-feature candidate → Finish-25 → release audit.

---

### PR #75 — Native Compiler/Linker (37 local vs 16 native-linker unexecuted)

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/pull/75 |
| Title | WIP: native compiler, CMake builder and PE/COFF linker acceptance pipeline |
| State | **OPEN** + **DRAFT** |
| Merged | **NO** |
| Mergeable | **MERGEABLE** (`mergeable=true` API) — draft; not merge-authorized |
| Base / Head refs | `fix/deep2-multimodel-safety-20261025` ← (PR head) |
| Head SHA | `3bbda91366161c08c103cd1111dc413e92bdd25b` |
| Base SHA | `fd906cc7816132927e91b4322f541319fc51528e` |
| Claimed local evidence (PR body; not re-executed this audit) | **37/37 local** Python black-box tests PASS (adapter/runner); blob SHAs cited for toolchain + tests |
| Explicit unexecuted | **16 native-linker** COFF-to-PE / negative mutation tests **committed but NOT EXECUTED** |
| CI state | Acceptance workflow jobs reported FAILURE with empty runner / 0 executed steps (e.g. run `42339466791`); **NOT a compiler PASS**; Windows PE execution/CRT/SDK ABI **not claimed**; MSVC own-linker positive integration **NOT EXECUTED** |
| Required evidence still OPEN | Execute 16 native-linker CTests on real toolchain; Windows PE execute path; CI runner assignment success; IDE menu / model-tool registration; T05/T24/T25 remain OPEN per PR body |

---

### PR #76 — Deep2 Consolidation (HELD / conflicts / CI)

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/pull/76 |
| Title | Consolidate Deep2 and native compiler work into main (certification pending) |
| State | **OPEN** + **DRAFT** |
| Merged | **NO** |
| Mergeable | **CONFLICTING** |
| Base / Head refs | `main` ← `fix/deep2-multimodel-safety-20261025` |
| Head SHA | `e91b476b51902e26fd1b0c3678ffce84efe7057d` |
| Base SHA | `033a8acb55d46d2fc22a84428e81f3167a0c3897` |
| Body disposition | **DO NOT MERGE** until divergence, conflicts, and CI failures reviewed; deliberately draft to prevent unverified promotion |
| CI state | Broad FAILURE rollup (native-build, windows/linux, compiler-pipeline, security suite, bridges, etc.); body notes jobs fail within seconds / BlobNotFound logs — **NOT_RUN/infra ≠ product PASS** |
| Changed files (API count) | 30 |
| Required evidence still OPEN | Conflict resolution vs `main`; CI that actually executes steps; certification review before any merge consideration |

---

## Issue inventory

### Issue #57 — 45 gates (three groups of 15)

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/57 |
| Title | RawrXD batch 024: 45 E2E native IDE, Slingshot/compiler and GPU release gates |
| State | **OPEN** |
| Framing | "**Open acceptance gates, not 45 accomplished fixes.**" Every item needs revision-specific receipt |

#### Group A — Native IDE E2E and source/dependency closure (15)

1. Resolve GitHub Actions jobs failing with runner_id=0 and no steps; capture successful Linux + Windows run
2. Re-run source-only per-file SHA-256 inventory on audited commit; archive machine-readable JSON
3. Re-run CMake literal-source admission; disposition every missing path
4. Run strict no-external-dependencies scan; remove or quarantine Qt/nlohmann production-link deps
5. Establish frozen manifest mapping each feature to compiled TU and call site
6. Rebuild real native Win32 IDE from clean checkout using no-Qt flags
7. Rebuild `rawr.exe` and snapshot/agent targets from same clean checkout
8. Launch Win32 IDE and save, close, reopen and compare file SHA-256
9. Verify terminal start, output stream, exit code, cancellation and process cleanup
10. Verify native PowerShell panel command output, terminal lifecycle and restart
11. Verify complete native LSP JSON-RPC handshake, diagnostics, definitions and completion
12. Verify GhostText inline completion display, accept/cancel and real model adapter
13. Verify native browser rendering, network/origin isolation and lifecycle
14. Verify debugger breakpoints, step, watch, variable/stack windows in real debuggee
15. Prove IDE-driven agent edit → build → test → snapshot rollback with source diff and evidence

#### Group B — Slingshot source, native compiler/linker and cross-platform outputs (15)

1. Recover exact `src/rawrxd_slingshot_braid.{hpp,cpp}` format owners from legacy repo with hashes
2. Validate SBraid emitter/read-back with binary-format roundtrip + corrupt/truncated rejection
3. Review `SlingshotGuard.cpp` concurrency/integrity constraints before native Deep2 integration
4. Replace `SlingshotPOC.cpp` simulated VRAM/fake weights with real allocator and measured prefetch if promoted
5. Reconcile legacy source against canonical Deep2 tensor residency and model loader
6. Recover compiler and linker source inventory from MASM, native, and independent-ancestry branches
7. Prove native `C` frontend compiles representative portable C programs
8. Prove general native `C++20` frontend compiles templates/exceptions/ABI samples
9. Prove MASM x86/x64 syntax, relocation and COFF interoperability with independent assembler oracle
10. Prove NASM x86/x64 syntax, relocation and object interoperability with independent assembler oracle
11. Prove rawrxd native linker PE32/PE32+ startup, imports, sections, relocations, exports
12. Prove full compile → link → execute with no external compiler for supported subsets
13. Define capability vs host-toolchain fallback for ELF/Linux; run Linux native executable smoke
14. Define Mach-O/macOS and iOS code signing and target SDK/toolchain contracts with macOS runner evidence
15. Define Android ABI, ELF/shared library and APK packaging/device contracts with Android test evidence

#### Group C — GPU correctness, 150 TPS, Top-25 parity and release (15)

1. Build deterministic reference model/quant baseline; archive tokenizer/template/logits/token receipts
2. Verify corrected `ffn_gate_up` multi-token path on GPU before performance promotion
3. Verify Deep2 Q4_K, Q5_K, Q6_K and F32 fused host GEMV against independent numerical oracles
4. Compare four recovered fused GEMV paths to pre-patch queue submit/fence wait counts
5. Verify lane-state restoration across success, error, fallback, and dual-GPU paths
6. Measure exact R9700 single-GPU TPS for 32/128/256 tokens with paired control
7. Measure exact RX7800 XT single-GPU TPS for 32/128/256 tokens with paired control
8. Measure dual-GPU full-model TPS on both discrete devices with strict no-fallback counters
9. Attribute GPU0 fence waits and GPU1 overlap using timestamps and PCIe transfer receipts
10. Certify GGUF shard/index, quant and architecture parsing on user-supported model matrix
11. Check Nemotron SSM Q4_K NaN and residual parity across reference boundaries
12. Benchmark real model 150+ single-stream decode TPS if attainable; never report synthetic kernel TPS
13. Require identical model/sampling/seed/context/clocks/thermal/residency for performance A/B
14. Apply 25 IDE ×20 capability = 500 cell feature matrix with real test evidence
15. Certify signed/reproducible packaging, security, crash/rollback, offline, cross-platform and release acceptance

**All 45 checkboxes on the issue body are unchecked → disposition OPEN / NOT_PASS (no invented PASS).**

---

### Issue #50 — Certification Ladder (11 layers: 0–10)

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/50 |
| Title | [MASTER] RawrXD Certification Ladder — 0-to-10 Tracking |
| State | **OPEN** |
| Labels | `certification`, `master-tracking` |

#### Layer table (from #50 body)

| Layer | Status on #50 | Child issue | Notes on #50 |
|---|---|---|---|
| 0 | IN PROGRESS | #39 | Provider isolated tests PASS; **integration seal pending** |
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

Provider isolated tests cited on #50 (DONE table): ProductionProfiler/NVMeStream/BP16Streamer/CompressedKVCache/MARSController — **isolated only**; does not seal Layer 0 integration or any later layer.

#### Layer defs for 2–8 (from child issues; present)

| Layer | Issue | Title / cert target | Definition (compressed) |
|---|---|---|---|
| 2 | https://github.com/ItsMehRAWRXD/RawrXD/issues/41 **OPEN** | `[LAYER-2] GPU/Runtime Execution Closure` · `DEEP2_GPU_RUNTIME_FINAL_001` | Vulkan init, device enum/select, R9700/7800XT policy, GPU weight residency, forward/decode counts >0, CPU fallback=0, staging/DMA/budget/fences, finite logits, tokens >0 |
| 3 | https://github.com/ItsMehRAWRXD/RawrXD/issues/42 **OPEN** | `[LAYER-3] Agent Reasoning + Tool Authority` · `RAWRXD_AGENT_AUTHORITY_FINAL_001` | GPU reasons → CPU Tool Authority → real tools → reinject → same session continues; sandbox; ORIGIN=MODEL; no stubs |
| 4 | https://github.com/ItsMehRAWRXD/RawrXD/issues/43 **OPEN** | `[LAYER-4] Autonomous Edit/Build/Test Loop` · `RAWRXD_AGENT_EDIT_BUILD_TEST_001` | BROKEN_SOURCE → edit → build fail recovery → rebuild → TEST_PASS without human intervention |
| 5 | https://github.com/ItsMehRAWRXD/RawrXD/issues/44 **OPEN** | `[LAYER-5] Multi-Agent / Dual-GPU Orchestration` · `RAWRXD_MULTI_AGENT_001` | R9700 coding agent + RX7800XT independent reviewer; independent contexts; shared CPU Tool Authority |
| 6 | https://github.com/ItsMehRAWRXD/RawrXD/issues/45 **OPEN** | `[LAYER-6] IDE Surface Completion` · `RAWRXD_IDE_SURFACE_001` | Explorer/Editor/Terminal/Chat/Agent/Build/Git/LSP/Debugger/… shipping chat test through real GPU+tools |
| 7 | https://github.com/ItsMehRAWRXD/RawrXD/issues/46 **OPEN** | `[LAYER-7] Product/Repository Convergence` · `RAWRXD_REPO_CONVERGENCE_001` | One authoritative CMake root; eliminate Qt/stale graphs/ghost sources; clean clone→cmake→build→test |
| 8 | https://github.com/ItsMehRAWRXD/RawrXD/issues/47 **OPEN** | `[LAYER-8] CI/Release Authority` · `RAWRXD_CI_RELEASE_001` | checkout→stub scan→strict native x64→compile→link→unit→headless integ→receipt validation→package; no synthetic green |

(Layers 9 `#48` PERFORMANCE and 10 `#49` PRODUCT_FINAL also OPEN; deps chain unbroken → **no layer 2–10 PASS invented**.)

---

### Issue #49 — Product-Final Acceptance (mandatory E2E scenario checklist)

| Field | Exact state |
|---|---|
| URL | https://github.com/ItsMehRAWRXD/RawrXD/issues/49 |
| Title | [LAYER-10] Product-Final Acceptance |
| State | **OPEN** |
| Cert target | `=== RAWRXD_PRODUCT_FINAL_001 ===` |
| Depends on | #48 (Layer 9 — Performance Closure) |
| Labels | `certification`, `layer-10` |

#### Mandatory E2E scenario (from issue body)

```
Fresh clone. No hidden environment variables. No development-only stubs. No manually pre-created receipt.

launch RawrXD
      ↓
select local model
      ↓
select R9700
      ↓
open project
      ↓
tell agent:
"Find the bug, fix it, build it and test it."
      ↓
agent reads project
      ↓
GPU reasons
      ↓
CPU Tool Authority operates
      ↓
source edited
      ↓
build fails once
      ↓
model diagnoses it
      ↓
second edit
      ↓
build succeeds
      ↓
tests succeed
      ↓
reviewer GPU reviews patch
      ↓
agent reports evidence
      ↓
Git commit
```

#### Mandatory final receipt keys (all required PASS / zero stubs; none proven CLOSED by this audit)

```
CLEAN_CLONE
STRICT_BUILD
DEEP2_LAYER0
DEEP2_INTEGRATION
GPU_RUNTIME
LOCAL_MODEL_LOAD
GPU_FORWARD
FINITE_LOGITS
GENERATION
AGENT_REASONING
TOOL_AUTHORITY
REAL_TOOL_CALL
RESULT_REINJECTION
AGENT_CONTINUATION
REAL_SOURCE_EDIT
BUILD_FAILURE_RECOVERY
FINAL_BUILD
FINAL_TESTS
MULTI_AGENT_REVIEW
IDE_CHAT
IDE_EDITOR
IDE_TERMINAL
IDE_GIT
STUB_PROVIDERS=0
STUB_FALLBACKS=0
SYNTHETIC_RECEIPTS=0
UNRESOLVED_EXTERNALS=0
CI_REPRODUCIBLE
CLEAN_MACHINE_REPRODUCIBLE
VERDICT
```

**Disposition this audit:** all #49 receipt keys remain **OPEN / NOT_PROVEN**. `PROMOTE=0`.

---

## GitHub search note (INTEG_004 / Finish-25)

```
gh search code "INTEG_004" --repo ItsMehRAWRXD/RawrXD  → 0 hits
gh search code "Finish-25" --repo ItsMehRAWRXD/RawrXD → 0 hits
gh search code "Finish 25" --repo ItsMehRAWRXD/RawrXD → 0 hits
```

Finish-25 is referenced in PR #77/#78/#79 **bodies** as prior authority **19/25**, but code search does not index those issue/PR bodies as code. **Search miss ≠ local absence** of Finish-25 / INTEG_004 evidence trees.

---

## Structured blocker list mapped to product-final #49

| #49 receipt / scenario step | Mapped GitHub blocker (exact OPEN evidence) | Status |
|---|---|---|
| `CLEAN_CLONE` / `STRICT_BUILD` | #57 A06–A07 clean Win32IDE/`rawr.exe` rebuild; #46 Layer-7 single CMake graph; PR #76 CONFLICTING consolidation HELD | OPEN |
| `CI_REPRODUCIBLE` / `CLEAN_MACHINE_REPRODUCIBLE` | #57 A01 runner_id=0 / empty steps; PR #75/#76 CI fail-before-run / BlobNotFound; #47 Layer-8 CI/Release Authority OPEN | OPEN |
| `DEEP2_LAYER0` | #50 Layer 0 IN PROGRESS — integration seal pending (#39); not product-final closed | OPEN |
| `DEEP2_INTEGRATION` | #50 Layer 1 BLOCKED (#40); blocks entire ladder through #49 | OPEN |
| `GPU_RUNTIME` / `GPU_FORWARD` / `FINITE_LOGITS` / `GENERATION` / `LOCAL_MODEL_LOAD` | #41 Layer-2 OPEN; #57 Group C GPU gates all unchecked | OPEN |
| `AGENT_REASONING` / `TOOL_AUTHORITY` / `REAL_TOOL_CALL` / `RESULT_REINJECTION` / `AGENT_CONTINUATION` | #42 Layer-3 OPEN; PR #78 AgentSession GUI OPEN+CONFLICTING, test plan unchecked | OPEN |
| `REAL_SOURCE_EDIT` / `BUILD_FAILURE_RECOVERY` / `FINAL_BUILD` / `FINAL_TESTS` | #43 Layer-4 OPEN; #57 A15 agent edit→build→test→rollback OPEN; PR #75 16 native-linker tests UNEXECUTED | OPEN |
| `MULTI_AGENT_REVIEW` (reviewer GPU) | #44 Layer-5 OPEN (R9700 + RX7800XT independent contexts) | OPEN |
| `IDE_CHAT` / `IDE_EDITOR` / `IDE_TERMINAL` / `IDE_GIT` | #45 Layer-6 OPEN; PR #77 IDE product path OPEN+CONFLICTING (ConPTY/Problems/Output/four-panel unchecked); PR #79 ExtensionHost OPEN+CONFLICTING | OPEN |
| `STUB_PROVIDERS=0` / `STUB_FALLBACKS=0` / `SYNTHETIC_RECEIPTS=0` | Explicit non-claims on #77/#78/#79; #49 forbids stubs; no SHA-specific zero-stub seal fetched as PASS | OPEN |
| `UNRESOLVED_EXTERNALS=0` | #57 A03–A04 CMake admission + no-external-deps OPEN; PR #76 conflicts | OPEN |
| Scenario: launch → model → R9700 → project → agent fix/build/test → review → git | Conjunction of Layers 2–8 + PRs #75–#79 + #57 A/B/C; **no end-to-end #49 receipt exists as PASS on GitHub** | OPEN |
| Finish-25 / unified full-feature after #77+#78+#79 | Bodies require all three merge+pass first; all three CONFLICTING / unmerged; Finish-25 held at **19/25** per PR text | OPEN |
| `VERDICT=PASS` / promote | Blocked by entire ladder; explicit `PROMOTE=0` on open PRs | **PROMOTE=0** |

---

## Audit verdict

```
GITHUB_ACCEPTANCE_INVENTORY=RECORDED
MERGED_OF_75_76_77_78_79=0
DRAFT_HELD=PR75,PR76
CONFLICTING=PR76,PR77,PR78,PR79
ISSUE49_PRODUCT_FINAL=OPEN
ISSUE50_LADDER=OPEN (L2–L10 PENDING/BLOCKED chain)
ISSUE57_45_GATES=OPEN (0/45 checked)
REQUIRED_EVIDENCE_STILL_OPEN=YES
PROMOTE=0
INVENTED_PASS=0
```
