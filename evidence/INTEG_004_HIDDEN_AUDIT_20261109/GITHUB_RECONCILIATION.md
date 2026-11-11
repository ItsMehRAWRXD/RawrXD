# INTEG_004 — GitHub ↔ Local Acceptance Reconciliation

```text
AUDIT_ID=INTEG_004_HIDDEN_AUDIT_20261109
ASOF=2026-11-09T12:35Z
WORKSPACE=g:\~dev\rawrxd
CANDIDATE_SHA256=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
LOCAL_GIT_HEAD=9edf63fed82bdf427f734591bff262282f6fe822
PROMOTE=0
TIP_CLIMB=HOLD
R28_APPLY=HELD
LAW=NOT_RUN != PASS; SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
DISPOSITION_VOCAB=OPEN | PARTIAL | HELD | UNKNOWN
PASS_MARKS=0
```

## Fail-closed notes (binding)

1. No GitHub checkbox, PR narrative, or historical seal is treated as PASS for `CANDIDATE_SHA256`.
2. `CANDIDATE_SHA256` is **64 hex** → content/binary SHA-256, **not** a git commit OID. `git cat-file -t` in `rawrxd` returns *not a valid object name*. Local verification must hash the built artifact and compare; do not equate to PR head OIDs.
3. Local `rawrxd` HEAD equals PR #77 tip (`9edf63fe…`). That is **source tip identity only**, not product-final acceptance.
4. Sealed scoreboard witness `G3_DEEP2_SCOREBOARD_FENCE3_MLA_LIVE_001` (`RUN_ID=2b7091ecdbaf4d06b8edb424897961ce`) asserts `SCOREBOARD_SCHEDULER_LIVE=1` with `PROMOTE=0`. That is an **input**, not promotion.
5. Issue #39 is GitHub-`CLOSED` while its body and Issue #50 still describe Layer 0 as incomplete / integration seal pending. Fail-closed: treat Layer 0 integration as **PARTIAL/OPEN**, not PASS.

---

## Structured disposition table

| GitHub item | GH status / merge | Claimed evidence (GitHub text) | SHA-bound? | Local gate on `CANDIDATE_SHA256` | Disposition |
|---|---|---|---|---|---|
| **PR #75** Native Compiler/Linker | OPEN · **DRAFT** · MERGEABLE · mergeState **UNSTABLE** · base `fix/deep2-multimodel-safety-20261025` · head `3bbda91366161c08c103cd1111dc413e92bdd25b` · not merged | 37/37 local Python adapter/runner tests; PE structural recognition; Linux ELF invoke; CI runner often empty/`steps=0` (explicitly **not** PASS); 16 own-linker COFF→PE tests committed **unexecuted**; Windows PE/CRT/SDK ABI **not** claimed; IDE menu/tool dispatch **not** registered | **YES** — blob SHA `tools/rawrxd_native_toolchain.py`=`1636ca47ccea954712ae9e87e5f1f7469d235158`; test blob=`426e9f6619d2b0676c9c1c09ddcd030b9506423f`; head OID bound | Rebuild/run native toolchain suite against tree that produced candidate binary; execute 16 COFF→PE CTests; Windows PE execute smoke; prove adapter registration path; CI green with real runners | **PARTIAL** (local Python claims exist on PR tip; own-linker + IDE + CI + candidate-SHA bind **OPEN**) |
| **PR #76** Deep2 Consolidation | OPEN · **DRAFT** · **CONFLICTING/DIRTY** · base `main` · head `e91b476b51902e26fd1b0c3678ffce84efe7057d` · not merged | Consolidation candidate only; **DO NOT MERGE**; Windows+Linux CI fail in seconds; logs `BlobNotFound`; draft to prevent unverified promotion | Head OID only; **no** PASS receipt SHA | Resolve conflicts vs `main`; re-run CI with usable logs; certify Deep2+toolchain on same candidate binary; no merge until conflict+CI closed | **HELD** |
| **PR #77** IDE Product Path | OPEN · not draft · **CONFLICTING/DIRTY** · base `main` · head `9edf63fed82bdf427f734591bff262282f6fe822` (= local HEAD) · checks FAILURE (CodeQL/CI) · not merged | Scope: ConPTY, async inference UI marshal, Problems/output; **PROMOTE=0 CERTIFIED=0**; Finish-25 remains **19/25** until new SHA-specific evidence; all test-plan boxes **unchecked** | References frozen baseline `A4F083DF…` (truncated); requires **SHA-specific** evidence — **not** bound to `CANDIDATE_SHA256` | Clean Win32IDE build/link/launch from candidate; ConPTY start/stop/resize/interrupt; inference UI stream/cancel; Problems dedupe + Output routing; no-regression vs `A4F083DF…`; record receipts keyed to `CANDIDATE_SHA256` | **OPEN** |
| **PR #78** AgentSession GUI | OPEN · **CONFLICTING/DIRTY** · base `main` · head `84b4725f798f329a31660e87820c2f57115247ce` · not merged | Lifecycle/cancel/cleanup; **PROMOTE=0 CERTIFIED=0**; Finish-25 **19/25**; must not inherit PASS from #77; test plan unchecked | Same `A4F083DF…` baseline reference; SHA-specific evidence required; **not** bound to candidate | Session ownership transitions; cancel/cleanup; kill/restore/proof without false PASS; binary SHA match candidate | **OPEN** |
| **PR #79** ExtensionHost Runtime | OPEN · **CONFLICTING/DIRTY** · base `main` · head `13c33a6f35c6493cd5bf60a9f5f0a21f6271ef8c` · not merged | Host/worker IPC/shutdown/crash recovery; real extension load/execute (compile≠PASS); **PROMOTE=0 CERTIFIED=0**; Finish-25 **19/25**; test plan unchecked | Same baseline + SHA-specific rule; **not** bound to candidate | Host→worker IPC; real extension execute; shutdown + crash recovery fail-closed; binary SHA match candidate | **OPEN** |
| **Issue #49** Product-Final Acceptance (L10) | OPEN · labels `certification`,`layer-10` · blocked by #48 | Full product workflow receipt (`CLEAN_CLONE`…`VERDICT=PASS`); end-state local agentic IDE chain | Criteria list only — **no** sealed run SHA on issue | Execute #49 scenario on candidate binary; emit every receipt field from real run (no synthetic) | **OPEN** |
| **Issue #50** Certification Ladder 0–10 | OPEN · `master-tracking` | L0 IN PROGRESS (integration seal pending); L1 BLOCKED; L2–10 PENDING; provider isolated 32/32 claimed with short commits | Provider table cites short commits (`75a302ad`…); **not** candidate-bound; ladder itself unsealed | Reconcile each layer issue #39–#49 against candidate; do not promote on provider-isolated tests alone | **PARTIAL** (tracking exists; ladder incomplete) |
| **Issue #57** 45 acceptance gates | OPEN · all 45 checkboxes unchecked | Batch 024 A/B/C gates; requires revision-specific receipts; cites baseline SHAs / draft PRs #53/#55; CI run #40089650136 failed `steps=[]` | Provenance SHAs listed for baselines/branches; **gates themselves unbound / unchecked** | Map A01–A15, B01–B15, C01–C15 to candidate runs; each needs executable receipt | **OPEN** |

### Additional local authority row (not a GitHub issue, governs promote)

| Local seal | Status | Relation to GitHub | Disposition |
|---|---|---|---|
| `G3_DEEP2_SCOREBOARD_FENCE3_MLA_LIVE_001` | `SCOREBOARD_SCHEDULER_LIVE=1`; `PROMOTE=0`; `TIP_CLIMB=HOLD`; `NEXT_GATE=POST_SCHEDULER_PROMOTION_REQUIREMENTS` | Does **not** close #49/#50/#57 or PRs 75–79 | **HELD** (promote conjunction incomplete) |

---

## Issue #49 — Product-final workflow acceptance criteria (extracted)

**Target:** `=== RAWRXD_PRODUCT_FINAL_001 ===`

**Scenario (must be real, clean clone, no hidden env, no stubs, no pre-created receipts):**

```text
launch RawrXD → select local model → select R9700 → open project
→ agent: "Find the bug, fix it, build it and test it."
→ agent reads → GPU reasons → CPU Tool Authority → source edit
→ build fails once → model diagnoses → second edit → build OK → tests OK
→ reviewer GPU reviews → agent reports evidence → Git commit
```

**Final receipt fields (all required; none marked PASS in this audit):**

```text
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

**Depends on:** #48 (Layer 9). **Blocks:** none (final).

**Local map for candidate:** every field must be witnessed on binary whose SHA-256 is `CANDIDATE_SHA256`. Until then: **OPEN**.

---

## Issue #50 — Layers 0–10 gate definitions

### Tracker status (Issue #50 body)

| Layer | Tracker status | Issue | Notes from #50 |
|---|---|---|---|
| 0 | IN PROGRESS | #39 | Provider isolated tests claimed PASS; **integration seal pending** |
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

### Layer 0 — `#39` `DEEP2_LAYER0_FINAL_001` (GH CLOSED; body incomplete)

Provider integration seal still lists ProductionProfiler / NVMeStream / BP16Streamer / CompressedKVCache / MARSController closure criteria. Final conj includes `INTEGRATED_DEEP2_RUNTIME`, stub/UE counts, `STRICT_RELEASE_BUILD`. **Local disposition: PARTIAL/OPEN** (do not treat GH close as PASS).

### Layer 1 — `#40` `Deep2 Integration & Runtime Closure` (OPEN)

Acceptance: `STRICT_RELEASE_BUILD`, `INTEGRATED_DEEP2_RUNTIME`, `REAL_PROVIDER_INTERACTION`, `generateChat() ≥ 1 token`. **OPEN**.

### Layer 2 — `#41` `DEEP2_GPU_RUNTIME_FINAL_001` (OPEN) — detail

Blockers: Vulkan init; device enum/select; R9700/7800XT policy; weight residency; GPU forward/decode counters >0; CPU fallback=0; pinned staging; cross-GPU DMA; memory budget; queue/fence lifecycle; failure recovery; model geometry; finite logits.

```text
VULKAN_BACKEND · DEVICE_ENUMERATION · EXPLICIT_DEVICE_SELECTION
R9700_AUTHORITY · RX7800XT_AUTHORITY=PASS_OR_NOT_PRESENT
WEIGHTS_GPU_RESIDENT · GPU_FORWARD_COUNT_GT_0 · GPU_DECODE_COUNT_GT_0
CPU_FORWARD_FALLBACK=0 · SYNTHETIC_GPU_EVENTS=0
MEMORY_BUDGET_ENFORCED · OUT_OF_CORE_PATH · MULTI_GPU_STAGED_DMA
LOGITS_FINITE · GENERATED_TOKEN_COUNT_GT_0 · STRICT_GPU_VIOLATIONS=0
TEST_FAILURES=0 · VERDICT
```

Critical predecessor failure to eliminate: `FORWARD_PASS_OK=FAIL`, `LOGITS_FINITE=FAIL`, `GENERATED_TOKEN_COUNT=0`.

### Layer 3 — `#42` `RAWRXD_AGENT_AUTHORITY_FINAL_001` (OPEN)

GPU tool-request → CPU Tool Authority → reinjection → same-session continue.

```text
MODEL_REASONING_GPU · TOOL_REQUEST_ORIGIN_MODEL · SYNTHETIC_TOOL_REQUESTS=0
TOOL_PARSER · TOOL_AUTHORITY · SANDBOX · REAL_TOOL_EXECUTION
TOOL_RESULT_REAL · RESULT_REINJECTION · SAME_AGENT_CONTINUATION
POST_TOOL_TOKEN_COUNT_GT_0 · STUB_FALLBACKS=0 · TEST_FAILURES=0 · VERDICT
```

### Layer 4 — `#43` `RAWRXD_AGENT_EDIT_BUILD_TEST_001` (OPEN)

Prove: `BROKEN_SOURCE → WORKING_SOURCE → BUILD → TEST` without human intervention.

```text
TASK_ACCEPTED · WORKSPACE_READ · MODEL_GENERATED_EDIT · REAL_FILE_EDIT
BUILD_INVOKED · BUILD_RESULT_RETURNED_TO_MODEL · FAILURE_RECOVERY_EXERCISED
SECOND_EDIT_MODEL_GENERATED · REBUILD_PASS · TEST_PASS · FINAL_DIFF_VERIFIED
HUMAN_INTERVENTION_REQUIRED=0 · SYNTHETIC_TOOL_RESULTS=0 · STUB_FALLBACKS=0 · VERDICT
```

### Layer 5 — `#44` `RAWRXD_MULTI_AGENT_001` (OPEN)

R9700 coding agent + 7800 XT reviewer; **independent model contexts**.

```text
AGENT_A_DEVICE=R9700 · AGENT_B_DEVICE=RX7800XT · AGENT_CONTEXTS_INDEPENDENT
TASK_DELEGATION · CROSS_AGENT_MESSAGE · CODE_AGENT_EDIT · REVIEW_AGENT_CRITIQUE
CODE_AGENT_REVISION · REVIEW_AGENT_VERIFICATION · CPU_TOOL_AUTHORITY_SHARED · VERDICT
```

### Layer 6 — `#45` `RAWRXD_IDE_SURFACE_001` (OPEN)

UI surface list (Explorer…Settings…workspace). Shipping chat test must traverse GPU→tools→CPU authority→continue→UI (not edit-control-only). **OPEN**.

### Layer 7 — `#46` `RAWRXD_REPO_CONVERGENCE_001` (OPEN)

One CMake root → native x64 → Deep2+Tool Authority+IDE+Agent+tests → shipping artifacts. Delete/archive Qt/stale graphs/ghosts/stubs/conflicting CI. Acceptance: `git clone → cmake → build → test` reconstructs product. **OPEN**.

### Layer 8 — `#47` `RAWRXD_CI_RELEASE_001` (OPEN)

Pipeline: checkout → stub scan → strict native x64 configure → compile → link → unit → headless integration → receipt validation → package. No synthetic green. **OPEN**.

### Layer 9 — `#48` `RAWRXD_PERFORMANCE_001` (OPEN)

Correctness gate never regresses; performance gate may fail without invalidating correctness. TPS/model/residency targets listed. Local PERF contract: `TIP_CLIMB=HOLD`, `PROMOTE=0`. **HELD/OPEN**.

### Layer 10 — `#49` (above) — **OPEN**.

---

## Issue #57 — 45 gates (summary for candidate mapping)

All items unchecked on GitHub. Groups:

- **A (01–15):** Actions runners, SHA-256 inventory, CMake admission, no-external deps, frozen manifest, Win32 IDE + `rawr.exe` clean rebuild, file SHA roundtrip, terminal/PowerShell/LSP/GhostText/browser/debugger, IDE agent edit→build→test→rollback.
- **B (01–15):** Slingshot braid recovery/validation, compiler/linker inventory, C/C++/MASM/NASM frontends, native PE linker, compile→link→execute without external toolchain, ELF/Mach-O/Android contracts with real runner evidence.
- **C (01–15):** Reference model/quant, `ffn_gate_up`, fused GEMV oracles, lane restore, R9700/RX7800/dual TPS, GGUF matrix, Nemotron SSM, 150+ TPS if attainable, 500-cell matrix, signed packaging/release.

**Release law (issue):** PASS only with reproducible executable evidence identifying tested commit. Preserve CI failures; do not force-promote.

**Local disposition for all 45 on candidate:** **OPEN**.

---

## Candidate SHA verification checklist (required next local work)

```text
CANDIDATE_SHA256=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
LOCAL_HEAD_GIT=9edf63fed82bdf427f734591bff262282f6fe822   # == PR77 tip; identity only
GIT_OBJECT_FOR_CANDIDATE=ABSENT
```

| Step | Action | Maps to | Disposition until done |
|---|---|---|---|
| 1 | Identify which local binary/path claims this SHA-256; re-hash file | All items | **UNKNOWN** → resolve or remain UNKNOWN |
| 2 | Confirm build provenance (branch tip, cmake flags, no stubs) | #46, #47, PR77–79 | OPEN |
| 3 | Native toolchain 37 + 16 COFF→PE + Windows PE smoke | PR #75, #57 B | PARTIAL/OPEN |
| 4 | ConPTY / Problems / inference UI on that binary | PR #77 | OPEN |
| 5 | AgentSession lifecycle/cancel/cleanup | PR #78 | OPEN |
| 6 | ExtensionHost real load/execute + crash recovery | PR #79 | OPEN |
| 7 | Deep2 GPU runtime counters + finite logits + tokens>0 | #41 L2, #40 L1 | OPEN |
| 8 | Tool Authority + reinjection | #42 L3 | OPEN |
| 9 | Broken→fixed edit/build/test loop | #43 L4, #49 | OPEN |
| 10 | Dual-GPU multi-agent if hardware present | #44 L5, #49 | OPEN / HELD if HW absent |
| 11 | CI with real runners (not `steps=[]` / BlobNotFound) | #47 L8, #57 A01, PR #76 | HELD/OPEN |
| 12 | Promote conjunction only if PRODUCT_OPEN && SESSION_ENTER && GENERATED_TOKENS>0 && TOKEN_COMMIT [+ multi-family] | Local PERF / Deep2ProductGate | **HELD** (`PROMOTE=0`) |

---

## Merge-state summary

| PR | Draft | Mergeable | Merge state | Merged |
|---|---|---|---|---|
| 75 | yes | MERGEABLE | UNSTABLE | no |
| 76 | yes | CONFLICTING | DIRTY | no |
| 77 | no | CONFLICTING | DIRTY | no |
| 78 | no | CONFLICTING | DIRTY | no |
| 79 | no | CONFLICTING | DIRTY | no |

**None merge-ready under fail-closed policy.** Conflicts and/or unstable CI block promotion narrative even before local candidate gates.

---

## Authority footer

```text
PROMOTE=0
TIP_CLIMB=HOLD
R28_APPLY=HELD
PASS_INVENTED=0
GITHUB_CLOSE != LAYER_SEAL
PR_CLAIM != CANDIDATE_SHA_RECEIPT
SCOREBOARD_SCHEDULER_LIVE=1 ≠ PROMOTE
NEXT_GATE=POST_SCHEDULER_PROMOTION_REQUIREMENTS
AUDIT_VERDICT=RECONCILED_FAIL_CLOSED
```
