# CERTIFICATION_LADDER_MAP — Layer 0–10 + Issue #57 + Wave1 crosswalk

```text
ASOF_UTC=2026-11-10T07:00:00Z
REPO=ItsMehRAWRXD/RawrXD
MASTER_TRACKING=#50 (OPEN)
RC4_LANE=CLOSED / IMMUTABLE
RC4_SHA=78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596
RC4_PUBLICATION_COMMIT=423ed47fcbd6610ea9742a538724a652f80123e5
RC4_PUBLICATION_BRANCH=upload/computer-use-20261110
PROMOTE=0
CERTIFIED=0
MATURITY=82%_ESTIMATE_UNCHANGED
TIP_CLIMB=HOLD
G15=NOT_ESTABLISHED
INVENT_PASS=0
NO_RC4_VERDICT_MUTATION=1
NO_CROSS_SHA_PASS_INHERITANCE=1
LAW=NOT_RUN != PASS ; SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
```

Inventory only. Does not establish acceptance, maturity increase, or promotion.

---

## 1) Issue #50 Layers 0–10 → Issues #39–#49

GitHub state pulled `2026-11-10` via `gh` from `ItsMehRAWRXD/RawrXD`.  
Layer 2–3 acceptance criteria are quoted from issue bodies (not inferred).

| Layer | Issue | GH state | Title (short) | Issue-body milestone / criteria (source) | LOCAL evidence (path + SHA if any) | Local note (fail-closed) |
|------:|------:|----------|---------------|-------------------------------------------|------------------------------------|--------------------------|
| 0 | #39 | **CLOSED** `2026-09-24` | Deep2 GPU Engine Integration & Runtime Residency Closure | Target `DEEP2_LAYER0_FINAL_001`. Providers Chamber/PlasmaGovernor/ToroidalKV/SovereignOOC/Elastic/Cyclone listed PASS in body; remaining ProductionProfiler, NVMeStream, BP16Streamer, CompressedKVCache, MARSController. Final seal requires STRICT_RELEASE_BUILD + INTEGRATED_DEEP2_RUNTIME + VERDICT=PASS. | `evidence/DEEP2_LAYER0_QUANT_FFN_RECOVERY_001\` (no EXE SHA pinned in this inventory). #50 body cites isolated provider commits: ProductionProfiler `75a302ad`, NVMeStream `1ee4a755`, BP16Streamer `faac5d52`, CompressedKVCache `de4de28a`, MARSController `06d76700`. | Issue CLOSED while #50 still says Layer 0 “integration seal pending.” Isolated provider PASS ≠ Layer 0 integration seal. |
| 1 | #40 | **OPEN** | Deep2 Integration & Runtime Closure | Acceptance: STRICT_RELEASE_BUILD, INTEGRATED_DEEP2_RUNTIME, REAL_PROVIDER_INTERACTION, `generateChat()` ≥ 1 token. Blocked by #39 in body (historical). | `evidence/RAWRXD_DEEP2_RUNTIME_*`, `RAWRXD_DEEP2_FULL_FORWARD_001`, `DEEP2_ONE_TOKEN_PONG` (family of receipts; not re-scored here). | OPEN. No same-SHA product-final credit onto RC4. |
| 2 | #41 | **OPEN** | GPU/Runtime Execution Closure | **From #41 body — do not infer:** Target `DEEP2_GPU_RUNTIME_FINAL_001`. Criteria include `VULKAN_BACKEND`, `DEVICE_ENUMERATION`, `EXPLICIT_DEVICE_SELECTION`, `R9700_AUTHORITY`, `RX7800XT_AUTHORITY=PASS_OR_NOT_PRESENT`, `WEIGHTS_GPU_RESIDENT`, `GPU_FORWARD_COUNT_GT_0`, `GPU_DECODE_COUNT_GT_0`, `CPU_FORWARD_FALLBACK=0`, `SYNTHETIC_GPU_EVENTS=0`, `MEMORY_BUDGET_ENFORCED`, `OUT_OF_CORE_PATH`, `MULTI_GPU_STAGED_DMA`, `LOGITS_FINITE`, `GENERATED_TOKEN_COUNT_GT_0`, `STRICT_GPU_VIOLATIONS=0`, `TEST_FAILURES=0`, `VERDICT=PASS`. Critical predecessor failures named: FORWARD_PASS_OK=FAIL, LOGITS_FINITE=FAIL, GENERATED_TOKEN_COUNT=0. | `evidence/RAWRXD_VULKAN_*`, `DEEP2_GPU_*`, `DUAL_GPU_FORWARD_*` (historical). RC4: G08 GPU = **NOT_RUN** on `78E187…`. | OPEN. Criteria taken verbatim from issue body. |
| 3 | #42 | **OPEN** | Agent Reasoning + Tool Authority | **From #42 body — do not infer:** Target `RAWRXD_AGENT_AUTHORITY_FINAL_001`. Architecture: GPU reason → tool request → CPU Tool Authority → ToolResult → same GPU session. Criteria: `MODEL_REASONING_GPU`, `TOOL_REQUEST_ORIGIN_MODEL`, `SYNTHETIC_TOOL_REQUESTS=0`, `TOOL_PARSER`, `TOOL_AUTHORITY`, `SANDBOX`, `REAL_TOOL_EXECUTION`, `TOOL_RESULT_REAL`, `RESULT_REINJECTION`, `SAME_AGENT_CONTINUATION`, `POST_TOOL_TOKEN_COUNT_GT_0`, `STUB_FALLBACKS=0`, `TEST_FAILURES=0`, `VERDICT=PASS`. | `evidence/AGENT_TOOL_*`, `T15_DIRECT_TOOL_*`, `RAWRXD_NATIVE_AGENT_COMPAT_001`. RC4 agent path: `AGENT_REPAIR_RECEIPT.txt` **FAIL** at READ; CU GUI **FAIL** (orphan registry). Standalone `computer_use_001` ≠ IDE GUI E2E (`STANDALONE_BRIDGE_CREDIT=0`). | OPEN. Wave1 primary surface. |
| 4 | #43 | **OPEN** | Autonomous Edit/Build/Test Loop | Target `RAWRXD_AGENT_EDIT_BUILD_TEST_001`. Acceptance includes TASK_ACCEPTED…FINAL_DIFF_VERIFIED; important test BROKEN_SOURCE→WORKING_SOURCE→BUILD_PASS→TEST_PASS. | `evidence/rawr_autonomous_repair\`, `deep2_autonomous_repair\`, `AGENT_E2E_*`, `RELEASE_FREEZE_001\` Issue#49 engineering on **35C22…** (not RC4). | OPEN. Historical 35C22 engineering ≠ RC4 runtime. |
| 5 | #44 | **OPEN** | Multi-Agent / Dual-GPU Orchestration | Target `RAWRXD_MULTI_AGENT_001`. Independent agent contexts on R9700 + RX7800XT; shared CPU Tool Authority. | `evidence/DUAL_GPU_FORWARD_*`, `RAWRXD_MULTI_MODEL_AGENTIC_001`. | OPEN. No RC4 multi-agent exercise. |
| 6 | #45 | **OPEN** | IDE Surface Completion | Target `RAWRXD_IDE_SURFACE_001`. UI checklist (Explorer…Settings). Shipping chat test: Send→GPU→tools→CPU authority→continue→UI. | `evidence/FULL_FEATURE_*`, `FULL_IDE\`, `IDE_RELEASE_READINESS_001\` (incl. RC4 G02 Native UI **PASS** on `78E187…`). | OPEN. Partial RC4 UI/chat tokens only. |
| 7 | #46 | **OPEN** | Product/Repository Convergence | Target `RAWRXD_REPO_CONVERGENCE_001`. One authoritative CMake root; delete/archive obsolete graphs. | `evidence/SOURCE_AUTHORITY_RECONCILIATION_001`, `RAWRXD_CANONICAL_INTEGRATION_*`. | OPEN. |
| 8 | #47 | **OPEN** | CI/Release Authority | Target `RAWRXD_CI_RELEASE_001`. Pipeline checkout→stub scan→strict configure→compile→link→unit→headless→receipt validate→package. | `evidence/RELEASE_FREEZE_001\`, `PRODUCT_BINARY_SEAL_001`, `IDE_RELEASE_READINESS_001\` (G13 Deployment package integrity **PASS** on RC4 package). | OPEN. Issue #57 A01 notes Actions runner_id=0 failure class (obligation, not auto-defect). |
| 9 | #48 | **OPEN** | Performance Closure | Target `RAWRXD_PERFORMANCE_001`. Correctness gate never regresses; performance gate separate. | `evidence/S07_*`, `DEEP2_STRATA_TPS_PARITY_001`, `gpu_recovery_perf_20261020`, AGENTS.md performance contracts under `rawrxd/evidence/RAWRXD_PERFORMANCE_001\` (when present). | OPEN. RC4 G08 NOT_RUN. |
| 10 | #49 | **OPEN** | Product-Final Acceptance | Target `RAWRXD_PRODUCT_FINAL_001`. Fresh clone E2E scenario + Final Receipt keys (see §2). | `evidence/RELEASE_FREEZE_001\` (35C22 Issue#49 engineering / independent review); `evidence/IDE_RELEASE_READINESS_001\rc4_runtime_001\` (**RC4 FAIL/HOLD**). | OPEN. Product-final **not** established on RC4. |

### #50 master status (issue body, not re-certified)

| Layer | #50 table status | Issue |
|------:|------------------|-------|
| 0 | IN PROGRESS — provider isolated PASS; **integration seal pending** | #39 CLOSED |
| 1 | BLOCKED | #40 OPEN |
| 2–10 | PENDING / blocked by predecessors | #41–#49 OPEN |

---

## 2) Issue #49 — 11-step engineering + product-final checklist vs RC4

**Controlling RC4 identity:**  
`EXE=F:\rawrxd\release\RawrXD-readiness-rc4\RawrXD-Win32IDE-Native-Ext.exe`  
`SHA256=78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596`  
Sealed root: `F:\rawrxd\evidence\IDE_RELEASE_READINESS_001\rc4_runtime_001\`  
**Do not inherit** 35C22 / 4DE0 PASS onto RC4.

### 2a) Engineering 11-step ledger (Issue #49 path used on 35C22)

Historical authority (immutable separately): `RELEASE_FREEZE_001\ISSUE49_CERT_READY_INDEX.md` — engineering **11/11** on `35C22…`, independent review CERTIFIED=1, **PROMOTE=0**, MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED.

| Step | Meaning | vs RC4 `78E187…` | Evidence |
|-----:|---------|------------------|----------|
| 01/04/05/06/08 | Baseline session/chat/loop pin | **PARTIAL / FAIL-closed** — live chat Send+Ollama TOKEN_SURVIVED=PASS; AgentSession/tool loop for CU **not** attached (orphan registry) | `COMPUTER_USE_GUI_E2E_RECEIPT.txt`, `DISPATCH_FIRST_FAILURE.txt` |
| 10 REAL_SOURCE_EDIT | Model/agent edits source | **NOT_RUN** (blocked by READ FAIL) | `AGENT_REPAIR_RECEIPT.txt` |
| 11 BUILD_FAILURE_RECOVERY | Fail→diagnose→repair | **NOT_RUN** | same |
| 12 MODEL_DIAGNOSES | Read diagnostics / reason | **FAIL** at required `TOOL read` emission | same; class `MODEL_PROTOCOL_NONCOMPLIANCE__REQUIRED_TOOL_READ_NEVER_EMITTED` |
| 13 SECOND_EDIT | Second durable hash change | **NOT_RUN** | — |
| 14 FINAL_BUILD | Build succeeds | **NOT_RUN** | — |
| 15 FINAL_TESTS | Real test execution | **NOT_RUN** | — |

```text
ISSUE49_ENGINEERING_ON_RC4=NOT_PASS
ISSUE49_11_11_ON_35C22=HISTORICAL_ONLY (no inherit)
```

### 2b) Product-final Final Receipt keys (#49 body) vs RC4

Fail-closed: absent same-SHA proof ⇒ **NOT_RUN**; exercised failure ⇒ **FAIL**.

| Key | vs RC4 | Note |
|-----|--------|------|
| CLEAN_CLONE | NOT_RUN | Not exercised this lane |
| STRICT_BUILD | NOT_RUN | No rebuild of RC4 |
| DEEP2_LAYER0 | NOT_RUN | Not sealed on RC4 SHA |
| DEEP2_INTEGRATION | NOT_RUN | — |
| GPU_RUNTIME | NOT_RUN | G08 NOT_RUN |
| LOCAL_MODEL_LOAD | PASS | Ollama backend live (`bigdaddyg-productivity-local:latest`) |
| GPU_FORWARD | NOT_RUN | — |
| FINITE_LOGITS | NOT_RUN | — |
| GENERATION | PASS | RESPONSE_END bytes=1161; success=1 |
| AGENT_REASONING | FAIL | Chat text path only; structured agent/tool loop not attached for CU |
| TOOL_AUTHORITY | FAIL | CU registry orphaned; repair harness never reaches authority via READ |
| REAL_TOOL_CALL | FAIL | `computer_use.*` tool_calls=0; repair emits write×8 not required read |
| RESULT_REINJECTION | NOT_RUN | Blocked |
| AGENT_CONTINUATION | PARTIAL→fail-closed **FAIL** for product path | Cancel ack after RESPONSE_END only; not post-tool continuation |
| REAL_SOURCE_EDIT | NOT_RUN | source_changed=false |
| BUILD_FAILURE_RECOVERY | NOT_RUN | — |
| FINAL_BUILD | NOT_RUN | — |
| FINAL_TESTS | NOT_RUN | — |
| MULTI_AGENT_REVIEW | NOT_RUN | — |
| IDE_CHAT | PASS | Live Send + response |
| IDE_EDITOR | NOT_RUN | G04 NOT_RUN |
| IDE_TERMINAL | NOT_RUN | G05 NOT_RUN |
| IDE_GIT | NOT_RUN | — |
| STUB_PROVIDERS | NOT_RUN | — |
| STUB_FALLBACKS | NOT_RUN | — |
| SYNTHETIC_RECEIPTS | NOT_RUN | Inventory does not invent PASS |
| UNRESOLVED_EXTERNALS | NOT_RUN | — |
| CI_REPRODUCIBLE | NOT_RUN | — |
| CLEAN_MACHINE_REPRODUCIBLE | NOT_RUN | G13 clean-machine NOT_RUN |
| VERDICT | **FAIL / HOLD** | `G15=NOT_ESTABLISHED`; `PROMOTE=0` |

### 2c) Master-plan 14-row product-final planning checklist vs RC4

(Planning checklist from parent Master IDE Completion Plan — **not** certification by itself.)

| # | Checklist row | vs RC4 |
|--:|---------------|--------|
| 1 | Build and launch native IDE from clean checkout | NOT_RUN (package launch PASS ≠ clean clone) |
| 2 | Select local model and R9700 | PARTIAL — local Ollama used; R9700 selection **NOT_RUN** |
| 3 | Open project + repair request | PARTIAL — agent harness fixture; GUI project repair **NOT_RUN** |
| 4 | Agent reads actual project source | **FAIL** (required TOOL read never emitted) |
| 5 | GPU reasons + real tool call | **FAIL** (no computer_use / no mandated read) |
| 6 | CPU Tool Authority executes | **FAIL** / NOT_REACHED for CU; write gated for repair |
| 7 | Edit + attempt build | **NOT_RUN** |
| 8 | First build fails; diagnostics return | **NOT_RUN** |
| 9 | Diagnose + fix | **NOT_RUN** |
| 10 | Second build + tests pass | **NOT_RUN** |
| 11 | Independent reviewer evaluates patch | **NOT_RUN** |
| 12 | Evidence report + Git commit | **NOT_RUN** |
| 13 | Verify chat/editor/terminal/Git/model state | PARTIAL chat only |
| 14 | Validate receipts/SHA/clean-machine | PARTIAL — identity/package PASS; G15 NOT_ESTABLISHED |

```text
PRODUCT_FINAL_ON_RC4=FAIL_CLOSED_HOLD
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
```

---

## 3) Issue #57 — 45 acceptance gates as obligations

**Source:** `gh issue view 57` — OPEN.  
**Law from issue:** open acceptance gates, **not** 45 accomplished fixes; every checked item needs revision-specific runtime receipt.  
**Inventory rule:** mark local receipt presence only. **None auto-defects.** Historical/unverified ≠ defect.

### A. Native IDE E2E and source/dependency closure (15)

| ID | Obligation (abbrev) | Local receipt? | Example path(s) if any |
|----|---------------------|----------------|------------------------|
| A01 | Resolve GHA runner_id=0; successful Linux+Windows run | **no** matching success receipt found | Issue body cites failed run `#40089650136` |
| A02 | Per-file SHA-256 inventory JSON on audited commit | **yes (related)** | `RAWRXD_SOVEREIGN_LINKER_CERT_001\native_object_inventory.json` / classify scripts; not claimed A02 PASS |
| A03 | CMake literal-source admission; disposition missing paths | **yes (related)** | `RAWRXD_SOVEREIGN_LINKER_CERT_001\`, various audit inventories |
| A04 | Strict no-external-deps scan; Qt/nlohmann quarantine | **partial/related** | docs/plans + audits; no sealed A04 PASS tagged |
| A05 | Frozen feature→TU/call-site manifest | **yes (related)** | `deep2_enterprise_closure_manifest_20261020\`, feature manifests |
| A06 | Rebuild real native Win32 IDE clean checkout no-Qt | **yes (related)** | multiple IDE build receipts / RC4 package identity — **not** clean-clone A06 seal |
| A07 | Rebuild `rawr.exe` + snapshot/agent same checkout | **yes (related)** | agent loop packaging under readiness trees |
| A08 | Launch IDE; save/close/reopen; compare file SHA-256 | **no** RC4-specific A08 | G04 editor NOT_RUN on RC4 |
| A09 | Terminal start/output/exit/cancel/cleanup | **yes (related)** | term-smoke / terminal gates under FULL_FEATURE_*; RC4 G05 **NOT_RUN** |
| A10 | Native PowerShell panel lifecycle | **yes (related)** | PowerShell panel evidence in FULL_FEATURE_*; RC4 G05 **NOT_RUN** |
| A11 | Native LSP JSON-RPC handshake/diagnostics/completion | **partial/related** | LSP mentions in surface audits; no A11 PASS seal cited |
| A12 | GhostText display/accept/cancel + real model adapter | **yes (related)** | `F_GHOSTTEXT_*`, `F_GUI_GHOSTTEXT_*` |
| A13 | Native browser render/network isolation/lifecycle | **no** clear A13 PASS receipt | — |
| A14 | Debugger BP/step/watch/vars/stack on real debuggee | **partial/related** | debugger UI audits / DEBUG receipts; not A14 product seal |
| A15 | IDE-driven agent edit→build→test→snapshot rollback | **yes (related)** | Issue#49 on **35C22…**; RC4 agent repair **FAIL** — related ≠ this-gate PASS |

### B. Slingshot / compiler / linker / cross-platform (15)

| ID | Obligation (abbrev) | Local receipt? | Example path(s) if any |
|----|---------------------|----------------|------------------------|
| B01 | Recover slingshot_braid sources + hashes from legacy | **no** sealed recovery receipt found | Issue cites legacy `RawrXD-IDE-Final` paths |
| B02 | SBraid emitter/read-back roundtrip + corrupt reject | **no** | — |
| B03 | Review SlingshotGuard concurrency/integrity | **no** | — |
| B04 | Replace SlingshotPOC simulated VRAM if promoted | **no** | Issue notes simulated VRAM |
| B05 | Reconcile legacy vs Deep2 residency/loader | **no** | — |
| B06 | Compiler/linker source inventory (MASM/native/ancestry) | **yes (related)** | `RAWRXD_MODEL_GENIE_COMPILER_BUILD_001`, linker cert inventories |
| B07 | Native C frontend compiles portable C | **no** A-gate style PASS | — |
| B08 | Native C++20 frontend (templates/exceptions/ABI) | **no** | — |
| B09 | MASM x86/x64 + COFF vs independent oracle | **partial/related** | MASM tooling present; oracle E2E not sealed as B09 |
| B10 | NASM x86/x64 + object oracle | **no** | Issue notes banner-only NASM script historically |
| B11 | Native linker PE32/PE32+ startup/imports/relocs/exports | **yes (related)** | `RAWRXD_SOVEREIGN_LINKER_CERT_001`, `RAWRXD_SOVEREIGN_PE_RUNTIME_001` |
| B12 | Full compile→link→execute without external compiler | **no** sealed B12 PASS | — |
| B13 | ELF/Linux capability vs host fallback + smoke | **no** | — |
| B14 | Mach-O/macOS/iOS contracts + macOS runner evidence | **no** | — |
| B15 | Android ABI/ELF/APK contracts + device evidence | **no** | — |

### C. GPU correctness / 150 TPS / Top-25 / release (15)

| ID | Obligation (abbrev) | Local receipt? | Example path(s) if any |
|----|---------------------|----------------|------------------------|
| C01 | Deterministic reference model/quant baseline archive | **yes (related)** | parity / oracle trees under `deep2_*parity*`, `PARITY_*` |
| C02 | Corrected `ffn_gate_up` multi-token GPU path | **yes (related)** | FFN/quant recovery evidence dirs |
| C03 | Q4_K/Q5_K/Q6_K/F32 fused host GEMV vs oracles | **yes (related)** | `DEEP2_KIMI_GPU_DOWN_GEMV_001`, `DEEP2_Q2K_PRODUCTION_QGEMV_RECOVERY_006`, fused verify trees |
| C04 | Compare four fused GEMV paths to pre-patch queue/fence | **partial/related** | fused GEMV recovery / draft PR #55 referenced in issue |
| C05 | Lane-state restoration success/error/fallback/dual-GPU | **yes (related)** | `deep2_multigpu_resilience`, dual-GPU forward receipts |
| C06 | R9700 single-GPU TPS 32/128/256 + control | **yes (related)** | `S07_*`, TPS/parity runs — **not** auto C06 PASS |
| C07 | RX7800 XT single-GPU TPS 32/128/256 + control | **yes (related)** | dual/device runs present historically |
| C08 | Dual-GPU full-model TPS; no-fallback counters | **yes (related)** | `DUAL_GPU_FORWARD_*` |
| C09 | Attribute GPU0 fences / GPU1 overlap + PCIe receipts | **partial/related** | timing/fence traces in S07 / GPU trees |
| C10 | GGUF shard/index/quant/arch on supported matrix | **yes (related)** | GGUF lifecycle / taxonomy evidence |
| C11 | Nemotron SSM Q4_K NaN + residual parity | **yes (related)** | `NEMOTRON*`, `RAWRXD_NEMOTRON_*` |
| C12 | Real-model 150+ single-stream decode TPS if attainable | **no** sealed 150+ product PASS claimed here | Issue forbids synthetic kernel TPS |
| C13 | Identical A/B conditions for performance compares | **partial/related** | many AB receipts; gate remains obligation |
| C14 | 25×20=500 cell feature matrix with real evidence | **yes (related)** | `FINISH_25_*` / Finish25 matrices — **≠** prefilled certification |
| C15 | Signed/reproducible packaging + security/crash/offline/cross-platform release | **partial/related** | RC4 portable integrity PASS; full C15 conjunction **NOT_ESTABLISHED** |

```text
I57_OBLIGATIONS=45
I57_AUTO_DEFECTS=0
I57_LOCAL_RECEIPT_PRESENT_RELATED≈A:9 B:3 C:11 (related≠PASS)
```

Companion CSV: `ISSUE57_GATES_OBLIGATIONS.csv`.

---

## 4) Master plan workstreams 01–25 × Wave1 blockers

**Wave1 first blockers (authoritative RC4 failure classes):**

1. `CHAT_SESSION_NOT_TOOL_LOOP__ORPHAN_CU_REGISTRY`  
2. `MODEL_PROTOCOL_NONCOMPLIANCE__REQUIRED_TOOL_READ_NEVER_EMITTED`

| WS | Workstream | Wave1 blocker touch | Crosswalk |
|---:|------------|---------------------|-----------|
| 01 | Release lineage | Indirect | New candidate SHA required after Wave1; do not mutate RC4 |
| 02 | Chat input | Direct (CU path) | Chat Send works; must not remain text-only for agent tools |
| 03 | Chat sessions | Direct | Session ownership must bind tools |
| 04 | AgentSession | **Direct / critical** | Session-owned Registry; attach CU + file tools |
| 05 | Agent loop | **Direct / critical** | Bounded tool-use loop vs Copilot text chat |
| 06 | Tool protocol | **Direct / critical** | Emit/parse/validate required `TOOL read` |
| 07 | File tools | **Direct / critical** | `read` before `write`; workspace files |
| 08 | Computer use | **Direct / critical** | End orphan `s_cuReg`; live dispatcher |
| 09 | Cancellation | Adjacent | Mid-CU cancel NOT_RUN until tools attach |
| 10 | Integrated terminal | Blocked-after | After Wave1 integrated |
| 11 | Build system | Blocked-after | Needs tool-read→edit path |
| 12 | Problems panel | Blocked-after | — |
| 13 | Editor | Blocked-after | — |
| 14 | Multi-panel UI | Blocked-after | — |
| 15 | Ollama | Direct (protocol) | Model must emit required tool form |
| 16 | Deep2Engine | Later wave | Wave3+ |
| 17 | Multi-GPU | Later | Wave3+ |
| 18 | Context system | Later | — |
| 19 | Agent orchestration | Direct after 04–07 | Wave2 |
| 20 | Extension host | Later | Wave4+ |
| 21 | Persistence | Adjacent | G11 PASS on RC4; re-prove on new SHA |
| 22 | Security | Direct for CU approval | Approval path NOT_RUN until dispatch lives |
| 23 | Reliability | After tools live | — |
| 24 | Packaging | After integrated SHA | — |
| 25 | Certification | Final | G15 / Issue #49 product-final / #50 Layer10 |

```text
WAVE1_CRITICAL_WS=04,05,06,07,08,15 (+02,03 session binding)
WAVE1_EXIT=real TOOL read bug.cpp + continuation AND computer_use reachable from live agent Registry on ONE new SHA
```

Companion CSV: `WORKSTREAMS_01_25_WAVE1_CROSSWALK.csv`.

---

## 5) Recommended serial order (after Wave1 integrated tool-read + CU on new SHA)

Assume Wave1 exit already proven on **one new SHA** (RC4 immutable). Then serialize:

1. **Re-pin identity** — record EXE SHA; freeze candidate; no cross-SHA inherit.  
2. **Issue #49 engineering 11-step on that SHA** — chat readback → session → loop → tool dispatch → source mutation → visible completion (Move 2). Hold on any FAIL.  
3. **Autonomous repair workflow (Wave2)** — READ→EDIT→BUILD fail→diagnose→second edit→BUILD→TEST on same SHA (#43 / WS07/11/19).  
4. **CPU Tool Authority + reinjection** — close #42 criteria on same SHA (not standalone bridge credit).  
5. **IDE surface subset needed for product path** — editor/terminal/Problems as required for the repair loop (#45 subset; WS10–14).  
6. **Deep2 / GPU correctness path (Wave3)** — Layers 0–2 integration seals per #39–#41 bodies; finite logits + generation on GPU when claimed.  
7. **Multi-agent / dual-GPU reviewer (Wave3 remainder)** — #44 only after single-agent repair is real.  
8. **Hidden-gap sweep Issue #57** — treat 45 items as obligations; open defects only with repro+owner; do not bulk-fail.  
9. **Reliability / cancel / persistence / security (Wave5)** — WS09/21/22/23 on same SHA.  
10. **Repo convergence + CI + packaging (Wave6)** — #46–#47 / WS01/24.  
11. **Performance qualification (Wave7 / #48)** — only after correctness frozen.  
12. **Product-final #49 Final Receipt + G15 independent acceptance (Wave7 / WS25 / Layer 10)** — one binary · one SHA · clean-machine; **PROMOTE** only if policy conjunction passes (`PROMOTE=0` until then).

```text
NEXT_IMMEDIATE=WAVE1_INTEGRATED_ON_NEW_SHA
  (orphan CU registry fix ∥ required TOOL read protocol)
THEN=ISSUE49_11_STEP_SAME_SHA
PROMOTE=0
TIP_CLIMB=HOLD
MATURITY=82%_UNCHANGED_BY_THIS_INVENTORY
```

---

## Evidence anchors (RC4 sealed — do not mutate)

| Artifact | Path |
|----------|------|
| Lane closed | `IDE_RELEASE_READINESS_001/rc4_runtime_001/RC4_LANE_CLOSED.txt` |
| Disposition | `.../RC4_RUNTIME_DISPOSITION.txt` |
| First failure | `.../DISPATCH_FIRST_FAILURE.txt` |
| CU GUI E2E | `.../COMPUTER_USE_GUI_E2E_RECEIPT.txt` |
| Agent repair | `.../AGENT_REPAIR_RECEIPT.txt` |
| G02–G14 | `.../G02_G14_MATRIX.txt` |
| G15 | `.../G15_INDEPENDENT_RECEIPT.txt` |
| Identity | `.../IDENTITY_RECEIPT.txt` |

---

## Files in this packet

- `CERTIFICATION_LADDER_MAP.md` (this file)
- `ISSUE57_GATES_OBLIGATIONS.csv`
- `WORKSTREAMS_01_25_WAVE1_CROSSWALK.csv`
- `LAYERS_0_10_GITHUB_LOCAL.csv`
