# RawrXD IDE — Full Audit (2026-11-25, Revision v2)

Branch: `fix/ide-default-model-scan` · HEAD: `f50ebd4ccb`
Auditor: Kilo (code agent) · Method: two static deep-dive passes (Win32 shell, agentic core/engine, Deep2, editor intelligence, security/modules, docs-vs-reality) + **first-hand build & runtime probes**.
Source of truth: this file + `evidence/gate_ledger.json`, reconciled to HEAD and live receipts.

> **Revision v2 (2026-11-25):** First-hand verification **refuted four inherited claims** from the 2026-11-24 audit that v1 of this report had repeated. The current tree is materially more hardened than that snapshot. Corrections are itemized in §0. Severities in §5 are updated accordingly.

---

## 0. Corrections vs the 2026-11-24 audit (verified at HEAD f50ebd4ccb)

| Prior claim | Verdict now | First-hand evidence |
|-------------|-------------|---------------------|
| MLA-H08 embedding row-stride divergence (CRITICAL) | **REFUTED** | `runtime_graph_executor.cpp:5216-5240` computes `row_stride=emb.bytes/max(vocab,1)`, `src=data+token*row_stride`, with `token>=vocab` and `row outside tensor` guards. The `MLA-H08` comment (5241) is diagnostic dump code, not a bug. |
| Agentic `TOOL bash` runs raw `_popen` with no approval/sandbox (CRITICAL) | **REFUTED (downgraded to MED)** | `deep2_agentic_loop.cpp:6122-6153`: gated by `CommandEscapesWorkspace` (6124) + blocklist (6131-6140) + `AuthorizeExecute`/`AuthorizeTool` (6006-6018); executed job-isolated via `RunCmd→RunProcess→JobIsolation::RunIsolated` (`process_runner.cpp:18-20`, `tool_security.hpp:198-209`). Residual: weak substring blocklist. |
| Shipped menu probe globally auto-approves (HIGH) | **REFUTED for live tree** | Live `Win32IDE_lifecycle.cpp` has no consent override; `SetAutoApproveConfirm(true)` exists only in frozen `cert-6711ff6f2f/…:1789-1790`. |
| Agent panel is a stub / `initAgentPanel` undefined (HIGH) | **REFUTED** | `Win32IDE_AgentPanel.cpp:27-42` is a real implementation (transcript + input + Send → shared chat backend); in build (`CMakeLists.txt:3848`). |
| Ghost-text model feed unwired (HIGH) | **REFUTED (path corrected)** | `NativeGhostTextController` is wired end-to-end to real Ollama/GGUF/cloud (`Win32IDE_GhostTextIntegration.cpp:47,244,296`; pumped in `Win32IDE_lifecycle.cpp:1022`). Only the *orphaned* `InlineCompletionEngine` is unwired. |

These corrections are the single most important output of v2: **the product is real and substantially safer than the prior audit stated.**

---

## 1. Executive verdict (v2)

RawrXD is a **real, substantial, launchable native Win32 IDE**. First-hand this session:
- **GUI startup OK** — `RawrXD-Win32IDE-Native.exe` (built today 04:11) stayed **alive after 8s** (no startup crash), then killed.
- **Terminal smoke PASS** — `--term-smoke --term-quit` receipt `START/CONPTY/ALIVE_ECHO = PASS`.
- **Build is fresh and real** — `_win32_build.log` (765 KB) written 04:11 today; product exe 4.79 MB.

It is **not yet production-certified**, but the blockers are **fewer and lower-severity** than v1 reported. The remaining gaps are performance/coverage (Deep2 quant + throughput), integration completeness (full session restore, AI completion popup, DAP), and build/hygiene integrity — not a fake core or an un-gated agent.

Certification posture unchanged: `CERTIFIED=0`, `PROMOTE=0`, `RELEASE=HELD` (G15/G16 BLOCKED, G17–G20 OPEN per `evidence/gate_ledger.json`).

---

## 2. First-hand build & runtime evidence (this session)

| Probe | Result |
|-------|--------|
| Product binary | `build/bin/Release/RawrXD-Win32IDE-Native.exe`, 4.79 MB, built 2026-11-25 04:11 |
| Build log | `_win32_build.log` 765 KB, 2026-11-25 04:11 (native MSVC build) |
| **GUI launch** | **ALIVE after 8s → startup OK**, no early exit/crash (then killed) |
| Terminal smoke | **PASS** (`evidence/FULL_FEATURE_ONESHOT_001/artifacts/term_smoke_receipt.txt`, fresh) |
| Runtime logs | `logs/RawrXD_IDE_20261125_041846.log`, `.rawrxd/ide.log` produced by the launch |
| Chat E2E | **unverified** (prior `--chat-smoke` hung 300s); not re-run this pass |
| Toolchain | CMake + Ninja + llvm-mingw gcc on PATH; `cl`/`ml64` not on PATH (MSVC build needs vcvars) |

---

## 3. Real vs stubbed subsystems (v2, verified)

| Subsystem | Status | Key evidence |
|-----------|--------|--------------|
| Win32 shell / command routing / message loop | **Real** | `main_win32.cpp`; `Win32IDE_lifecycle.cpp`; `Win32IDE_Commands.cpp:217-343` |
| Rendering (TransparentRenderer, D3D11+D2D) | **Real** | `TransparentRenderer.cpp` (D3D11CreateDevice, WARP fallback, D2D, embedded HLSL) |
| LSP client (JSON-RPC over pipes) | **Real** | `Win32IDE_LSPClient.cpp:734-820`; **crash risk** `std::stoi` at 774 (unguarded) |
| Debugger / native backend (DR0-7, StackWalk64) | **Real** | `Win32NativeDebugBackend.cpp` |
| Terminal (ConPTY) | **Real** | live smoke PASS |
| Agent panel | **Real (implemented)** | `Win32IDE_AgentPanel.cpp:27-42` |
| Ghost text inline completion | **Real, wired to model** | `Win32IDE_GhostText*.cpp`; Ollama/GGUF/cloud |
| Agentic loop (native) | **Real, gated + job-isolated** | `deep2_agentic_loop.cpp:6122-6153`; `tool_security.hpp` |
| Agentic bridge (BackendRouter/ToolCallBridge/FSM) | **Real, fail-closed** | `Win32IDE_AgenticBridge.cpp:101-199` |
| CPU inference (native, linked into product) | **Real** | `cpu_inference_engine_impl.cpp:534-949`; `CMakeLists.txt:4071` |
| GGUF loaders | **Real** | `gguf_loader.cpp`, `streaming_gguf_loader.cpp` |
| Deep2 Vulkan/CPU engine | **Real, coverage/perf gated** | see §4 |
| Session persistence (full) | **Orphaned** | `Win32IDE_Session.cpp` not in link set; reduced `saveIdeSession` in `Win32IDE_FileOps.cpp` |
| Code-completion popup | **Keyword-only (no AI)** | `requestHybridCompletion` returns static list (`Win32IDE_CompletionHelpers.cpp:14-35`) |
| `RealTimeCompletionEngine` | Discards model output; **Qt/benchmark only** | `real_time_completion_engine.cpp:45-47,345-356` |
| DAP layer | **Dead** | `DapService.hpp/.cpp` nonexistent; `Win32IDE_DAPServer` compiled, never instantiated |
| Plan executor | **Orphaned, wrong contents** | `Win32IDE_PlanExecutor.cpp` (prompt templates; header missing) |
| PowerShell panel | **Core real, accessors stubbed** | `Win32IDE_PowerShell.cpp:74-136` real; 233/641 return cached/empty |
| Security: audit_log/sast/dast/secrets/sbom | **Real** | `audit_log.cpp` SHA-256 hash-chain; scanners real |
| Security: auth_manager/permissions/secure_store/tls | **Absent** | files do not exist |
| Enterprise (license/mfa/siem/residency) | **Absent** | `src/enterprise/` does not exist |
| HTTP server (`api_server.cpp`) | **Scaffold; `/api/tool` inert (safe)** | `InitializeHttpServer` no socket (446-459); 481-487 disabled |
| Rate limiting | **Absent (doc-only)** | no `rate_limiter` implementation |
| Qt app (`qtapp/`, random logits) | **Orphaned, NOT linked** | excluded from native build (CMakeLists:347-348,543-545) |
| RE / codec / asm / vscode API | **Real** | `binary_loaders.cpp`, `compression.cpp`, 5 `.asm`, 2989-line API layer |
| QuickJS extension host | **Stub (native-only)** | `quickjs_extension_host.cpp:67-129` |

---

## 4. Deep2 engine (verified this pass)

- **Embedding lookup correct** (MLA-H08 refuted, §0).
- **Quant GPU coverage:** real GPU dot kernels for Q4_0/Q4_1/Q5_0/Q5_1/Q8_0/Q2_K/Q3_K/Q4_K/Q5_K/Q6_K/IQ4_NL (+NVFP4 shader). **Gaps:** Q8_K has **no** GPU weight-dot kernel (CPU fallback, `runtime_graph_executor.cpp:1670-1713`); Q4_1/Q5_1 lack a runtime dispatch kind; **Q6_K GPU unverified** — forced to FP32 (`QuantKernelRegistry.cpp:866-883`) despite `gpuPackedType` advertising it (`Deep2Engine_GpuForward.cpp:80`).
- **Batching/prefill exist** (v1 "no batching" refuted): `can_batch_` default-on (`:5035`), `PrefillBatch` (`:4148`); tiled4x opt-in.
- **Non-functional placeholders:** `gpu/Deep2GPUBackend.cpp:276-309` (`InitializeVulkan` returns false, hard-coded devices); GPU MoE router stub (`vulkan_compute.cpp:4475` `return false; // TODO`); multishard embedding dequant gap (`Deep2Engine.cpp:5989`); SSM scan unimplemented (`universal_gguf.cpp:1489`).
- **10/23 archs fail single forward = DOC-ONLY** (`evidence/DEEP2_NATIVE_FORWARD_MATRIX_23MODELS.md:39`); no automated test; the 23-model run was CPU-only. One zeroed forward (`argmax=0,max_logit=0`) is uncaught by any gate.
- **Memory/ownership real:** ResidencyManager (707 ln), device-lost guards (`GpuDeviceLostReset_Vk.cpp`, `vulkan_compute.cpp:4278,1498`); paged KV only in QSA path (main executor KV is flat).
- **Throughput ~4.5 TPS vs 150 gate** remains the headline perf gap (G15 BLOCKED).

---

## 5. Consolidated defect register (v2, severity-corrected)

| # | Sev | Defect | Evidence |
|---|-----|--------|----------|
| 1 | HIGH | Build integrity: 183 `EXISTS()` guards + `if(FALSE)` blocks can silently drop targets; tests OFF by default | root `CMakeLists.txt` passim |
| 2 | HIGH | Throughput ~4.5 TPS vs 150 gate (G15 BLOCKED); stale 245 TPS JSON is void | `evidence/gate_ledger.json`; `evidence/PERFORMANCE_CERTIFICATION.json` |
| 3 | HIGH | Q6_K GPU unverified (FP32 forced) + Q8_K no GPU kernel → perf cliff / capability mismatch | `QuantKernelRegistry.cpp:866-883`; `runtime_graph_executor.cpp:1670-1713` |
| 4 | HIGH | 10/23 archs fail single forward — DOC-ONLY, no regression test; zeroed forward uncaught | `DEEP2_NATIVE_FORWARD_MATRIX_23MODELS.md:39` |
| 5 | HIGH | Full session save/restore orphaned (tabs, cursor, theme, model reload, window geom) | `Win32IDE_Session.cpp` not in link set |
| 6 | HIGH | LSP reader `std::stoi` on malformed Content-Length can `std::terminate` — **PATCHED + BUILT + E2E PASS (10/10)** | `Win32IDE_LSPClient.cpp:774` → `lsp_content_length.h` (strict, shared w/ test) |
| 7 | HIGH | Split-brain build: two CMake source lists (`~dev` vs root) → "works in dev, missing in package" | root `3841-4075` vs `~dev/rawrxd/CMakeLists.txt:5503+` |
| 8 | MED | Weak, bypassable shell blocklist on model `bash` (misses `;`,`|`,`>`,`%VAR%`, single `&`) — mitigated by job isolation + workspace guard | `deep2_agentic_loop.cpp:6131-6140` |
| 9 | MED | GPU MoE router stub; `gpu/Deep2GPUBackend` placeholder; multishard/SSM gaps block some GPU forwards | `vulkan_compute.cpp:4475`; `Deep2GPUBackend.cpp:276-309` |
| 10 | MED | AI code-completion popup is keyword-only (no LSP/AI); `RealTimeCompletionEngine` discards output (Qt/benchmark only) | `Win32IDE_CompletionHelpers.cpp:14-35`; `real_time_completion_engine.cpp:45-47` |
| 11 | MED | DAP layer dead (`DapService` nonexistent; `Win32IDE_DAPServer` never instantiated); PlanExecutor orphaned/wrong | `CMakeLists.txt:4017`; `Win32IDE_DAPServer.cpp` |
| 12 | MED | IDE ctor unguarded (open); double `SetUnhandledExceptionFilter` + always-false witness guard — **crash-filter consolidation PATCHED + BUILT + E2E PASS (AV/div0)** | `main_win32.cpp:306-338` (single filter chains witness→minidump) |
| 13 | MED | Hardcoded `F:\rawrxd` / `C:\RawrXD_IDE.log` paths incl. `SetCurrentDirectoryA` | `main_win32.cpp:17-39,81,132,309` |
| 14 | MED | HTTP server is a scaffold (no socket); no rate limiting; enterprise layer absent | `api_server.cpp:446-518` |
| 15 | MED | Audit log: hardcoded timestamp; `Verify` treats missing file as valid | `audit_log.cpp:154,175` |
| 16 | LOW | Dead Qt lineage with random-logit path (not linked); duplicate `CPUInferenceEngine` | `qtapp/transformer_inference.cpp:441-455` |
| 17 | LOW | Stale contradictory "CERTIFIED/SHIPPED" docs with placeholder hash | `CERTIFICATION_COMPLETE.md` etc. |
| 18 | LOW | Repo hygiene: ~6000 root entries, ~715 `.f32`+`.bin` dumps, duplicate snapshot trees | root listing |

**Removed from v1 (refuted, §0):** un-gated `_popen` (was #1), random-logits-in-product (was #2), MLA-H08 (was #3), menu auto-approve (was #4), agent-panel stub (was #12).

### 5b. Source-level implementation progress (PATCHED ≠ BUILT ≠ TESTED ≠ CERTIFIED)

| Task | Source | Build | E2E test | Cert |
|------|--------|-------|----------|------|
| LSP strict Content-Length parse (#6) | **PATCHED** | **BUILT** | **E2E PASS** (10/10, `lsp_content_length_test`) | 0 |
| Crash-filter consolidation (#12) | **PATCHED** | **BUILT** | **E2E PASS** (AV `0xC0000005` + div0 `0xC0000094` → witness+dump+terminate; abort `0xC0000409` fail-fast bypass) | 0 |

Build: `cmake --build build --config Release --target RawrXD-Win32IDE-Native` → `build/bin/Release/RawrXD-Win32IDE-Native.exe` (0 errors). Regression: `--term-smoke` exit 0 PASS.
E2E harnesses: `--crash-inject=<av|div0|abort>` (in `main_win32.cpp`) + `lsp_content_length_test.cpp` (shared `lsp_content_length.h`, real parser). LSP 10/10 PASS; crash AV+div0 produce `IDE_CRASH.log` witness + 5.45 MB minidump + `exception_stack.txt`.
Backlog: `TOTAL=58 · SOURCE_PATCHED=2 · BUILD_VERIFIED=2 · E2E_CLOSED=2 · CERTIFIED=0`. Next: remaining P0 (chat heap corruption, terminal receipt handoff, 5/5+50/50 chat, 150 TPS, 23/23) — these need models + Vulkan hardware + measurement.

**Work Packages 3–10** (specs/inventories/acceptance tests, **not closures**) are in `WORKPACKAGES_2026-11-25.md`:
LSP regression matrix (P3), crash fault-injection (P4), completion routing trace (P5), build-guard classification
(179 EXISTS/11 if(FALSE); Deep2 silent-omit is the top risk) (P6), session integration spec + duplicate-symbol
blockers (P7), doc↔ledger reconciliation (CERTIFICATION_COMPLETE / 00-FINAL-* = VOID) (P8), GPU quant matrix
(Q8_K/Q4_1/Q5_1/IQ4_NL CPU-only, Q6_K FP32, MoE stub) (P9), MSVC handoff commands (P10).

---

## 6. Documentation vs reality

- ≥100 `*COMPLETE*.md` (glob-capped), ~529 md files / ~177k lines — documentation exceeds real source (~191k lines).
- "100%/SHIPPED/FULLY CERTIFIED" docs are older, mutually contradictory, self-refuting, and **superseded by this v2 + `gate_ledger.json`**.
- No single source of truth historically; this file + `evidence/gate_ledger.json` is now the reconciled pair.
- The honest docs (2026-11-24 E2E, `BRUTAL_TRUTH_REPORT.md`, `gate_ledger.json`) are directionally right but, per §0, **overstated several defects** that v2 refutes.

---

## 7. Repository hygiene

~6,000 root entries; ~715 `.f32` + ~30 `.bin` tensor dumps; 300+ build scripts; hundreds of `.dir/.obj/.vcxproj` intermediates; 152 `src/tool_*.exe`; duplicate snapshot trees (`cert-6711ff6f2f/`, `~dev/`, `candidate_*`, `evidence/`, `package*/`). The `cert-6711ff6f2f/` snapshot still contains the dangerous auto-approve probe — a regression risk if ever re-merged.

---

## 8. Certification posture

No gate promoted. `evidence/gate_ledger.json` (baseline `4213f56908`): G01–G05 PASS, G06/G08/G10 PARTIAL, G07 BLOCKED, G09/G11–G14 OPEN, **G15 BLOCKED (~4.5 TPS)**, **G16 BLOCKED (Qt ABI)**, G17–G20 OPEN. `PROMOTE=0`, `TIP_CLIMB=HOLD`, `RELEASE=HELD`. The July "all_passed" performance JSON is void.

---

## 9. Prioritized recommendations (v2)

1. **Make the build honest (HIGH):** fail-fast on missing product sources; default `RAWRXD_BUILD_TESTS=ON`; delete `if(FALSE)` blocks; reconcile the two CMake lists (ship `Session.cpp` or delete it).
2. **Close the perf/coverage gap (HIGH):** certify Q6_K GPU (resolve L2~1e32) or keep FP32 but stop advertising GPU; add a Q8_K GPU dot kernel; implement the GPU MoE router; add an automated 23-model forward regression test.
3. **Fix crash surfaces (HIGH):** guard the ctor; single exception filter; wrap LSP `std::stoi` (774).
4. **Finish integration (MED):** wire AI completion (LSP/AI) into the popup or remove the keyword-only stub; decide on DAP (implement `DapService` or delete `Win32IDE_DAPServer`); fix or delete `Win32IDE_PlanExecutor.cpp`.
5. **Harden the agent (MED):** expand the shell blocklist to `;`,`|`,`>`,`<`,`%VAR%`, single `&` (or use a real parser/allowlist); keep job isolation + workspace pinning.
6. **Security/enterprise (MED):** implement or remove the scaffold HTTP server; add rate limiting; fix audit-log timestamp + missing-file handling; add the absent enterprise layer or drop the claim.
7. **Hygiene (LOW/MED):** untrack build artifacts/`.f32`/`.bin`; delete duplicate snapshot trees (esp. `cert-6711ff6f2f/`); collapse `*COMPLETE.md` into this file + ledger.
8. **Independent certification** only after 1–3 close and live E2E (chat) + perf receipts exist.

---
*Evidence base: two static deep-dive passes + first-hand probes (GUI launch ALIVE 8s, terminal smoke PASS, `_win32_build.log` 04:11) at HEAD f50ebd4ccb. All file:line refs verified against the working tree. v2 refutes four v1/prior-audit claims (§0).*