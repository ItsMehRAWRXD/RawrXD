# RawrXD IDE — End-to-End Audit (2026-11-24)

Branch: `fix/ide-default-model-scan` · HEAD: `5911a28b1c` · Working tree: 28 M / 847 D / 655 ?? (617k deletions = untracked build/tmp artifacts)
Method: 5 parallel deep static audits (Win32 shell, editor intelligence, Deep2 engine, agentic subsystem, build/tests) + live runtime probes on the 2026-11-23 Ninja/Release build.

---

## 1. Executive verdict

The RawrXD IDE is a **real, substantial native product** — a RichEdit-based Win32 shell with a genuine ConPTY terminal, a real Win32 debug engine, real LSP clients, a QuickJS extension host with a fail-closed sandbox, and a genuine Vulkan/CPU inference engine (Deep2) that executes real tokens on GPU. It is **not** a demo.

However, end-to-end it is **not shippable today**:

- **Correctness**: the flagship MLA (DeepSeek) path has an open P0 divergence (MLA-H08, embedding lookup selects the wrong Q4_K row). 10 of 23 model architectures fail even a single forward pass. No full-model parity for any MoE/GDN arch.
- **Performance**: best measured end-to-end throughput ~4.5 tok/s vs the project's own 150 tok/s gate (G15 BLOCKED) — 1–2 orders of magnitude short.
- **Agentic safety**: the only real plan→act→observe loop (`deep2_agentic_loop.exe`) executes model-authored shell commands with **no approval, no sandbox, no content filter**. A shipped IDE menu probe globally disables consent.
- **Product coherence**: the advertised agent panel does not exist (`initAgentPanel` undefined); MCP, swarm, skill system are documentation shells; ~7.7k lines of win32app production code and the entire Qt shell are orphaned; two stale `RawrXD_IDE.exe` lineages are not reproducible from the tree.
- **Build integrity**: 183 `EXISTS()` guards + 11 `if(FALSE)` blocks mean a green build can silently omit the IDE/engine/tests. CTest is off by default; `tests/` is orphaned. One real green native-IDE build exists (2026-11-23, `build/cmake-preset-ninja-release/bin`, 45 exes).
- **Runtime (this audit)**: terminal smoke **PASS** (exit 0, <60s). Chat smoke (send→tokens→cancel→2nd request) **DID NOT COMPLETE in 300s** — no receipt; chat E2E remains unverified.

Certification ledger claims (`R27=LIVE_E2E_PASS`, `PROMOTE=0`, `TIP_CLIMB=HOLD`) are consistent with the evidence: nothing in this audit promotes any gate.

---

## 2. What the product actually is

| Artifact | Status |
|---|---|
| `RawrXD-Win32IDE-Native.exe` (src/win32app, ~142 TUs, target at CMakeLists.txt:3673) | **The product.** Fresh build 2026-11-23 05:56, 4.37 MB, `build/cmake-preset-ninja-release/bin` |
| `ide/RawrXD_IDE.exe` (602 KB), `src/ide/RawrXD_IDE*.exe` | Stale artifacts of earlier lineages; `RawrXD_IDE_Win32.cpp` missing; not reproducible; **not the IDE** |
| `src/qtapp` (229 entries), `src/gui`, `src/ui` | Orphaned; targets inside `if(FALSE)`; no CMakeLists for qtapp |
| `deep2_agentic_loop.exe`, `deep2_openai_server.exe`, `rawrxd_deep2_engine.exe` | Built 2026-11-23; real binaries |

Entry point: `WinMain` — `src/win32app/main_win32.cpp:288`. Smoke flags: `--term-smoke`, `--chat-smoke`, `--ext-*`.

---

## 3. Subsystem findings

### 3.1 Win32 IDE shell — REAL (fixed layout, no docking engine)
- Window/editor/aux panels: RichEdit 50W editor with syntax highlighting (6 languages), multi-cursor, minimap, find/replace, ghost text, snippets (`Win32IDE_SyntaxHighlight.cpp`, `_MultiCursor.cpp`).
- Terminal: real ConPTY + pipe fallback (`Win32TerminalManager.cpp:64,208,298`).
- Debugger: real `Win32NativeDebugBackend` (DEBUG_ONLY_THIS_PROCESS, int3 BPs, trap-flag step, StackWalk64) wired to UI (`Win32IDE_Debugger.cpp:314-399`).
- Dead: `Win32IDE_DAPServer.cpp` (fully implemented, never instantiated); `Win32IDE_Core.cpp` (6001 lines, orphan, duplicate lifecycle symbols); `Win32IDE_ChatWindow.cpp` unreachable; `DialogBoxWithInput` always returns cancel.
- Top risks: malformed LSP `Content-Length` → `std::stoi` in reader thread can `std::terminate` (`Win32IDE_LSPClient.cpp:771`); no try/catch around IDE construction (`main_win32.cpp:321`); double `SetUnhandledExceptionFilter` kills the first crash filter (`main_win32.cpp:290-291`); hardcoded `F:\rawrxd` / `C:\RawrXD_IDE.log` paths incl. `SetCurrentDirectoryA`.

### 3.2 Editor intelligence — REAL core, partial AI
- LSP client real (clangd/pyright/tsserver, JSON-RPC, semantic tokens); embedded MASM LSP server real. `AdvancedLSPClient` is a **mock** (hardcoded symbols).
- Completion pipeline **drops model output**: `real_time_completion_engine.cpp:45-47` overwrites with empty `postProcessCompletions`; Win32 ghost text `onModelResponse()` has **no caller**.
- Debugger/terminal/GitHub REST/QuickJS extension host + sandbox: real. DAP layer references nonexistent `DapService` (unbuildable orphans).
- Git: shell-out only (`_popen`), no libgit2; `git_client.cpp` builds a PS command it never runs.
- 3 overlapping extension-host implementations (minimal registry / QuickJS / external worker exe).

### 3.3 Deep2 engine — REAL, correctness & perf gated
- Load: GGUF (mmap/IOCP/sharded/Ollama-blob) → ModelSpec/ArchKind → tensor registry → residency (512 MB default) → fail-closed binding.
- Compute: Vulkan (`deep2_qgemv.comp` single-pipeline + batch/tiled prefill, MLA, GDN, MoE shaders; GPU op counters prove real device execution) and CPU (19 GEMV + 19 dequant kernels, AVX512/AVX2).
- Quant GPU gate (vulkan_compute.cpp:4297): Q4_0, Q8_0, Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, IQ4_NL, NVFP4, F16. **No GPU path: Q4_1, Q5_0/Q5_1, Q8_K.** Q6_K quantized GPU dot unverified (FP32 forced after L2~1e32 explosion).
- Model coverage (23-model sweep): **13/23 one-forward OK**; FAIL: qwen35/qwen35moe/qwen3next (4), phi3, deepseek3/4, gptoss (2), laguna; PARTIAL: nemotron_h (parity FAIL).
- **P0 OPEN — MLA-H08**: embedding lookup row-stride bug (`runtime_graph_executor.cpp:5225-5240`, twin `:4383-4412`; dequantizer ignores `dims[1]`), cos≈0.002 divergence; `MLA_H08=PAUSED`, `PROMOTE=0|CERTIFIED=0|RELEASE=HELD` (`evidence/SPRINT9_STAGEA_20261122/INTEGRATION_RECEIPT.md:73-74`). Diagnostic dumps still in tree.
- Q2_K GPU block-layout **fixed at HEAD** (single-token verified, "Paris"; multi-token parity explicitly open).
- Memory/ownership: paged KV with transactional `advanceBy`, host-RAM governor fail-closed, `DownloadBufIsolated` + `ReapSubmissionCompletion` (Retain/Reclaim/TerminalTeardown), device-lost guards wired but never observed firing.
- Perf (measured): Llama-3.1-8B Q4_K_M GPU: prefill 13.8 / decode 7.1 / **E2E 4.51 TPS**; DeepSeek-Coder-V2-16B MoE: 0.66 tok/s decode, TTFT 75s; TinyLlama CPU ~1.1–1.3 tok/s. Gate G15_150tps **BLOCKED**. `evidence/PERFORMANCE_CERTIFICATION.json` (245 tok/s, all_passed, July) is **stale and contradicted** — do not cite.
- ~26 `.comp` shaders have no `.spv`/build rule (source-only).

### 3.4 Agentic subsystem — one real loop, unsafe; rest shells
- Real loop: `tools/deep2_agentic_loop.cpp:5056` (budget gates, cancellation, fail-closed parse, write verify/rollback, independent host verification). **`TOOL bash` → `_popen` with no approval/sandbox/filter (`:5731-5735`, `:548-562`)** — CRITICAL.
- IDE "loop" (`Win32IDE_AgenticBridge.cpp:464-481`) repeats the same prompt N times — not ReAct. Agent panel host is a stub (`initAgentPanel` undefined; `docs/TOP50_READINESS_PASSTHRU.md:27`).
- Shipped menu probe (id 9618) calls `SetInteractive(false)` + `SetAutoApproveConfirm(true)` — global consent bypass (`Win32IDE_lifecycle.cpp:1781-1790`).
- `AgentOrchestrator.cpp` ReAct loop is real but unreachable (HexMag not built); its approval lambda returns `true` unconditionally.
- MCP: **non-functional** (missing header/impl, inert `/api/tool` at `src/api_server.cpp:481-487`, orphaned PS bridge). Swarm/skill_system/agent_puppeteer: docs/config only. Truth gates 002/003: honest, but prove model plumbing only (TG3 token generation pending). No sealed certification of the agentic loop exists.
- IDE tool path (ToolCallBridge + Registry + MOTD auth + exactly-once + ExtensionSandboxManager) is genuinely well-designed and fail-closed — undermined by the un-gated loop/CLI paths and substring-blacklist command filter (trivially bypassed).

### 3.5 Build & tests — mixed
- One real green native-IDE build (MSBuild `__buildnative.txt`, 0 errors/79 warnings; Ninja tree 2026-11-23 with 45 exes). Most "latest" failure logs are from a foreign `D:\rawrxd` checkout.
- 81 `add_test`, but `RAWRXD_BUILD_TESTS` defaults OFF, `tests/CMakeLists.txt` orphaned, `src/test*` unreferenced.
- Hard requirements: VS2022 x64, Python3 (REQUIRED), ml64 (FATAL_ERROR), Vulkan SDK (or `-DENABLE_VULKAN=OFF`); Win32 CI leg contradicts x64-only FATAL_ERROR.
- Hygiene: ~6000 root entries; ~715 `.f32` + ~30 `.bin` dumps; hundreds of `.dir/` intermediates; tracked `build-*`/`node_modules` being deleted in the current 847-D working tree; duplicate `cert-6711ff6f2f/` snapshot tree.

---

## 4. Live runtime evidence (this audit, 2026-11-24)

| Probe | Result |
|---|---|
| `RawrXD-Win32IDE-Native.exe --term-smoke --term-quit` (2026-11-23 build) | **PASS**, exit 0, <60s |
| `--chat-smoke` (Ollama live, 16 GB Inkling Q4_0-Q8_0 + 8 local GGUFs) | **INCOMPLETE** — killed at 300s, no receipt. Chat E2E unverified; possible model-load stall or hang in chat path |
| Ollama API :11434 | reachable, models listed |
| Models | 8+ local GGUFs incl. nemotron 30B, deepseek-r1 32B, starcoder2 15B |

---

## 5. Consolidated defect register (severity-ranked)

| # | Sev | Defect | Evidence |
|---|---|---|---|
| 1 | CRITICAL | Model-authored shell executed with no approval/sandbox in real agentic loop | tools/deep2_agentic_loop.cpp:5731-5735, 548-562 |
| 2 | CRITICAL | MLA-H08 embedding row-stride divergence OPEN; DeepSeek/MLA incorrect | runtime_graph_executor.cpp:5225-5240; SPRINT9 receipt:73-74 |
| 3 | HIGH | Menu probe globally auto-approves commands + resets workspace to F:\rawrxd | Win32IDE_lifecycle.cpp:1781-1790 |
| 4 | HIGH | Agent panel stub (`initAgentPanel` undefined) while UI implies agent surface | Win32IDE_Core.cpp:4477; TOP50_READINESS_PASSTHRU.md:27 |
| 5 | HIGH | Throughput 4.5 TPS vs 150 TPS gate; G15 BLOCKED | gate_ledger.json:19; DEEP2_NATIVE_GPU_TOKENS_LLAMA31_8B_001 |
| 6 | HIGH | 10/23 archs fail single forward; no full-model parity for MoE/GDN | DEEP2_NATIVE_FORWARD_MATRIX_23MODELS.md |
| 7 | HIGH | LSP reader thread `std::stoi` can terminate process | Win32IDE_LSPClient.cpp:771 |
| 8 | HIGH | IDE ctor unguarded; double exception filter installs dead crash filter | main_win32.cpp:290-291,321 |
| 9 | HIGH | Completion pipeline discards model output; ghost text model feed unwired | real_time_completion_engine.cpp:45-47; Win32IDE_InlineCompletion.cpp:48 |
| 10 | HIGH | Build integrity: 183 EXISTS guards + if(FALSE) blocks silently drop targets; tests off by default | CMakeLists.txt passim |
| 11 | MED | Q6_K GPU dot unverified (FP32 forced); Q8_K/Q4_1/Q5_0/Q5_1 no GPU path | QuantKernelRegistry.cpp:866-880; vulkan_compute.cpp:4297 |
| 12 | MED | Device-lost guards never demonstrated firing; mid-token abort not implemented | evidence/DEVICE_LOSS_OWNERSHIP.md:60-66 |
| 13 | MED | MCP advertised, non-functional; /api/tool inert | src/mcp/MCP_Test.cpp:6; api_server.cpp:481-487 |
| 14 | MED | Swarm certification covers unbuildable code; __cert_*.txt unsealed | certification/RAWRXD_AGENT_RELIABILITY_001.md:143-155 |
| 15 | MED | Sandbox command filter is bypass-prone substring blacklist; path policy lexical only | ExtensionSandboxManager.cpp:121-180 |
| 16 | MED | Orphaned DAP layer references nonexistent DapService (unbuildable) | Win32IDE_DebuggerIntegration.cpp:72+ |
| 17 | MED | Hardcoded F:\rawrxd / C:\ paths incl. SetCurrentDirectoryA in shipped code | main_win32.cpp:17-39,309; Win32IDE_FileOps.cpp:49 |
| 18 | MED | Repo hygiene: 6000 root entries, tracked build/node_modules churn, duplicate snapshot tree | root listing; git status |
| 19 | LOW | Stale PERFORMANCE_CERTIFICATION.json (245 TPS) contradicts Nov receipts | evidence/PERFORMANCE_CERTIFICATION.json |
| 20 | LOW | Tool schemas lack parameter properties; GetAllToolSchemas empty | ToolCallBridge.h:53-63 |

---

## 6. Certification posture

No gate was promoted by this audit. Consistent with ledger: MLA-H08 PAUSED, Q2_K single-token fixed/multi-token open, G15 BLOCKED, agentic loop uncertified, `PROMOTE=0`, `TIP_CLIMB=HOLD`. The stale July "all_passed" JSON must be treated as void.

## 7. Prioritized recommendations

1. **Contain the agentic blast radius**: gate `TOOL bash` behind the existing ToolCallBridge approval + sandbox; remove/segfault-guard the menu probe auto-approve; fix or delete `AgentOrchestrator`'s `return true` approval.
2. **Close MLA-H08**: fix row-stride/dequantizer to honor `dims[1]`; add a committed cos-parity receipt; remove diagnostic hooks after closure.
3. **Make the build honest**: convert EXISTS guards to fail-fast for product targets; default `RAWRXD_BUILD_TESTS=ON` for the IDE preset; delete `if(FALSE)` blocks or move to `legacy/`.
4. **Fix crash surfaces**: try/catch around ctor; single exception filter; LSP header parse hardening.
5. **Wire or remove**: agent panel, ghost-text model feed, completion post-process, DAP layer, Qt shell, stale RawrXD_IDE binaries.
6. **Performance program**: profile the 4.5 TPS path (batched prefill + GPU dot coverage for Q8_K/Q6_K) before any 150 TPS claim.
7. **Hygiene**: untrack build artifacts/node_modules, delete `.f32`/`.bin` dumps and duplicate snapshot trees, add root-level README map of the real product path.

---
*Evidence base: 5 subsystem audit reports (win32app/editor/deep2/agentic/build) + live probes listed in §4. All file:line references verified against working tree at HEAD 5911a28b1c.*