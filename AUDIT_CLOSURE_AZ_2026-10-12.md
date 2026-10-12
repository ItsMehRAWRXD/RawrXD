# RawrXD / Deep2 — A–Z Closure Audit (2026-10-12)

Product definition (per owner): a complete **native autonomous software-engineering platform**.
Differentiator = the four pillars in ONE product, not separately:
P1 native inference · P2 custom GPU compute · P3 autonomous coding · P4 integrated build tools.
Audit rule set: fail-closed law `SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`, `NOT_RUN != PASS`.

## 0. Scope & method

- Read-only audit of `src\`, `~dev\`, `tools\`, `certs\`, `agentic_ws\`, `win32app`, CMake/build scripts, `.git` refs, evidence manifests, and legacy/old trees (`.archive`, `.archived_orphans`, `.archived_orphans_ultra`, `archive`, `backup`, `.backups`, `_pre_merge_backup`, `Consolidated_Modules_*`, `Advanced_Reverse_Engineered`, `bigdaddyg-ide`).
- Four parallel deep-audit passes (engine/GPU, agentic harness, IDE/CLI, stub-sweep+baseline) + direct verification of the two load-bearing claims.
- No source changed. No build, no run, no mock anything.

## 1. Verdict summary by pillar

| Pillar | Verdict | Strongest real evidence | One-line blocker |
|---|---|---|---|
| P1 Native inference | PARTIAL — real core, severed link | `src\deep2\Deep2Engine.cpp` (9,635 LoC): real CPU `LinearW` (L3885+), toroidal KV cache, `ProductionCertificate` 9 gates; `GGUFLoader.hpp` arch-aware | `forwardTokenAllLayers` declared but never defined in `src` → engine target cannot link; `nemotron_h_moe` arch NOT implemented |
| P2 Custom GPU compute | REAL kernels, WIRING gap | `src\deep2\vulkan_compute.{h,cpp}` (~6,900 LoC), **48 SPIR-V shaders** (`deep2_q4_gemv.spv`, `deep2_moe_gate_up_fused.comp`, MLA/flash), complete 241-LoC adapter, parity GPU-vs-CPU proven (377/377 weights, 300/300 ops) | Decode call-site not integrated; silent CPU fallback unless `vulkanStrictNoCpuFallback_` (set only at L7924–7928 after GPU init) |
| P3 Autonomous coding | REAL loop, TOY tool surface | `~dev\src\rawr_agent.cpp` (520 LoC, `run_agent_session`, bounded 32 steps, `<tool>/<args>` protocol, Qwen2.5 framing), real parser/dispatch/audit-driver/receipts `FAKE_TOOL_RESULTS=0` | Tool registry is **read-only** (audit.scan, read, grep) — no write/edit/shell/compile/test → calc.cpp 14-receipt run impossible as of today |
| P4 Integrated build tools / IDE | LIVE binary, STUBBED agency | `RawrXD-Win32IDE-Native` is the ONLY current target: `src\win32app\Win32IDE.cpp` (6,012 LoC) + 22 modules, binds real `CPUInferenceEngine` | `AgenticBridge::StartAgentLoop` **returns false** (Win32IDE_AgenticBridge.cpp); `AutonomyManager::start()` no-op (Win32IDE_Autonomy.cpp) → IDE cannot drive the agent |

## 2. P0 blockers (the entire gap; if these fall, closure follows)

1. **P0-1 Engine does not link.** `forwardTokenAllLayers` declared `src\Deep2Engine.h:480`, called `src\deep2\Deep2Engine.cpp:4754,4889` — **no definition in `src\`** (6 grep hits: decl+calls+comments only). Sole definition on disk: `~dev\rawrxd\src\deep2\Deep2Engine.cpp:2178`. CMake comment (@L1434) says "the link errors ARE the deliverable" — an inventory target, not product. Closes: Stages A/E/K.
2. **P0-2 Nemotron 30B cannot run.** `nemotron_h_moe` architecture unimplemented (own evidence: `evidence\RAWRXD_DEEP2_PER_TOKEN_PROFILE_001\certificate.json:31-48` — "the blueprint target model cannot run on this engine at all"). Closes: Stages C/D/N/P start line.
3. **P0-3 No Nemotron model on disk.** `**/*nemo*.gguf` → **0 files** in workspace (only `models\registry.json` entries + other 22 GGUFs). Stage C blocked until model restored + SHA-256 frozen.
4. **P0-4 No TPS baseline.** Best genuine E2E decode evidence: TinyLlama-1.1B Q4_K_M @ **1.32 TPS** (two GPUs detected, CPU-bound) and DeepSeek-V2-Lite @ 0.18 TPS (CPU). Magnitude gap to 150 TPS = ~100–500×, unmeasured at 30B. Closes: N/O/P.
5. **P0-5 Agent can only read.** `~dev\src\rawr_agent_dispatch.cpp` authority: `audit.scan`, `audit.add_candidate`, file read/grep. Missing: write/edit with hashes, shell, cl.exe build+capture, git, test-runner. calc.cpp (seeded `a-b` bug) can never reach 14/14 receipts. Closes: L/M/R.
6. **P0-6 E2E receipt runner is orphaned.** `tools\deep2_agentic_loop.cpp` (verifies MODEL_SAID_FINISH/SOURCE_PATCHED/BUILD_ARTIFACT/TEST_EXECUTION/FINAL_VERDICT) is **in zero CMake targets** and has uncommitted edits. Closes: B/R/Y.
7. **P0-7 IDE↔agent bridge is stubbed at both ends.** `Win32IDE_AgenticBridge.cpp StartAgentLoop → false`; `Win32IDE_Autonomy.cpp AutonomyManager::start() → no-op`. Closes: J/U.
8. **P0-8 Silent CPU fallback.** `LinearW` falls back to CPU thread pool on any Vulkan failure unless `vulkanStrictNoCpuFallback_` is armed post-init (Deep2Engine.cpp L3885→L3972, arm at L7924–7928). Violates Z (zero-stub acceptance) unless counters force-fail. Closes: G/Z.
9. **P0-9 K2 hard stubs.** `src\deep2\K2VNNIKernel.cpp`, `K2LogitsClimb.cpp`, `K2LivePathTensorCache.cpp` = 2-line each. Either implement or excise from the live path. Closes: X.
10. **P0-10 Simulator upstream of product.** `src\agentic_engine.cpp` (keyword "generateResponse" fallback), `src\agentic_executor.cpp:414` + `src\ai_model_caller.cpp:414` (Hello-World mock "TODO: Implement actual model calls") — conflated by old docs as "the agentic engine". Quarantine. Closes: Z.
11. **P0-11 Baseline not frozen.** HEAD = `11402a373e` on branch `tmp-rebase`, **mid-rebase** (conflicts fixed), 2 build-cache mods + 1 tracked source mod (`tools\deep2_agentic_loop.cpp`). Stage A blocked until rebase lands + clean build proves.

## 3. Verified-genuine assets (do NOT rewrite — integrate)

| Asset | Path | Why it is real |
|---|---|---|
| Deep2 engine core | `src\deep2\Deep2Engine.cpp` (9,635 LoC) | Real math paths, chrono throughput timing (L4845–5136), 9-gate production cert, no-stubs header comment |
| Vulkan compute layer | `src\deep2\vulkan_compute.{h,cpp}` (~6,900 LoC) | `physicalInfo()`, `DispatchGEMV/DispatchGEMVQuant`, arena buffers, weight pin/residency |
| Quant GPU kernels | `src\deep2\shaders\*.spv` (48) | q4 GEMV, fused MoE gate_up, MLA fused-gather/flash, rope/kvwrite/spec ops |
| Engine adapter | `src\deep2\vulkan_compute_engine_adapter.cpp` (241 LoC) | Full forwarding of all 8 dispatch members — complete, non-stub |
| Arch-aware loader | `src\deep2\GGUFLoader.hpp` | Dynamic arch dispatch (`nemotron_h`, `nemotron_h_moe`, `deepseek2`, …) — prefix exists, M ach impl missing |
| Agentic loop | `~dev\src\rawr_agent.cpp` + `rawr_agent_parse_only.cpp` + `rawr_agent_dispatch.cpp` + `rawr_agent_audit_driver.cpp` + `rawr_run_stream.cpp` | Unified bounded loop, strict `ModelReply{ToolCall|Final|ProtocolError}` parse, receipt + `FAKE_TOOL_RESULTS=0` |
| Build a real cert harness | `certs\hexmag_swarm_cert.cpp` (1,385 LoC) | Real pipeline user→plan→parallel exec→verify→review; acceptance P1–P6; Stage-R-shaped |
| Native IDE | `src\win32app\Win32IDE.cpp` + 22 modules | Only target that currently builds (MSVC+Vulkan, no Qt) |
| GPU cert tooling | `tools\deep2_gpu_certify.cpp`, `tools\deep2_runtime_dispatch.exe` evidence | Builds & runs on real AMD R9700 (dispatch probe reachable via cl.exe/Vulkan 1.4 SDK) |
| Evidence corpus | `evidence\RAWRXD_DEEP2_*`, `VAL-051-*`, `AGENT_LOCAL_MODEL_SWEEP_2026-10-12` (22 models), `sweep\` nemotron parity logs | Reusable receipts/manifests for Y |

## 4. Claims vs reality (what must be corrected before any valuation talk)

| Claim | Verdict | Reality |
|---|---|---|
| "26/26 GPU forward certificate" | FALSIFIED as stated | No such artifact exists. The string 26/26 appears only in UI/event-handler and validation docs (e.g. `STUB_ELIMINATION_CHANGE_INDEX.md:204`). Actual certs: 18/18 gates (DeepSeek-Coder-V2-Lite) — which explicitly does **NOT** establish TPS or coherence (degenerate all-token-0 output, open severity-high defect) |
| "Nemotron 30B native decode" (commit c878bc2b) | UNVERIFIED | Commit+parity logs exist (`sweep\`), but arch loader missing ⇒ decode could not be engine-native on this tree; re-verify after C |
| "≥150 TPS" | NOT_RUN | No sustained decode measurement exists for any ≥30B model; no machine-readable prefill/decode split product-wide |
| "Production-ready IDE" (CURRENT_STATE/00-FINAL docs) | FALSE by fail-closed law | Engine target does not link; IDE agent bridge returns false; agent has no write/shell tools |
| "Autonomous platform" | PARTIAL | Loop+parse+receipts real and fixing at HEAD (`11402a373e fix(deep2): agentic loop context, parsing, verification, and logging`), but autonomy is read-scan only today |

## 5. Stub/mock/fakes inventory (strip, quarantine, or implement — Z feed)

| Severity | Site | What it is | Disposition |
|---|---|---|---|
| P0 | `src\deep2\K2VNNIKernel.cpp`, `K2LogitsClimb.cpp`, `K2LivePathTensorCache.cpp` | 2-line stubs | Implement or excise (X) |
| P0 | `src\agentic_executor.cpp:400,414`, `src\ai_model_caller.cpp:414` | "Placeholder: return mock response" + `Hello, World!` | Rewrite against Deep2 (Q) or delete callers |
| P0 | `src\agentic_engine.cpp:30` | "Stub for initializeAllTools" (`TOOL_REGISTRY_INIT_IMPLEMENTED` guard) | Wire real registry or remove file |
| P0 | `src\win32app\Win32IDE_AgenticBridge.cpp` StartAgentLoop→false; `Win32IDE_Autonomy.cpp` start() no-op | IDE agency buttons | Implement bridge to `run_agent_session` (J/U) |
| P1 | `src\agentic_engine.cpp` keyword-based "generateResponse" | Simulated Qt engine | Quarantine from product; keep as test fixture, rename not needed |
| P1 | `src\agentic_iterative_reasoning.cpp:333,398`; `src\agentic\AgenticNavigator.cpp:291-431`; `AgenticCopilotIntegration.cpp:165` | "Simulate execution / returns true" placeholders | Touch real tools or delete callers |
| P1 | `src\plan_orchestrator.cpp:159,176,196,348,359` | "return a stub result / create stub tasks" | Real planner + LLM call or remove |
| P1 | `src\real_time_completion_engine{,_v2}.cpp:154,261,313`; `src\CompletionEngine.cpp:68-69` | "TEMPORARY: return realistic mock data" | Bind to Deep2 streaming (T) |
| P2 | `src\api_server.cpp:267,291,326` ; `src\cloud_api_client.cpp:409,415` | Simulated inference/download/stream | Mark cloud deps optional; do not ship labels |
| P2 | `src\agent\action_executor.cpp:439`; `agent\agentic_copilot_bridge.cpp:65,233,598,726` | Placeholder recursion / completions | Purge from production targets |
| P2 | `src\security_manager.cpp:954,960` ("stored credentials (stub)"); `llm_adapter\QuantBackend.cpp:54` | Stub paths | Implement or gate off |
| Inert | `src\vulkan_stubs.cpp`, `vulkan_compute_stub.cpp`, `stub_main.cpp`, `_fake.obj`, `cpu_inference_engine_autofix_stub.cpp` (RAWRXD_PRODUCTION_STRIP_STUB_SOURCES) | Zero refs in live targets | Delete from tree (Z) |

## 6. Build system & git baseline

- Canonical build: `cmake --preset ninja-release` + `cmake --build --preset ninja-release` (`CMakePresets.json` v3). Historical: `build.bat` (VS 2026 x64).
- Live targets today: `RawrXD-Win32IDE-Native` (works, gated `if(MSVC AND RAWRXD_BUILD_WIN32IDE)`), `rawr_monolith`, `rawr_monolith_v2`, `hexmag-integration-tests`. Dead: `RawrXD-Win32IDE` (Qt; missing src), `RawrXD-AgenticIDE` (Qt6 OFF), `RawrXD-Compiler`.
- Hard seam: **root CMake does not include `src\`** — nine subdirs only; the engine lives behind a deliberately-non-linking `rawrxd_deep2_engine` target (`CMakeLists.txt:1442-1466`).
- Duplicate surfaces: `~dev\rawrxd\CMakeLists.txt` (12,938-line second tree), `CMakeLists.txt.bak/.old/.tmp`, `src\CMakeLists.txt`+.old variants — one SSOT required (A/Y).
- Git: HEAD `11402a373e` on `tmp-rebase`, rebase in progress ("all conflicts fixed"), 2-ahead of `origin/feat/gpu-quant-dot`; clean of source edits except `tools\deep2_agentic_loop.cpp` + 2 build-cache files. GGUFs are plain binaries (no LFS). No local tags → Y needs tags/manifests.
- Root pollution: ~4,900 root entries are logs/reports/binary debris (100+ build*.bat, cert_*.log, tool_*.exe × 152) — breaks A (clean checkout) and Y (repro evidence). Archive in batch 6.

## 7. IDE / CLI source triage (current + old)

**LIVE (keep, close it):**
| Path | Role | State |
|---|---|---|
| `src\win32app\Win32IDE.cpp` (+22 modules) | Native Win32 IDE shell, real CmdSurface/Hotpatch/Debugger integration | Builds; agent bridge stubbed (P0-7); `~10` .bak/.stale files in tree |
| `~dev\` (own CMake tree) | rawr agent loop, Deep2 runner, stub scanner + `rawr_monolith_v2` CLI (`agent`/`agent-audit`/`run`) | The **most production-ready agentic path**; promote to `src\` |
| `tools\deep2_agentic_loop.cpp` | E2E receipt runner for calc fixture | Orphaned from build; wire it (R) |
| `certs\hexmag_swarm_cert.cpp` | HexMag Swarm real cert harness (P1–P6) | Not in default build (W) |

**DEAD in-tree (if(FALSE) or gated OFF — consolidate then archive):**
`src\ide_main.cpp`, `ide_main_window.cpp`, `ide_window.cpp`, `agentic_ide*.cpp`, `agentic_ide_main*.cpp`, `main.cpp`, `main-simple.cpp`, `main-minimal.cpp`, `rawrxd_cli.cpp`, `src\ide\` (126 entries), `src\full_agentic_ide\` (manifest+README only), `src\cli\editor\`, `src\session`, `src\qtapp\`.

**OLD/LEGACY (dead weight; mine only for salvage):**
`.archive\FULL_SOURCE`, `.archived_orphans*` (three tiers), `archive\`, `backup\`, `.backups\`, `_pre_merge_backup\`, `Consolidated_Modules_20260124_*` (3 tiny), `Advanced_Reverse_Engineered\src`, `bigdaddyg-ide` (JS), `~dev\rawrxd\src\reverse_engineering\` (fine-grained; separate product NOT needed for closure), plus ~4,900 root log/report/exe artifacts.

## 8. What is needed to close — batched A–Z (matches working TODO plan, 6 batches)

**Batch 0 — AUDIT (this report): COMPLETE.**
**Batch 1 — A/B/C (baseline + entry + model):**
- A: land rebase, clean checkout, toolchain/driver/model SHA-256 freeze; single build script; delete/archive root debris so clean build reproducible. Closes gate: fresh tree builds `RawrXD-Win32IDE-Native` + runner targets.
- B: ONE production CLI = `~dev\rawr_monolith_v2` (`agent` / `agent-audit` / `run`) promoted into `src\` + documented invocation; kill if(FALSE) dinosaurs and Qt shells.
- C: restore Nemotron 3.5 Lightning 30B GGUF (from registry/E drive), verify arch/quant/tensors/expert metadata/tokenizer, freeze SHA-256. Requires `nemotron_h_moe` loader completion (with P0-2). Gate: `MODEL_LOADED`, zero unresolved weights.

**Batch 2 — E/F/I/K (harness repair):**
- E: incremental context append vs full re-prefill — rawr_agent loop has compact 6-entry history + KV reset; implement append-only KV continuation with position audit; no duplicated context.
- F: complete-command rule (terminator, JSON args validated) — extend `rawr_agent_parse_only` to reject/truncate-with-notify malformed `<tool>` blocks; no partial execution.
- I: instrument load/prefill/first-token/decode/TPS/GPU-dispatch counters as flush receipts (machine-readable JSON); reuse `ProductionCertificate` gates.
- K: prefill/incremental/eviction/cap/multi-step KV lifecycle tests incl. cross-turn reuse at 4096-token contexts.

**Batch 3 — J/L/M/S (integration + boundaries):**
- J: same process: CLI (or Win32) → `run_agent_session` → Deep2 runtime → real dispatcher; generated `<tool>` reaches authorized tool. Bridge Win32IDE StartAgentLoop→real runner (fix P0-7).
- L: write/edit tools with real file-hash receipts, workspace containment, scoped path allowlist.
- M: cl.exe/link shell tool with stdout/stderr/exit capture + timeouts; observations returned into next model turn (real tool authority, not parse-only).
- S: fail-closed boundaries: deny outside workspace, no destructive ops, process kill on timeout, permission model + audit of every denied call.

**Batch 4 — G/H/O/N/P (GPU + perf):**
- G: re-run forward cert on repaired link (26/26→ correctly named gate: 18/18 extended) with counter export (vulkanGemvOk/Fail, CPU fallback = hard FAIL).
- H: re-run batched MoE equivalence, buffer lifetime, cache-residency, allocation-failure suites.
- O: profile MoE expert GEMV/weight traffic/dispatch overhead on Nemotron 30B-A3B profile; fix measured hotspots; parity after EVERY change (decode call-site gap = first target).
- N: sustained decode benches 128/512/1024/4096 tokens, prefill vs decode separated, JSON receipts.
- P: prove ≥150 sustained TPS at documented context/hw/concurrency; TPS reported from decode wall time, not token-echo.

**Batch 5 — D/Q/R/T/W (autonomy + acceptance):**
- D: rebuild parity cert for Nemotron arch (logits/token parity at meaningful positions vs independent reference), close all-token-0 degenerate defect.
- Q: structured tool selection + self-correction on unseen tasks; (30B-A3B MoE model fitted); substitution of `rawr_agent` receipt gate for simulators.
- R: run `agentic_ws\calc.cpp` E2E through wired runner: 14/14 authentic receipts, PASS exit 0, model-generated finish, disposable git diff. This is the valuation-critical first milestone and NEEDS P0-5/6 fixed first.
- T: multi-file real tasks (dependency analysis, regression tests) ≥5 unique tasks repeated.
- W: `certs\hexmag_swarm_cert.cpp` promoted to default build; multi-agent session isolation tested on real registry (K2 stubs resolved or removed, P0-9).

**Batch 6 — U/V/X/Y/Z (product hardening + release):**
- U: IDE and CLI share task/session state (one runner service); IDE bridge unstubbed end-to-end.
- V: endurance + crash-recovery + OOM + malformed-input + cancellation; fail-closed recovery proven.
- X: close `nemotron_h_moe` forward + fused-QKV/gated attention; certify separately Qwen3, Gemma3, Granite, DeepSeek-Coder-V2, Laguna; K2 path fixed (P0-9).
- Y: hashed/signed binaries, ONE build script/SSOT, benchmark logs, receipt manifests, known-limitations doc; tag release ref.
- Z: zero-stub audit: delete inert stub list (§5), counters assert no CPU fallback, scanning over shipped targets passes.

## 9. Immediate execution order (shortest path)

1. `Batch1 A` (rebase + clean tree) → 2. `B` (promote ~dev runner to src, single CLI) → 3. `C`+`D` (Nemotron arch loader + parity: kills P0-1 and P0-2) → 4. `Batch2 (E/F/I/K)` on the ~dev loop → 5. `Batch3 (J/L/M/S)` to enable write/shell/compile → 6. **`R`: first authentic 14/14 receipts** → 7. `Batch4 (G/H/O/N/P)` toward 150 TPS → 8. `Batch5 (Q/T/W)` → 9. `Batch6 (U/V/X/Y/Z)` release hardening.

Pillar alignment: buys P1+P3+P4 immediately (an authentic autonomous receipt = the product exists); P2 closes last and its TPS ceiling is then measurable honestly.

## 10. Failure modes explicitly banned (per owner instruction)

No mock source, no fake tool output, no re-run theater, no stub engine swap, no pretended compiler/build/link. Gate receipts must be generated by real tool execution. The simulator tree (`src\agentic_engine.cpp` and friends) is not a product path and must never be cited as one.

}*Audit authored 2026-10-12, static analysis + git refs + direct verification; ≤4 subagent sweeps consolidated; no mutations made.*
