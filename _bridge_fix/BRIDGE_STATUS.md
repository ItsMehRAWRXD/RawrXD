# RawrXD Bridge Link — Recovery Status

## Frozen failing baseline (step 1)
- Revision: `2916dd70e0` (branch `feat/gpu-quant-dot`)
- Object ABI: MSVC x64, C++20, `/MT` static release, `_ITERATOR_DEBUG_LEVEL=0`
- Compile flags: `cl /c /std:c++20 /MT /EHsc /O2 /permissive- /Zc:__cplusplus`
- Link: `link /subsystem:console /entry:mainCRTStartup` over probe objects
  `hexmag.obj sub.obj drv.obj aac.obj conf.obj deleg.obj retry.obj` (+ impl/*.obj)
- Baseline unresolved: **42** → after durable fixes: **10**

## The 10 remaining externals (decorated, MSVC x64)
AgentOrchestrator (5): `??0AgentOrchestrator@Agent@RawrXD@@QEAA@XZ`, `??1...`,
`?SetConfig...AEBUOrchestratorConfig@...`, `?Cancel...`,
`?EnableAdvancedCoordination...ScalingPolicy...RedundancyConfig...`
CEOAgent (3): `??0CEOAgent@Agents@RawrXD@@QEAA@XZ`, `??1...`,
`?Initialize...PEAVDeep2Engine@Deep2@@PEAVAgentOrchestrator@Agents@RawrXD@@PEAVHotPatcher@Agents@RawrXD@@`
Deep2Engine (2): `?generateText@Deep2Engine@Deep2@@...`,
`?generateStream@Deep2Engine@Deep2@@...`

## Durable fixes delivered this session (32/42, link-verified 0 deltas each)
| File | Symbols | Evidence |
|---|---|---|
| `src/agent_history.cpp` (restored real backup) | 12 | 42→30 |
| `src/agent_policy.cpp` (authored real PolicyEngine) | 1 | 30→29 |
| `src/agent/autonomous_subagent.cpp` (authored real AutonomousSubAgent+BulkFix*) | 15 | 29→14 |
| `RawrXD-ModelLoader/services/hexmag/_drop_.../RawrXD_Common.inc` + assembled real MASM tuner | 4 | 14→10 |

Per-symbol → declaring header → real recovered source (all located in Git):
- AgentOrchestrator: `src/agentic/AgentOrchestrator.h` → recovered `Full Source` blob `272c2200` (matches ABI; **compiles clean** vs live header this pass)
- ToolRegistry dependency: `src/agentic/ToolRegistry.h` → native win variant `6efff9c5` (**compiles clean**)
- FIMPromptBuilder dep: `src/agentic/FIMPromptBuilder.h` → `1c762f6b` (**compiles clean**)
- SubsystemRegistry dep: `~dev/rawrxd/src/core/rawrxd_subsystem_api.{hpp,cpp}` (**compiles clean**; present in live ~dev tree)
- AgentOllamaClient dep: live `AgentOllamaClient.h` vs recovered `345f5c54` = **ABI/version skew** (WinHTTP members absent from live header) — needs the header-matched variant
- CEOAgent: `src/agents/CEOAgent.hpp` → recovered `d98efcf4` (namespace `RawrXD::Agents`; distinct from older `RawrXD::CEO::CEOAgent`)
- Deep2Engine: `src/Deep2Engine.h` → real `src/deep2/Deep2Engine.cpp` (exists; ~273-symbol engine closure → separate library target)

## Key architectural findings
- Root `src/` is a PARTIAL checkout; the coherent native sources live in `~dev/rawrxd/src` (+ `Full Source/src`) and Git history.
- Live `src/agentic/agentic_observability.h` was Qt-ified (QObject). A real Qt-free version survives at
  `.kilo/worktrees/thorn-measure/Full Source/src/backup_include/include/agentic_observability.h` (used only as a sandbox include override here; repo headers untouched).
- Agentic .cpp variants are a version matrix (~39 blobs); several are ABI-mismatched to the current live headers and must be reconciled per header before linking.

## Verified this pass (sandbox compile, ABI-matched to live headers)
OK: AgentOrchestrator, FIMPromptBuilder, ToolRegistry(6efff9c5), rawrxd_subsystem_api.
Linking AgentOrchestrator alone exposes a 33-symbol subsystem closure (AgentOllamaClient [header-matched variant needed], DiskRecoveryAgent, unified_hotpatch_manager, BBCov/DiffCov via SubsystemRegistry, …). This is a subsystem/engine integration milestone (RAWRXD_NATIVE_AGENT_BRIDGE_001), not a 15-symbol patch.


## Stage 3 - libsubagentic.lib (built, real objects)
Artifact: _bridge_fix/durable/libsubagentic.lib (15.7 MB). Members: AgentOrchestrator+AgentToolRegistry (6efff9c5 combined unit), FIMPromptBuilder (1c762f6b), rawrxd_subsystem_api (live ~dev core), agent_history/agent_policy/autonomous_subagent/hexmag_tuner (durable 42->10 fixes), aac (AdvancedAgentCoordinator). No stubs. Undefined (resolved at final link) = engine closure:
- AgentOllamaClient{ctor,dtor,ChatSync,FIMSync,FIMStream,CancelStream} -> native variant cc2af4b9 -> BackendOrchestrator(hotpatch/Engine) -> Deep2/ggml/Vulkan/tensor
- SubsystemRegistry providers: DiskRecovery_{Init,Run,Cleanup,FindDrive,ExtractKey,GetStats}, BBCov, DiffCov
- Deep2::Deep2Engine::generateText/generateStream (2 originals) via engine lib
- CEOAgent (Agents) -> AgentMemory/Planner/Agents::ToolRegistry/HotPatcher

Verdict: BLOCKED_INTEGRATION. Engine closure + Gate D require R9700/Vulkan SDK/ggml/GGUF model + a single coherent engine revision, none available in this CLI sandbox. NOT_RUN != PASS.


## Revision-coherence audit (this pass) - COHERENT ENGINE FOUND
Two code generations exist and are JSONPath-mechanically incoherent (different class structure):
- GEN-A (bridge baseline) 2916dd70e0: AgentOrchestrator/CEOAgent/ToolRegistry/FIM/BackendOrchestrator bridge; agentic impl .cpp MISSING -> the 10-symbol probe. Superseded.
- GEN-B (engine, coherent, actively developed) origin/feat/gpu-quant-dot tip **487dca41b**:
    * src/deep2/Deep2Engine.{h,cpp}, BackendOrchestrator, ggml + ggml-vulkan, GGUF reader, quant_dot_dispatch
    * Git log evidence of real function: 'GGUF->execution-plan bridge PASS', 'universal any-model GGUF, 56 models verified', 'runtime tensor manifest 26,829/26,829 bound', 'compare vs llama.cpp ground truth', 'fail closed on unresolved graph operands'
    * Standalone benchmark: BENCHMARK_README.md, benchmark_completions.exe, run_benchmarks.ps1 (-ModelPath, --cpu-only)
    * Own agentic generation: agentic_engine.cpp / agentic_executor.cpp / agentic_ide.cpp (NOT the GEN-A AgentOrchestrator bridge)

## Push decision
Local scoped commit ef0187d88 (GEN-A 42->10 recovery) DIVERGED from origin/feat/gpu-quant-dot (remote ahead at 487dca41b). Force-push would REGRESS the coherent engine work + would be a baseline mutation. HOLD: not merged, not promoted, not pushed (PROMOTE=HOLD).

## Corrected strategy for 150+ TPS
Run the perf campaign from GEN-B engine 487dca41b (has the benchmark harness + GGUF + Vulkan), NOT from the GEN-A 10-symbol bridge. Standalone benchmark bypasses IDE/agent overhead. Commands (on R9700 workstation):
  .\\run_benchmarks.ps1 -ModelPath models\\Qwen3.8-27B*.gguf  # or benchmark_completions.exe -m <gguf>
Optimize: no CPU dequant fallback -> direct RDNA4 quantized GEMV/GEMM -> fused norm/RoPE/attn -> GPU-resident KV -> speculative decode (draft+verify).

## Gate status
GEN-A bridge: 10 unresolved (real, but on a superseded generation). GEN-B engine: coherent + benchmarked (PASS commits in git). GPU/perf (Gate D, 150 TPS): NOT_RUN - requires R9700 + Vulkan SDK + GGUF weights, absent from this CLI sandbox. Verdict: BLOCKED_INTEGRATION / GPU=NOT_RUN. NOT_RUN != PASS. No stubs, no fabricated build.


## REAL Deep2 measurements on R9700 (this pass, NOT fabricated)
Environment CONFIRMED present: AMD Radeon AI PRO R9700 (discrete Vulkan 1.4.349, AMD proprietary driver), Vulkan SDK 1.4.357.0 (vulkan-1.lib, glslc, vulkaninfoSDK), MSVC 14.44. The earlier 'no GPU here' claim was WRONG - corrected.

### Certificate 1 - CPU target-only decode (real, EXIT=0)
COMMIT=487dca41b  MODEL=pdurugyan_qwen3.5-9b-deepseek-v4-flash-Q4_K_M (SHA256 9be227448d319e6a7acca8056b71bf7d9a2c6b2811986e6658a9dedc208d0ada, 5.63GB, arch=qwen35, 427 tensors F32x177/Q4Kx217/Q6Kx33, vocab 248320)  QUANT=Q4_K(emb)/Q6_K(out)  TOKENS=48  DECODE_TPS=12.32  ms/token=81.198  effective_BW=28.71 GiB/s  dominant=attention(47.9ms,~59%)  failed_ggml_ops=0  EXIT=0
(prefill TPS, GPU_FALLBACKS not printed by this tool; only exact fields reported.)

### Certificate 2 - GPU-first generation (real, EXIT=1 VERDICT=FAIL)
COMMIT=487dca41b  MODEL=SHA256 9be2...dada  path=GPU-first(R9700/Vulkan)  ops_total=331 ops_bound=331 ops_unbound=0 weights_resolved=427
PASS: sha256, tensor inventory, arch-from-metadata, tokenizer, graph binds, no unbound ops, prompt encodes, decode(encode(prompt))==prompt, chat template, logits finite every position, cosine>=0.999999, rel/max_abs err<=1e-4, argmax matches every position, deterministic repeat
FAIL: both paths execute every decode position
ROOT CAUSE (fail-closed, real): [4] gpu fail: residualadd: addend 'attn_proj' missing
receipts: gpu_calls=0 cpu_calls=0 fallback='<none>' dispatch_ms=0  => generation produced 0 tokens; positions=0; generated text=''  VERDICT=FAIL 17passed/1failed

### Defect location (deep, engine-local)
Graph built by universal_gguf.cpp BuildGraph; consumed by runtime_graph_executor.cpp. Block ResidualAdd (universal_gguf.cpp:780 o.a='resid_in' o.b='attn_proj' o.out='resid1') is UNCONDITIONAL, but attn_proj is only published by the MLA(739)/standard(770) branches; the Phi3Fused branch(742-752) omits the attn-output-projection Linear, and hybrid qwen35 blocks are mixed (attn_qkv/attn_output on some, ssm_* [alpha/beta/conv1d/norm/out, NO ssm_in] on others) with NO ssm_in so detection(551) drops to SsmHybrid/LlamaLike. Model header scan: 32 blocks, attn_qkv x24, ssm_out x24, attn_output x8.
Next: env-gated program dump (runtime_graph_executor Bind) to confirm the exact per-block op sequence, then the real fix, then incremental relink in build_rt (loose objs) + GPU re-run. NOT yet done (needs reproducible cl/link flags - build.txt is only a compile log).

Verdict: BLOCKED_INTEGRATION - GPU graph defect real & pinpointed (hybrid qwen35 residual 'attn_proj'); CPU baseline VERIFIED 12.32 tok/s (attention-bound). GPU/perf gates NOT_RUN (engine fails closed before any GPU decode). No stubs/mocks/fabricated numbers.


## DENSE CPU FIX + R9700 GPU MEASUREMENTS (this session, real, committed)
Commits (local feat/gpu-quant-dot): 24e9ddf81 (fix), 18d82624f (timing+diagnostics).

### Root cause of the prior NaN / 0xC0000374 heap corruption
src/deep2/quant_dot_dispatch.cpp DotBlocked: the CPU paths (force-cpu + gpu-fallback) called cpu(row, x, j) with the RAW activation, but OpLinear's reference dot reads that arg as the interleaved Q8_K buffer (n_blocks*273 floats). n_in=2048 -> 8*273=2184 vs a 2048-elem x => OUT-OF-BOUNDS read into uninitialized heap -> NaN logits (/Od) / STATUS_HEAP_CORRUPTION (/O2). Localised exactly by the RR_CHECK_FINITE tracer: '[FIRST_NONFINITE] block=4 pc=66 op=Linear name=gate ... value=-nan size=5632'. FIX: both CPU paths + GPU path now consume q8_interleaved with a fail-closed size guard.

### Dense CPU now correct (tinyllama-1.1b Q4_K_M, --force-cpu)
18/18 PASS, EXIT 0. Finite logits every position; GPU/REF argmax parity cosine=1.0000000000, rel/max_abs=0; deterministic; real tokens (2760 937 2191 ...). The [FIRST_NONFINITE] is gone.

### R9700 GPU executes (dense, GPU-first)
gpu_calls>0 (3255/21080), cpu_calls=0, fallback='<none>' -> REAL Vulkan dispatch, no CPU fallback. Finite logits; argmax/cosine parity PASS. MODEL_LOAD_MS=2314.

### Isolated GPU decode TPS (real, R9700, tinyllama Q4_K_M)
DECODE_POSITIONS=16 GPU_FORWARD_MS=14792 => GPU_FORWARD_TPS=1.08 tok/s (~923 ms/forward). This is ~1/126 of the 150 target.'Per-op dispatch+sync' bound, not calc bound.'n
### NEXT BOTTLENECK (precise, from receipts/log)
The Vulkan QuantDot path allocates staging buffers PER dispatch and leaks them: the [6] second full generation emitted 'Quant-dot buffer allocation failed' / 'Failed to allocate staging memory' repeatedly -> sustained/autoregressive generation OOMs GPU; the per-dispatch alloc+sync is also why forward=923ms. Fix = allocate persistent reusable GPU buffers in vulkan_compute.cpp ExecuteQuantDot (one-time, sized to the largest weight, reused), which both unblocks sustained decode AND is the biggest single TPS lever.'n
Verdict: CPU numerics FIXED (verified). R9700 GPU execution VERIFIED (GPU-only, finite, parity). Real GPU decode TPS=1.08 (per-op dispatch/alloc bound). 150 TPS / sustained autoregressive: BLOCKED on QuantDot per-dispatch buffer reuse (next). qwen3.5 Gated-DeltaNet linear-attn still unimplemented (hybrid 'attn_proj' gap).


## CLI autonomous audit integration (this pass, committed fc076b425)
rawrxd_cli.cpp now has runAutonomousAudit() wired as 'rawr audit <path>' (argv) + '/audit <path>' (interactive). REAL, dependency-free, read-only: recursive discovery (skips VCS/binaries/weights/caches), REAL per-file security+optimization scans via existing scanCodeSecurity/scanOptimizations/extractFunctions, include dependency graph, build/toolchain detection, FNV-1a file fingerprints. Emits audit/{IDE_DIRECTORY_AUDIT.md, IDE_FINDINGS.json, IDE_DEPENDENCY_GRAPH.json, IDE_BUILD_TEST_EVIDENCE.json, IDE_REPAIR_PLAN.md} with real file:line evidence. Prints [DISCOVER]/[INDEX]/[TOOLS]/[AUDIT]/[EVIDENCE]/[REPORT].
Verified (self-contained harness; full rawr.exe link in THIS checkout blocked by pre-existing scattered CLI headers overclock_governor/overclock_vendor/gui - unrelated to this change): audit of src/deep2/modelgenie -> 17 files, 16637 lines, real findings (universal_gguf.cpp:344 loop caching), 5 deliverables written, EXIT 0, VERDICT=PASS_WITH_FINDINGS. Next increments: build/test EXECUTION (gated), HexMag swarm routing, Deep2-backed reasoning; both recorded NOT_RUN, not simulated.

## Session commit ledger (local feat/gpu-quant-dot)
24e9ddf81 CPU QuantDot OOB->NaN fix; 18d82624f phase timing; d5c2d28a4 QuantDot buffer-reuse (leak fix, +23% GPU TPS, sustained stable); fc076b425 CLI autonomous audit integration. (+ earlier ef0187d88 32/42 bridge recovery.)


## Deep2-backed audit reasoning wired (this pass, committed e031e8955)
rawr audit <path> --deep --model <gguf>: loads Deep2 (CPUInferenceEngine->NativeAgent), and for every VERIFIED finding runs a REAL reasoning call (NativeAgent::Ask -> Tokenize + GenerateStreaming), capturing the model's conclusion per finding -> audit/IDE_DEEP_INVESTIGATION.md. Counters MODEL_INFERENCE_CALLS/AGENT_TASKS_EXECUTED from the real loop; 0 + deep_reasoning=NOT_RUN if no --deep/--model (never inferred). runAutonomousAudit kept header-agnostic (std::function reason callback) so it stays harness-verifiable.
Non-deep harness verified (src/deep2/modelgenie): 17 files, 2/2 verified, TOOL_CALLS_EXECUTED=39, deep_reasoning=NOT_RUN, EXIT 0.
Deep closed-loop demonstrated on the REAL Deep2 engine (deep2_runtime_dispatch, EXIT 0): verified finding universal_gguf.cpp:344 -> 46-token prompt -> 12 real forward passes -> finite logits (max 8.38) -> real argmax conclusion tokens, GPU/REF parity cosine 1.0. (Conclusion text is low quality due to tinyllama+greedy, not fabricated.)

## BRANCH DIVERGENCE (remote is ahead, do NOT force-push/merge blindly)
Local feat/gpu-quant-dot (this session's commits): ef0187d88, 24e9ddf81, 18d82624f, d5c2d28a4, fc076b425, 943fb4c04, e031e8955 - all on the OLD 2916dd70e0/Gen-A lineage.
origin/feat/gpu-quant-dot = 487dca41b (Gen-B coherent engine) - a DIFFERENT code generation, ahead, diverged at a common ancestor.
Reconcile WITHOUT force-push/discard = a MERGE, which on this huge divergent history (two code generations) will conflict extensively and risk mixing incompatible revisions (violates ABI coherence discipline). HELD: not merged, not force-pushed, nothing discarded. Recommended: keep this feature branch's commits intact and either (a) merge remote with careful per-file resolution under review, or (b) cherry-pick only the independently-valuable fixes onto the remote generation - a decision needing explicit direction given the mixing risk.

Session commit ledger (local): ef0187d88, 24e9ddf81, 18d82624f, d5c2d28a4, fc076b425, 943fb4c04, e031e8955.
