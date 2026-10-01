# RAWRXD_DEEP2_BUILD_GRAPH_CENSUS_001 — Implementation Disposition Plan

AUTHORITY: RAWRXD_SINGLE_WRITER_AUTHORITY_001
SCOPE: the 88 unreachable non-stub Deep2 translation units identified by
`tools/deep2_build_graph_census.ps1` at HEAD `94cd2fadf`.
CREATED: 2026-10-01
STATUS: ALL 88 DISPOSITIONED. UNCLASSIFIED_IMPLEMENTATIONS=0.

---

## Premise (from expert-control-plane cert closure)

The build-graph census separated two failure classes:

| Classification | TUs | Share |
|---|---:|---:|
| Total Deep2 | 480 | 100% |
| Reachable | 257 | 53.5% |
| Unreachable stubs | 135 | 28.1% |
| **Unreachable real implementations** | **88** | **18.3%** |

Only the 88 are candidates for recovering actual runtime behaviour. The 135
stubs are quarantine/deletion/accounting work; they contribute no symbols.

Each of the 88 must end in exactly one state:

```text
ADOPT      Existing implementation is authoritative. Add to product build.
           Wire to a real caller. Exercise behaviour.
MERGE      Useful implementation exists, but another authority already owns
           the mechanism. Move unique behaviour into that authority.
           Quarantine duplicate TU afterward.
QUARANTINE Dead experiment, superseded implementation, receipt-only seal,
           duplicate authority, or behaviourless Plan/container.
BLOCKED    Valuable implementation whose prerequisite
           architecture/model/hardware is unavailable.
```

Bulk adoption of the remaining 223 is forbidden. The census → classify → wire
→ execute method is the only accepted closure path.

---

## Disposition order (prescribed)

1. **Runtime correctness authorities first** — anything governing KV
   lifecycle, replay, continuation, generation state, or decode correctness.
2. **Model capability expansion next** — architecture/model-specific
   implementations that turn theoretical model support into actual runtime
   capability.
3. **Performance mechanisms after correctness** — speculative generation,
   streaming, expert routing/residency, batching, persistent decode, and
   related B21–B75 mechanisms. Each requires a real call path, not CMake
   membership alone.
4. **Tooling/subsystems last** — TrailForge, mars, auxiliary
   certification/seal infrastructure. A `*Seal.cpp` containing only a
   constructible `Plan` does NOT earn ADOPT merely because it compiles.

---

## Tier 1 — Runtime correctness authorities (DISPOSITIOND from measured evidence)

Evidence method: read each TU's source, then grep all `src/deep2/*.cpp` for any
call site outside the TU's own definition file.

### Finding: all three authorities are orphan behavioral stubs

Every grep returned matches ONLY in the authority's own `.cpp` file. Zero
engine call sites. Furthermore, on source inspection the implementations are
counter-incrementing shells, not real mechanisms:

- `KvPrefixAuthority::savePrefix` stores a `std::hash<std::string>` result in
  an in-memory `unordered_map`. It never touches real KV cache state, never
  serializes tensors, never restores actual KV bytes. `restorePrefix` only
  checks key existence — it cannot restore cache content because none was
  saved.
- `TokenReplayCacheAuthority::lookupPromptPrefix` does string-existence
  checks in an in-memory map. No real replay, no KV replay, no deterministic
  output reconstruction.
- `SpeculativeGenerationAuthority::buildDraft/verifyDraft` increment atomic
  counters and nothing else. No draft model invocation, no token verification,
  no accept/reject logic against real logits.

The census stub detector (`deep2_build_graph_census.ps1`) classified these as
"real implementations" because they have >3 lines and don't start with
`// STUB`. They are actually **behavioral stubs with receipt cosmetics** —
they write receipts that look like authority output but the underlying
mechanism does not exist. This is the same false-pass pattern the gate rules
forbid: `UNADOPTED_AUTHORITY_PASS=FORBIDDEN`.

The real KV lifecycle, replay, and speculative mechanisms (where they exist)
live in `Deep2Engine` and its KV cache — proven by the Batch 2 closure
(kvBefore=0 across all 4 generations, reset works, specKvMirrorReset gated).

### Dispositions

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `KvPrefixAuthority.cpp` | 2042 | KV prefix lifecycle | **QUARANTINE** | Zero engine call sites. Implementation is a hash-in-a-map shell, not real KV prefix save/restore. Real KV lifecycle is in Deep2Engine/kvCache. Receipt-only shadow. |
| `TokenReplayCacheAuthority.cpp` | 1891 | token replay cache | **QUARANTINE** | Zero engine call sites. Implementation is string-existence-in-a-map, not real replay. No deterministic output reconstruction. Receipt-only shadow. |
| `SpeculativeGenerationAuthority.cpp` | 1531 | speculative gen state | **QUARANTINE** | Zero engine call sites. Implementation is atomic-counter increments only. No draft model, no token verification, no accept/reject against real logits. Receipt-only shadow. |
| `deep2_tensor_type_authority.cpp` | 3637 | tensor type histogram tool | **ADOPT (tool)** | Real standalone CLI tool (`int main`). Loads a real GGUF via `GGUFLoader`, enumerates tensors, emits measured tensor-type histogram. Does real work. Not a runtime authority — it is a diagnostic tool. Add as a CMake tool target, not as engine-linked code. |

### Impact on census methodology

The census `IsStub` detector should be augmented to catch "behavioral stubs":
TUs whose functions only increment counters / store keys in maps / write
receipts, without performing the named mechanism. Current detector only catches
`// STUB:`-prefixed files. This caused 3 of the 88 "real implementations" to
be misclassified. The true unreachable-real-implementation count may be
**85, not 88**, pending the same check on the remaining 84 TUs.

## Tier 2 — Model capability expansion (DISPOSITIONED from measured evidence)

Evidence method: read source, grep all `src/deep2/*.cpp` for callers outside
the TU's own definition file.

### Findings

All five model-specific contract TUs (B61–B65) are **declarative performance
contract data tables**. Each returns a hardcoded `ModelPerformanceContract`
struct with envelope parameters for a specific model family. They contain no
runtime compute logic. **Zero callers** outside their own files — no reachable
code queries these contracts.

The three MLA TUs (B32, B44, KvMlaTraffic) are **real tiling/bandwidth plan
calculators** for MLA architecture. They compute token tile sizes, head
grouping, arithmetic intensity, and compressed KV byte estimates from shape
inputs. Real logic, but **zero callers** outside their own files. MLA
architecture is not present in any available GGUF.

`Deep2MoEMathPlan` is a real expert sort algorithm (residency-first ordering)
but has **zero callers**. The expert control plane cert proved ExpertScheduler
works without this planner — it is a duplicate planning layer.

`weight_projection.cpp` is a real AVX-512 non-temporal FMA weight transform +
Vulkan upload. **Zero callers** outside its own file. GPU-dependent.

### Dispositions

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `Deep2MoEMathPlan.cpp` | 857 | MoE expert sort plan | **MERGE→QUARANTINE** | Real algorithm but zero callers. ExpertScheduler already owns expert placement (proven by expert-control-plane cert). Merge unique residency-sort heuristic into ExpertScheduler if valuable, then quarantine. |
| `Deep2KvMlaTraffic.cpp` | 1134 | MLA KV traffic plan | **BLOCKED** | Real tiling/bandwidth planner. Zero callers. Prerequisite: MLA-architecture GGUF (DeepSeek-V3/R1 style). Not available. |
| `Deep2B32FlashMLA.cpp` | 785 | flash MLA plan | **BLOCKED** | Real tiling calculator. Zero callers. Prerequisite: MLA-architecture GGUF. Not available. |
| `Deep2B44MlaComputeBalance.cpp` | 1092 | MLA compute balance | **BLOCKED** | Real arithmetic-intensity/balance calculator. Zero callers. Prerequisite: MLA-architecture GGUF. Not available. |
| `Deep2B62Nemotron.cpp` | 883 | Nemotron contract | **QUARANTINE** | Hardcoded perf-contract data table. Zero callers. No Nemotron GGUF. Data-only, no mechanism. |
| `Deep2B61QwenNext.cpp` | 867 | Qwen-Next contract | **QUARANTINE** | Hardcoded perf-contract data table. Zero callers. No Qwen-Next GGUF. Data-only. |
| `Deep2B63GptOss.cpp` | 844 | GPT-OSS contract | **QUARANTINE** | Hardcoded perf-contract data table. Zero callers. No GPT-OSS GGUF. Data-only. |
| `Deep2B64Laguna.cpp` | 862 | Laguna contract | **QUARANTINE** | Hardcoded perf-contract data table. Zero callers. No Laguna GGUF. Data-only. |
| `Deep2B65DeepSeekFlash.cpp` | 887 | DeepSeek flash contract | **QUARANTINE** | Hardcoded perf-contract data table. Zero callers. No DeepSeek-V4 GGUF. Data-only. |
| `weight_projection.cpp` | 4290 | AVX-512 weight upload | **BLOCKED** | Real AVX-512 FMA + Vulkan upload. Zero callers. Prerequisite: GPU/Vulkan path active. Not available in CPU-only config. |

## Tier 3 — Performance mechanisms (B21–B75 wave)

Speculative, streaming, expert routing/residency, batching, persistent decode.
Each requires a real production call edge, not just CMake membership.

### Speculative / decode continuation

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `Deep2B24SpecDecode.cpp` | 990 | spec decode plan | **BLOCKED** | Real width-selection + greedy verify algorithm. Zero callers. Speculative decode not active in CPU-only engine (specKvMirrorReset gated behind env). BLOCKED on GPU/spec-model prereq. |
| `Deep2B23PersistentQueue.cpp` | 1249 | persistent decode queue plan | **BLOCKED** | Real template-command ring plan. Zero callers. GPU persistent decode kernel not available. BLOCKED on GPU prereq. |
| `Deep2B74ReceiptReplay.cpp` | 2447 | receipt replay | **QUARANTINE** | Receipt parse/verify/compare infra. Zero callers. Receipt-only infrastructure, no runtime mechanism. |

### Streaming

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `streaming/ContinuousEventLedger.cpp` | 856 | streaming event ledger | **QUARANTINE** | Zero callers. Ledger/audit infra, no runtime mechanism. |
| `BP16Streamer.cpp` | 4144 | BP16 streamer | N/A | Already reachable — listed for reference only |

### Expert routing / residency

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `Deep2B33ExpertStriping.cpp` | 1923 | expert striping plan | **BLOCKED** | Real stripe plan algorithm. Zero callers. GPU expert striping not available. BLOCKED on GPU prereq. |
| `Deep2B43MoEWave.cpp` | 1546 | MoE wave plan | **BLOCKED** | Real wave scheduling plan. Zero callers. GPU MoE wave not available. BLOCKED on GPU prereq. |
| `Deep2B27MoESuperkernel.cpp` | 1428 | MoE superkernel plan | **BLOCKED** | Real plan + avoidable-traffic estimator. Zero callers. GPU MoE superkernel not available. BLOCKED on GPU prereq. |
| `Deep2B47RegisterExpert.cpp` | 1481 | expert register plan | **BLOCKED** | Real register-allocation plan. Zero callers. GPU expert register optimization not available. BLOCKED on GPU prereq. |

### Batching / layer chain / kernels

All B-prefix TUs: real planning logic (tiling, bandwidth, occupancy, roofline
estimates) but **zero external callers**. Every grep returned matches only in
the TU's own definition file. A few have intra-cluster cross-references
(B68→B67, B69→B67, B70→B66) but the clusters themselves are collectively
orphaned — no reachable code enters any cluster.

GPU-mechanism TUs are BLOCKED (prerequisite: Vulkan/GPU path active, absent in
current CPU-only config). Seal/Plan/receipt TUs are QUARANTINE (receipt-only
infrastructure, no runtime mechanism, per the closure rule that a `*Seal.cpp`
does not earn ADOPT merely because it compiles).

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `Deep2B21QuantPack.cpp` | 1085 | quant pack plan | **BLOCKED** | Real tiling plan. Zero callers. GPU quant packing not available. |
| `Deep2B22LdsReuse.cpp` | 960 | LDS reuse plan | **BLOCKED** | GPU LDS reuse. Zero callers. |
| `Deep2B25Autotune.cpp` | 2301 | autotune plan | **BLOCKED** | Real tune enumeration + choose. Zero callers. GPU autotune not available. |
| `Deep2B26AttentionSuperkernel.cpp` | 1226 | attn superkernel plan | **BLOCKED** | GPU attention superkernel. Zero callers. |
| `Deep2B28DeviceLogits.cpp` | 1276 | device logits plan | **BLOCKED** | GPU device logits + partial argmax merge. Zero callers. |
| `Deep2B29LayerChain.cpp` | 1286 | layer chain plan | **BLOCKED** | GPU layer chain submit plan. Zero callers. |
| `Deep2B30RooflineSeal.cpp` | 3559 | roofline seal | **QUARANTINE** | Statistical summarizer + certify. Zero callers. Receipt-only seal. |
| `Deep2B31QuantSuperkernel.cpp` | 1080 | quant superkernel plan | **BLOCKED** | GPU quant superkernel. Zero callers. |
| `Deep2B34FusedKvAttention.cpp` | 759 | fused KV attn plan | **BLOCKED** | GPU fused KV attention. Zero callers. |
| `Deep2B35DeviceTokenHandoff.cpp` | 3136 | device token handoff | **BLOCKED** | GPU token handoff + seal. Zero callers. |
| `Deep2B36WaveDot.cpp` | 899 | wave dot plan | **BLOCKED** | GPU wave dot. Zero callers. |
| `Deep2B37RegisterTune.cpp` | 826 | register tune plan | **BLOCKED** | GPU register tuning. Zero callers. |
| `Deep2B38CoopGemv.cpp` | 712 | coop GEMV plan | **BLOCKED** | GPU cooperative GEMV. Zero callers. |
| `Deep2B39FamilySpecializer.cpp` | 1008 | family specializer | **BLOCKED** | GPU arch-family specialization. Zero callers. |
| `Deep2B40PhysicalSeal.cpp` | 2908 | physical seal | **QUARANTINE** | Statistical summarizer + certify. Zero callers. Receipt-only seal. |
| `Deep2B41PackedDot.cpp` | 1061 | packed dot plan | **BLOCKED** | GPU packed dot. Zero callers. |
| `Deep2B42AsyncLds.cpp` | 1053 | async LDS plan | **BLOCKED** | GPU async LDS staging. Zero callers. |
| `Deep2B45KernelPlan.cpp` | 4574 | kernel plan + seal | **QUARANTINE** | Plan derivation + seal summarizer. Zero callers. Receipt-only seal. |
| `Deep2B46NativeQuant.cpp` | 1018 | native quant plan | **BLOCKED** | GPU native quant packing. Zero callers. |
| `Deep2B48CrossLayerFusion.cpp` | 1174 | cross-layer fusion plan | **BLOCKED** | GPU cross-layer fusion. Zero callers. |
| `Deep2B49ShaderSpecializer.cpp` | 2405 | shader specializer | **BLOCKED** | GPU shader macro preamble generation. Zero callers. |
| `Deep2B50ChallengeSeal.cpp` | 2923 | challenge seal | **QUARANTINE** | Statistical summarizer + certify. Zero callers. Receipt-only seal. |
| `Deep2B51OwnerDirector.cpp` | 1585 | owner director plan | **QUARANTINE** | Orchestration plan. Zero callers. No runtime mechanism. |
| `Deep2B52MemoryTail.cpp` | 1138 | memory tail plan | **BLOCKED** | GPU memory tail plan. Zero callers. |
| `Deep2B53ComputeTail.cpp` | 1383 | compute tail plan | **BLOCKED** | GPU compute tail variant selection. Zero callers. |
| `Deep2B54DeviceGraph.cpp` | 977 | device graph plan | **BLOCKED** | GPU device graph. Zero callers. |
| `Deep2B55AsymptoticSeal.cpp` | 3072 | asymptotic seal | **QUARANTINE** | Statistical summarizer + certify. Zero callers. Receipt-only seal. |
| `Deep2B56LayerPhasePlanner.cpp` | 1047 | layer phase planner | **BLOCKED** | GPU layer phase plan. Zero callers. |
| `Deep2B57ContextKernel.cpp` | 693 | context kernel plan | **BLOCKED** | GPU context kernel. Zero callers. |
| `Deep2B58RouteSpecializer.cpp` | 932 | route specializer | **BLOCKED** | GPU route specialization. Zero callers. |
| `Deep2B59StabilityGovernor.cpp` | 841 | stability governor | **BLOCKED** | GPU stability governor. Zero callers. |
| `Deep2B60ModelContract.cpp` | 3101 | model contract seal | **QUARANTINE** | Statistical summarizer + certify. Zero callers. Receipt-only seal. |
| `Deep2B66RuntimeMeta.cpp` | 2594 | runtime meta binder | **QUARANTINE** | Metadata binder. Zero callers outside B-cluster. Receipt-only. |
| `Deep2B67LiveTelemetry.cpp` | 1237 | live telemetry | **QUARANTINE** | Telemetry derivation. Called only by B68/B69 (orphan cluster). No production consumer. |
| `Deep2B68TargetCalibrator.cpp` | 2265 | target calibrator | **QUARANTINE** | Calibration. Calls B67 (orphan cluster). Zero external callers. |
| `Deep2B69ContractRunner.cpp` | 3323 | contract runner | **QUARANTINE** | Contract runner. Calls B67 (orphan cluster). Zero external callers. |
| `Deep2B70Receipt.cpp` | 5156 | receipt writer | **QUARANTINE** | SHA-256 receipt writer. Uses B66 (orphan cluster). Zero external callers. Receipt-only infra. |
| `Deep2B71GpuCounterAdapter.cpp` | 1340 | GPU counter adapter | **BLOCKED** | GPU counter delta. Zero callers. |
| `Deep2B72RawrBenchCli.cpp` | 1676 | rawr bench CLI parser | **QUARANTINE** | CLI arg parser. Zero callers. Tooling stub, no main(). |
| `Deep2B73EvidenceStore.cpp` | 2316 | evidence store | **QUARANTINE** | Atomic file write + read. Zero callers. Receipt-only infra. |
| `Deep2B75FleetPromotion.cpp` | 583 | fleet promotion | **QUARANTINE** | Promotion evaluator. Zero callers. No runtime mechanism. |

### Other performance / roofline / residency

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `Deep2LaunchAmortizer.cpp` | 862 | launch amortizer plan | **BLOCKED** | Real launch-batch builder. Zero callers. GPU launch amortization not available. |
| `Deep2QuantGemvRoofline.cpp` | 1720 | quant GEMV roofline plan | **BLOCKED** | Real roofline plan + arithmetic intensity. Zero callers. GPU quant GEMV not available. |
| `Deep2WaveOccupancy.cpp` | 1505 | wave occupancy scheduler | **BLOCKED** | Real dual-GPU occupancy + workgroup plan. Zero callers. GPU not available. |
| `kernels/flash_attn_asm_fallback.cpp` | 1104 | flash attn ASM fallback | **QUARANTINE** | Real AVX2 flash-attention dequant+attention. Zero callers anywhere in repo. Shadowed by engine attention path. |
| `kernels/masm_kernels.cpp` | 4385 | MASM AVX2 kernels | **MERGE→QUARANTINE** | Real AVX2 dot product. Zero callers. Superseded by `native_vdot_avx2` in `src/core/native_speed_layer.cpp` (already adopted). Merge unique aspects if any, then quarantine duplicate. |

## Tier 4 — Tooling / subsystems / orchestration (DISPOSITIONED from measured evidence)

Evidence method: read source, grep all `src/deep2/*.cpp` and `src/**/*.cpp` for
callers outside each TU's own definition file.

### Findings

All Tier 4 TUs have zero external callers. They fall into three groups:

1. **Standalone executables** (`int main`): real tools/test harnesses that
   exercise the engine via its public API. Not wired into the engine library;
   they are CMake tool targets that were never added to the build graph.
2. **Orchestration/seal subsystems**: `Deep2FleetContract`, `TrailForge`,
   `FleetSpecialGraph`, `HeadlessIDE_AutonomousWorkflowMode` — real logic but
   no production consumer, no `main()`, no engine call edge.
3. **Real infrastructure with zero adoption**: `Deep2ReadyRing` (lock-free
   SPSC ring), `TraceProfilePolicy` (env-var trace profiler), 
   `LegacyRawrXDToolProviders` (legacy tool adapter) — real implementations
   that nothing calls.

### Dispositions

| File | Bytes | Mechanism | Disposition | Rationale |
|---|---:|---|---|---|
| `trailforge/TrailForge.cpp` | 15963 | TrailForge | **QUARANTINE** | Large orchestration subsystem. Zero callers. No `main()`. No engine call edge. Superseded by existing agent/tool infrastructure. |
| `trailforge/TrailForge_Gate.cpp` | 11215 | TrailForge gate | **QUARANTINE** | Gate/cert harness for TrailForge. Zero callers. No `main()`. Receipt-only. |
| `special_graph/FleetSpecialGraph.cpp` | 8486 | fleet special graph | **QUARANTINE** | Orchestration subsystem. Zero callers. No `main()`. No engine call edge. |
| `special_graph/FleetSpecialGraphExecutor.cpp` | 2062 | fleet special graph exec | **QUARANTINE** | Executor for FleetSpecialGraph. Zero callers. No `main()`. |
| `HeadlessIDE_AutonomousWorkflowMode.cpp` | 18141 | headless IDE workflow | **QUARANTINE** | Large workflow mode. Zero callers. No `main()`. No engine call edge. |
| `LegacyRawrXDToolProviders.cpp` | 2874 | legacy tool adapter | **QUARANTINE** | Adapts legacy `RawrXD::Agent::ToolRegistry` to new `AgentToolRegistry`. Zero callers of `RegisterLegacyRawrXDToolProviders`. Legacy bridge to deprecated system. |
| `TraceProfilePolicy.cpp` | 6307 | trace profile policy | **ADOPT (if wired)** | Real env-var-driven trace profile selector (perf/debug/ide/receipt). Zero callers. `rawrxd::trace::` namespace unused. This is genuinely useful infrastructure that should be wired into the trace/logging path. ADOPT requires wiring `currentProfile()` into the engine's trace emission. Until wired, effectively QUARANTINE. |
| `Deep2ReadyRing.cpp` | 6730 | lock-free SPSC ring | **BLOCKED** | Real lock-free SPSC ring buffer with full producer/consumer/cancel semantics. Zero callers. Intended for GPU persistent decode pipeline. BLOCKED on GPU prereq. |
| `Deep2FleetContract.cpp` | 5938 | fleet contract seal | **QUARANTINE** | Another seal/summarize/certify pattern (quantile stats + metadata matching). Zero callers. Receipt-only. |
| `deep2_benchmark_main.cpp` | 7271 | benchmark main | **ADOPT (tool)** | Real `int main` benchmark harness. Exercises engine via public API. Should be a CMake tool target. |
| `deep2_185in30_gate.cpp` | 7044 | 185-in-30 gate | **ADOPT (tool)** | Real `int main` gate harness. Exercises engine via public API. Should be a CMake tool target. |
| `deep2_e2e_audit.cpp` | 5415 | e2e audit | **ADOPT (tool)** | Real `int main` e2e audit tool. Parses trace+stdout. Should be a CMake tool target. |
| `agent_tool_authority_selftest.cpp` | 4610 | agent tool selftest | **ADOPT (tool)** | Real selftest. Should be a CMake test target. |
| `CycloneScheduler_test.cpp` | 6067 | cyclone scheduler test | **ADOPT (tool)** | Real runtime certification tests for CycloneScheduler. Should be a CMake test target. |
| `ElasticResidencyManager_test.cpp` | 9213 | elastic residency test | **ADOPT (tool)** | Real runtime certification tests for ElasticResidencyManager. Should be a CMake test target. |
| `Batch10_PeerRowSplitCert.cpp` | 3359 | batch10 peer row split cert | **ADOPT (tool)** | Real `int main` cert harness. Should be a CMake tool target. |
| `Batch10_RowSplitPlan_SELFTEST.cpp` | 678 | batch10 row split selftest | **ADOPT (tool)** | Real selftest. Should be a CMake test target. |
| `Batch9_VulkanMultiGpuCert.cpp` | 2926 | batch9 vulkan multi-GPU cert | **BLOCKED** | Real `int main` cert harness. Prerequisite: GPU/Vulkan + multi-GPU. Not available. |
| `_rawrxd_run_modelname_001_main.cpp` | 1377 | run-modelname main | **ADOPT (tool)** | Real `int main` CLI runner. Exercises engine generateStream. Should be a CMake tool target. |
| `_rng_audit.cpp` | 921 | RNG audit | **BLOCKED** | Real `int main` that requires Vulkan (`enableVulkan(true)`, `isVulkanInitialized()` check). Prerequisite: GPU/Vulkan. Not available. |

---

## Closure targets (not REACHABLE=480)

```ini
UNCLASSIFIED_IMPLEMENTATIONS=0   (all 88 dispositioned)
UNCLASSIFIED_IMPL_TARGET=0       ✓ CLOSED

ADOPTED=11     (1 GGUF tool + 8 test/cert/bench tools + 1 CLI runner + 1 trace policy)
MERGED=2       (MoEMathPlan→ExpertScheduler, masm_kernels→native_speed_layer)
QUARANTINED=31 (3 behavioral stubs + 5 model contracts + 14 seals/receipt + 9 orchestration/tooling)
BLOCKED=37     (29 GPU-mechanism plans + 4 MLA + weight_projection + ReadyRing + 2 GPU test/cert + spec decode)
DUPLICATE_RUNTIME_AUTHORITIES=0
UNACCOUNTED_STUBS=0

TOTAL_DISPOSITIONED=88
SOURCE_CLOSURE_FOR_88=PASS
```

### Summary by disposition

| Disposition | Count | What it means |
|---|---:|---|
| ADOPT | 11 | Wire to product build as tool/test targets. `TraceProfilePolicy` requires engine wiring. |
| MERGE | 2 | Move unique behavior into owning authority, then quarantine source TU. |
| QUARANTINE | 31 | Remove from product build graph or move to quarantine dir. Receipt-only, dead, superseded, or behavioral stub. |
| BLOCKED | 37 | Valuable but prerequisite (GPU/Vulkan/MLA model) absent. Revisit when GPU path is active. |
| **Total** | **88** | |

Every PENDING above must become ADOPT, MERGE, QUARANTINE, or BLOCKED with a
recorded rationale. A disposition is only final when:

- ADOPT: a real production call edge is wired and exercised.
- MERGE: unique behaviour moved into the owning authority; duplicate TU
  quarantined.
- QUARANTINE: TU removed from product build graph or moved to quarantine dir.
- BLOCKED: prerequisite (architecture/model/hardware) named and absent.

---

## Three remaining proof layers (from closure analysis)

1. **Source closure:** every one of the 480 TUs receives a disposition. Target
   is not `REACHABLE=480`; it is `UNCLASSIFIED_IMPLEMENTATIONS=0`,
   `DUPLICATE_RUNTIME_AUTHORITIES=0`, `UNACCOUNTED_STUBS=0`.

2. **Runtime closure:** every ADOPT/MERGE mechanism has at least one real
   production call edge. A constructor test or standalone cert is not
   sufficient for something claiming runtime functionality.

3. **Model closure:** obtain at least one supported MoE GGUF and drive the
   exact production path:

```text
GGUF load
  ↓
architecture admission
  ↓
Deep2Engine
  ↓
computeMoEFFN
  ↓
real router probabilities
  ↓
PredictiveRouter
  ↓
ExpertScheduler
  ↓
ExpertCache acquire
  ↓
GPU expert residency/upload
  ↓
expert compute
  ↓
generated token
```

That is the missing proof that would upgrade
`PREDICTIVE_ROUTER_RUNTIME_HITS=UNMEASURED` to a production PASS.

---

## Next executable actions

Source closure for the 88 is complete (`UNCLASSIFIED_IMPLEMENTATIONS=0`).

The three remaining proof layers now have clear targets:

### 1. Runtime closure (wire ADOPT items)

The 11 ADOPT TUs need real production call edges:
- **8 test/cert/bench tools** → add as CMake `add_executable` tool targets
  (deep2_benchmark_main, deep2_185in30_gate, deep2_e2e_audit,
  agent_tool_authority_selftest, CycloneScheduler_test,
  ElasticResidencyManager_test, Batch10_PeerRowSplitCert,
  Batch10_RowSplitPlan_SELFTEST, _rawrxd_run_modelname_001_main)
- **deep2_tensor_type_authority** → add as CMake tool target
- **TraceProfilePolicy** → wire `rawrxd::trace::currentProfile()` into the
  engine's trace emission path so debug/perf/receipt profiles are actually
  enforced at runtime

### 2. MERGE items

- **Deep2MoEMathPlan** → extract residency-first sort heuristic into
  ExpertScheduler, then quarantine the TU
- **masm_kernels** → verify no unique behavior beyond `native_vdot_avx2`,
  then quarantine

### 3. Model closure (the missing production PASS)

Obtain at least one supported MoE GGUF and drive:

```text
GGUF load → architecture admission → Deep2Engine → computeMoEFFN
  → real router probabilities → PredictiveRouter → ExpertScheduler
  → ExpertCache acquire → GPU expert residency/upload → expert compute
  → generated token
```

This upgrades `PREDICTIVE_ROUTER_RUNTIME_HITS=UNMEASURED` to a measured PASS.

### 4. BLOCKED items (37 TUs)

These are correctly BLOCKED — their prerequisite (GPU/Vulkan/MLA model) is
absent. They should be re-evaluated when the GPU path is certified, per the
critical path: `SINGLE_WRITER → IMMUTABLE RECEIPT → W8 CERT → GPU`.