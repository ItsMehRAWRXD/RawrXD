# RAWRXD One-Pass Completion — Engineering Handoff

Baseline branch: `feat/hexmag-polymorphic-repeat-tuner-masm` @ `43dc3f2673`
Model: `DeepSeek-V2-Lite-Chat.Q4_K_M.gguf`, sha256 `5d33e5f045c7a03351c319aafc8afdad94b69d07bb68f36dc9bb5af340b343a4`
Certificates held: `RAWRXD_CORE_DLL_NATIVE_E2E_001` (17/17), `RAWRXD_STREAM_CANCEL_001`,
`RAWRXD_DEEPSEEK_TOKENIZER_PARITY_001`, `RAWRXD_REFERENCE_REPRODUCIBILITY_001`.

Two coordinated workstreams. The product workstream certifies against the **existing CPU
Deep2 runtime** and does NOT wait on GPU work; the GPU workstream converges at release.

## Workstream A — GPU inference correctness

### Verified facts (this session)
- Native Vulkan devices: **GPU0 = AMD Radeon AI PRO R9700 (apiVersion 1.4.349, native AMD
  ICD)**; GPU2 = integrated Radeon (1.4.315); GPU1/3/4 = D3D12 wrappers.
- **The RX 7800 XT does not enumerate as a native Vulkan physical device.** Windows sees the
  adapter, the AMD Vulkan ICD does not. `RAWRXD_HETEROGENEOUS_GPU_COMPLETE_001` is blocked
  until an AMD driver/ICD exposes it (verify with: `vulkaninfo | Select-String "GPU id"`).
  AdapterRAM in Win32_VideoController is a Windows reporting limitation; use
  `VkPhysicalDeviceMemoryProperties` heaps for real VRAM.
- Q4_K GPU kernel state (`certs/rawrxd_kva_q4k_spv_001.cpp`): source + SPV + registry entry
  exist, but `KVA_Q4K_PARITY=0` and `KVA_Q4K_MEASURED=0` — **no numerical parity evidence**.
  Treat as scaffold only.

### Stage A1 — quantized kernels (`RAWRXD_VULKAN_KERNEL_COMPLETE_001`)
Owned sources: `src/backend/*.comp|*.spv`, `src/backend/VulkanGemmDispatcher.{cpp,hpp}`,
`src/vulkan_compute.cpp`, `src/agentic/vulkan_compute_real.cpp`.
Do not fork a second engine — extend the existing dispatcher.
Implement + validate against an independent CPU reference (the certified
`ModelGenieExecutor` CPU path is the reference oracle):
1. `gemv_q4k` (Q4_K × Q8_K) and `gemv_q6k` (Q6_K × Q8_K) dot products: block layout,
   `d`/`dmin` scales, 256-element super-blocks, sign extension, FP32 accumulation.
2. Tensor primitives: RMSNorm, RoPE (must preserve the 65/65 bitwise CPU/GPU RoPE
   regression), softmax, attention-value aggregation, SiLU, residual add.
3. MoE: routing, TopK, expert execution, weighted aggregation.
4. Shapes/strides/partial blocks/memory boundaries; validation layers with zero unexpected
   errors; both physical AMD devices once the 7800 XT enumerates.
Acceptance: per-kernel table (kernel, shape, max abs diff vs CPU, cos, PASS/FAIL); source
hashes and process evidence attached. A kernel PASS never counts as a layer PASS.

### Stage A2 — single-GPU Layer 0, then full model (`RAWRXD_DEEP2_GPU_PRODUCTION_001`)
Route Layer 0 projections → RMSNorm → attention/softmax/values → MoE → residuals → KV
updates through Vulkan; certify Layer-0 intermediates against CPU; extend to all 27 layers,
output projection, logits; preserve tokenizer/sampling/streaming/cancel; every routing
decision observable (no hidden CPU); benchmark prefill/decode/TTFT/VRAM; 150 TPS only
after numerical correctness.

## Workstream B — autonomous product (certifiable on CPU Deep2)

### Stage B1 — CLI build (`RAWRXD_CLI_BUILD_001`)
Done so far: configure passes from a clean checkout of `43dc3f2673`
(`cmake -S <wt> -B <wt>/build_ide2 -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release`);
11 legacy inference/stub sources removed from the `rawrxd` target (`43dc3f2673`).
**Blocker, root-caused:** seven headers are corrupted placeholders containing git stderr
text instead of source — `src/sovereign/{AutoRepairEngine,Beaconism,ExpertCache,Fabric,
KVCache,VulkanCompute}.hpp` and `include/d2_material_overlap.h` (written by commit
`582fdbe36c`, whose recovery piped stderr into files). No reachable commit, branch, or
worktree holds their authentic content; history past `582fdbe36c` is missing objects
(`786acfad…`, `995393e0…`). They account for 732 of 2301 current errors.
Next action: reconstruct those seven headers from the symbol requirements in the compiler
diagnostics (or from off-repo backups); then re-run the build and re-count unique errors
against the 243-identifier / 2301-error baseline.
Build commands (MSVC x64, no Qt, no external deps):
```
cmake --build <wt>/build_ide2 --config Release --target rawrxd -- /m:4
```
MASM note: if `ml64` fails with `A1000 cannot open ... InferenceEngine.dir\Release\src/asm/...obj`,
create that directory (`build_ide2\InferenceEngine.dir\Release\src\asm`) and retry — the VS
project for the `rawrxd` target is named `InferenceEngine`.

### Stage B2 — HexMag + product (`RAWRXD_HEXMAG_LINK_CLOSURE_001`, `…_LIVE_SWARM_001`,
`RAWRXD_AGENT_RESILIENCE_PRODUCTION_001`, `RAWRXD_DEEP2_IDE_PRODUCTION_CLOSURE_001`,
`RAWRXD_PRODUCT_RELEASE_001`)
Link the real `CEOAgent`/`SubAgentManager`/`AgentOrchestrator`/`RealNativeToolExecutor`
(`src/agentic/`, `src/agent/`, `src/cli/swarm_orchestrator.h`); verify seven swarm strategies
and ten specialist types; exercise ConflictEngine/AdaptiveRetryEngine/DelegationManager
under injected failures; enforce quotas/depth/circuit breakers/cancellation/edit
preservation; connect generation to real file/terminal/compiler/linker/test/Git tools; run
plan → edit → build → test → repair → verify; build the Win32 IDE **without Qt**
(`RawrXD-Win32IDE` target — the sibling `.kilo/worktrees/ide-closure` reconstruction
requires Qt6 and must NOT be adopted); clean-machine release acceptance.

## Stop conditions (record, do not fake)
- Any certificate whose acceptance test has not executed → stays OPEN with the blocker named.
- The RX 7800 XT not Vulkan-enumerable → `RAWRXD_HETEROGENEOUS_GPU_COMPLETE_001` blocked.
- Q4_K/Q6_K parity unmeasured → no kernel PASS may be claimed.
- GPU numerical failure → fail first result; no correctness retries in the certification path.

## Ownership boundaries
- `src/core/dll/Deep2InferenceAdapter.{cpp,h}` and `tools/capture_native_logits.cpp` belong
  to a concurrent owner; do not restage or revert them.
- Sibling worktrees `.kilo/worktrees/ide-closure`, `.kilo/worktrees/thorn-measure`,
  `G:\rawrxd-push-tmp` are other sessions' — read only.
- Every new production source must be committed (no untracked production source).
