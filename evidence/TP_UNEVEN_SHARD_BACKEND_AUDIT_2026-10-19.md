# Uneven Tensor-Parallel Backend Audit

**Date:** 2026-10-19

**Audit baseline:** `93fe08748c` (`local-30b-backend`)

**Decision:** Gate 10 remains **NOT STARTED**. This is a source and hardware audit, not a tensor-parallel execution or performance receipt.

## Findings

- `vulkaninfo --summary` enumerated the AMD Radeon AI PRO R9700 and AMD Radeon RX 7800 XT as discrete Vulkan devices on this machine. It also listed the AMD integrated GPU and Microsoft D3D12/Dozen aliases. RawrXD's `VulkanCompute::EnumeratePhysicalDevices()` deduplicates physical devices before assigning its own ordinals.
- The active Deep2 execution path is Vulkan. `Deep2Engine::tryVulkanGEMV()` chooses one `VulkanCompute` instance for a weight based on its layer assignment, then dispatches that whole weight to that device. `Deep2MultiGpuLayerPlan` assigns contiguous layer ranges. This is layer parallelism; it does not split one matrix across devices.
- `src/deep2/MultiGPU/MultiGPUScheduler.h` declares `ExecutionMode::TENSOR_PARALLEL`, `tensorShard`, and `PlanTensorExecution()`, but the repository search found no implementation or call site for that mode. `ChoreographyResidencyLaw.hpp` currently emits `TENSOR_PARALLEL_ALLOWED=0` and `TP_SHARDS=1`.
- The generic `deep2_ops.comp` F32 GEMV uses `local_size_x = 64`, assigns one global invocation to each output row, and loops over all input columns. It is not a Tensor Core GEMM. Its odd-width cost must be measured on this shader and device; PTX/SASS or Tensor Core tiling claims do not describe this kernel. Other quantized GEMV shaders need separate inspection and measurements.
- Vulkan timing support writes calibrated GPU timestamp intervals. This change now records `queueSubmitCallNs` and `fenceWaitWallNs` separately in `GpuWorkInterval`; the fence wait overlaps GPU execution and must not be added to GPU time as if it were disjoint.
- The installed `DeepSeek-V2-Lite-Chat.Q4_K_M.gguf` reports hidden width 2048, FFN width 10944, 16 attention heads, 16 KV heads, key length 192, value length 128, and expert FFN width 1408. These listed dimensions divide evenly at TP=2, so this model alone cannot demonstrate a ragged 2-way split.

## First measured Vulkan microbenchmark

The new `tools/gpu_profiler/deep2_uneven_tp_gemv.cpp` benchmark ran 1,024-row deterministic F32 GEMVs for 30 measured iterations per shape. It sharded the columns across the R9700 and RX 7800 XT and reduced outputs on the host. The executable passed both CPU-reference and single-GPU Vulkan-reference comparisons with zero max absolute error in every case.

The R9700 median GPU time was 115.6 µs at local width 2048, 355.0 µs at width 2049, 353.5 µs when both ranks used width 2049, and 166.3 µs at width 2052. The repeated 2048 control returned to 106.0 µs. On the RX 7800 XT, width 2048 measured 142.8 µs, width 2049 measured 455.0 µs, and width 2052 measured 208.4 µs. This repeatable cliff is consistent with row-stride or access-pattern sensitivity in this shader, but it does not identify the hardware cause; AMD ISA and timeline tools were not installed for this run.

The raw timing receipt is `evidence/TP_UNEVEN_GEMV_2026-10-19.v2.receipt.txt`. It records device UUIDs, shard offsets and sizes, host dispatch, queue-submit API time, fence-wait wall time, calibrated GPU intervals, bytes, and parity. Fence-wait wall time overlaps GPU execution. Device allocator high-water was not instrumented, and the cross-device reduction is host-staged.

The engine smoke regression is `evidence/TP_UNEVEN_GEMV_ROOFLINE_REGRESSION_2026-10-19.receipt.txt`: the roofline target built and generated four TinyLlama tokens with exit code 0, `STRICT_VIOLATION=0`, and `PLANNED_CPU_GEMV=0`. It reported `GPU_DEVICES=1` and `FORWARD_LAYERS=0`, so this run is not multi-GPU or resident-forward certification.

Radeon GPU Profiler and Radeon GPU Analyzer were not installed on this host. Before attributing the width-2049 slowdown, repeat on alternate shape order and inspect the Vulkan shader ISA/timeline when AMD's tools are available. Add explicit planner coverage for `9 / 2 -> [5, 4]` and `9 / 4 -> [3, 2, 2, 2]`; the latter is planner-only on this two-discrete-GPU machine.

This host-reduced microbenchmark proves only sharded GEMV math and local timing. Gate 10 still requires a real inference graph with cross-device activation/reduction transfer, no CPU fallback, allocation high-water, and full-logit parity. The real DeepSeek-V2-Lite dimensions listed above divide evenly at TP=2, so the synthetic ragged widths remain necessary.

For AMD Vulkan, Radeon GPU Profiler is the timeline tool and Radeon GPU Analyzer can inspect Vulkan shader ISA. Nsight Systems, CUDA PTX/SASS, Triton, and NCCL environment variables do not profile RawrXD's current AMD Vulkan path. NCCL guidance should not assume that a collective will silently pad mismatched rank counts or fall back to point-to-point behavior; a ragged implementation needs explicit, compatible communication semantics.

## Evidence sources

- Hardware inventory: `vulkaninfo --summary` on 2026-10-19; AMD discrete devices reported as R9700 and RX 7800 XT.
- Shard placement: `src/deep2/Deep2Engine.cpp` (`tryVulkanGEMV`, `enableVulkan`) and `src/deep2/Deep2MultiGpuLayerPlan.cpp`.
- Tensor-parallel declaration and disabled policy witness: `src/deep2/MultiGPU/MultiGPUScheduler.h` and `src/deep2/ChoreographyResidencyLaw.hpp`.
- Generic F32 shader shape: `src/deep2/shaders/deep2_ops.comp`.
- Vulkan submit/timestamp accounting: `src/deep2/vulkan_compute.cpp` and `src/deep2/vulkan_compute.h` (`GpuWorkInterval`, `endSubmitWait`).
- AMD profiling references: [Radeon GPU Profiler](https://gpuopen.com/rgp/) and [Radeon GPU Analyzer](https://gpuopen.com/rga/).
- Collective count semantics: [NCCL collective API](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/api/colls.html).

## Receipt status

`SOURCE_AUDIT=PASS`

`VULKAN_DEVICE_ENUMERATION=PASS`

`UNEVEN_TP_GPU_BENCHMARK=PASS_MICROBENCH_ONLY`

`REAL_TENSOR_PARALLEL_EXECUTION=NOT_IMPLEMENTED`

`GATE_10=NOT_STARTED`
