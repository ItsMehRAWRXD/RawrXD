# Uneven Tensor-Parallel Backend Audit

**Date:** 2026-10-19

**Repository revision:** `93fe08748c` (`local-30b-backend`)

**Decision:** Gate 10 remains **NOT STARTED**. This is a source and hardware audit, not a tensor-parallel execution or performance receipt.

## Findings

- `vulkaninfo --summary` enumerated the AMD Radeon AI PRO R9700 and AMD Radeon RX 7800 XT as discrete Vulkan devices on this machine. It also listed the AMD integrated GPU and Microsoft D3D12/Dozen aliases. RawrXD's `VulkanCompute::EnumeratePhysicalDevices()` deduplicates physical devices before assigning its own ordinals.
- The active Deep2 execution path is Vulkan. `Deep2Engine::tryVulkanGEMV()` chooses one `VulkanCompute` instance for a weight based on its layer assignment, then dispatches that whole weight to that device. `Deep2MultiGpuLayerPlan` assigns contiguous layer ranges. This is layer parallelism; it does not split one matrix across devices.
- `src/deep2/MultiGPU/MultiGPUScheduler.h` declares `ExecutionMode::TENSOR_PARALLEL`, `tensorShard`, and `PlanTensorExecution()`, but the repository search found no implementation or call site for that mode. `ChoreographyResidencyLaw.hpp` currently emits `TENSOR_PARALLEL_ALLOWED=0` and `TP_SHARDS=1`.
- The generic `deep2_ops.comp` F32 GEMV uses `local_size_x = 64`, assigns one global invocation to each output row, and loops over all input columns. It is not a Tensor Core GEMM. Its odd-width cost must be measured on this shader and device; PTX/SASS or Tensor Core tiling claims do not describe this kernel. Other quantized GEMV shaders need separate inspection and measurements.
- Vulkan timing support already writes timestamp queries and records calibrated GPU intervals plus host submit-to-completion bounds. The generic `endSubmitWait()` does not currently expose the exact `vkQueueSubmit()` call duration or a separate fence-blocking duration. A benchmark must add or derive these fields carefully; raw fence wait overlaps GPU execution and must not be added to GPU time as if it were disjoint.
- The installed `DeepSeek-V2-Lite-Chat.Q4_K_M.gguf` reports hidden width 2048, FFN width 10944, 16 attention heads, 16 KV heads, key length 192, value length 128, and expert FFN width 1408. These listed dimensions divide evenly at TP=2, so this model alone cannot demonstrate a ragged 2-way split.

## Corrected profiling direction

Use a Vulkan-native uneven-shard GEMV benchmark on the R9700 and RX 7800 XT. Compare aligned and ragged cases on each device separately, then run a two-device split with deterministic inputs and compare the reduced result to a single-device reference. A useful first pair is a 4096-column matrix split `[2048, 2048]` versus a 4097-column matrix split `[2049, 2048]`. Include planner cases `9 / 2 -> [5, 4]` and `9 / 4 -> [3, 2, 2, 2]`; the latter is planner coverage only on this two-discrete-GPU machine.

Each measured shard should report device name/UUID, rows and columns, start offset, useful and padded elements, dispatch count, input/weight/output bytes, correctness error, calibrated GPU execution time, host API time, queue-submit call time, fence wait, and allocator/device-heap high-water marks. Compare each GPU against its own aligned control because the two cards have different performance. A host-reduced microbenchmark proves only the sharded kernel math; Gate 10 still requires the real inference graph, cross-device transfer/reduction path, no CPU fallback, and full-logit parity.

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

`UNEVEN_TP_GPU_BENCHMARK=NOT_RUN`

`REAL_TENSOR_PARALLEL_EXECUTION=NOT_IMPLEMENTED`

`GATE_10=NOT_STARTED`
