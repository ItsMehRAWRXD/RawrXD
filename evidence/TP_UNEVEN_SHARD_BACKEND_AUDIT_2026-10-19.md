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

## Full width sweep and RGA analysis

Radeon GPU Analyzer 2.15.0.30 was downloaded from the official AMD GPUOpen release and its archive SHA-256 was verified. Its Vulkan SPIR-V offline mode produced ISA for `gfx1201` (R9700) and `gfx1101` (RX 7800 XT). The shader takes width in a runtime push constant, so both devices use one static ISA per ASIC for the sweep. The ISA includes scalar `buffer_load_b32` operations. Offline statistics report 34 SGPRs, 13 VGPRs, no SGPR/VGPR spills, no scratch memory, and no LDS use. RGA reports workgroup size and wavefront size as zero for this offline pipeline, so these outputs do not establish runtime occupancy. RGA offline compilation is static analysis, not a live Vulkan timeline capture.

The 30-repetition sweep covered 98 shapes: each local width from 2032 through 2080 with both an even split and a rank-0-plus-one ragged split. Every shape had zero maximum absolute error against both the CPU result and the single-GPU Vulkan result on both cards. On balanced cases, the median calibrated GPU time clustered by local width modulo four:

- R9700: mod 0 = 139.3 µs; mod 1 = 350.6 µs; mod 2 = 227.0 µs; mod 3 = 355.6 µs.
- RX 7800 XT: mod 0 = 167.5 µs; mod 1 = 453.5 µs; mod 2 = 288.6 µs; mod 3 = 453.7 µs.

A benchmark-only zero-padding experiment rounded each rank's physical GEMV weight stride up to four F32 elements, copied the real values, and appended zero weights; inputs remained logical-width. It used the existing production shader and preserved the logical shard widths. All 98 cases again passed CPU and single-GPU Vulkan comparisons with zero maximum absolute error. The balanced medians flattened to approximately 140 µs across mod classes on the R9700 and 169 µs on the RX 7800 XT. For a 2049-wide balanced shard, padding to 2052 changed R9700 GPU time from 353.9 to 168.2 µs and RX 7800 XT time from 445.4 to 203.9 µs. A width already aligned at 2052 stayed effectively unchanged (R9700 165.6 to 165.5 µs; RX 7800 XT 200.7 to 204.0 µs).

The modulo-four periodicity and its removal by zero-padding support row-stride sensitivity in this GEMV layout. They do not distinguish cache-sector behavior from a specific memory-bank conflict. No RGP live timeline or hardware counter capture was made. The initial padding result is a diagnostic microbenchmark, not a production tensor-parallel implementation; the final alignment comparison below supersedes its candidate timings.

## Stride-aware F32 view and alignment sweep

The Vulkan F32 GEMV path now accepts a `GpuWeightView::rowStride` that is separate from logical `cols`. `Deep2PadF32WeightView` creates an explicit owned view by copying logical weights and zero-filling the physical row tails. The shader indexes rows by physical stride and accumulates only through logical width; input vectors stay logical-width. Weight-cache identity includes the logical width and physical stride. Existing contiguous views retain `rowStride=0` behavior. The helper is opt-in and does not rewrite GGUF weights during model loading.

Four final isolated runs compared row-stride multiples 1, 4, 8, and 16 over the same 98 shapes, 1,024 rows, and 30 measured repetitions per shape. The analyzer validated each receipt against the source, benchmark executable, shader source, and SPIR-V hashes; every run passed 98/98 CPU parity, 98/98 single-GPU parity, and 98/98 zero-tail checks. The competing S12 benchmark process was absent immediately before and after each run. The machine-checkable summary is `evidence/TP_UNEVEN_STRIDE_LAYOUT_CERT_2026-10-19.md`, generated and validated by `scripts/summarize_deep2_gemv_stride.py`.

Across 49 balanced shapes, the median-of-shape-medians was 237.9/289.4 µs (R9700/RX 7800 XT) at stride multiple 1, 140.5/169.0 µs at 4, 121.6/144.2 µs at 8, and 114.5/138.5 µs at 16. At local width 2049, pad-16 measured 120.3 µs on the R9700 and 140.5 µs on the RX 7800 XT, versus 354.0 and 443.2 µs for contiguous rows: 2.94× and 3.15× faster in calibrated GPU execution time. The 16-element stride leaves only 1.2 µs and 0.4 µs max-minus-min spread across local-width modulo-four groups on the two GPUs. For 1,024 rows at width 2049, the physical stride grows to 2064, adding 61,440 bytes (about 0.73%) to the F32 weight rows.

This establishes pad-16 as the best candidate among the four tested multiples, for this synthetic F32 workload and these two devices. It does not identify a hardware mechanism or establish performance for quantized production weights. RGA output is offline static analysis, not live occupancy or hardware counters. The strict single-R9700 TinyLlama compatibility smoke and its raw log/hash are recorded under `evidence/TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD16_RGA215/`; it preserved the prior four-token stream with 4,304 planned GPU GEMVs, zero planned CPU GEMVs, and zero strict violations. That smoke is not evidence that ordinary GGUF loading automatically pads rows.

The raw timing receipt is `evidence/TP_UNEVEN_GEMV_2026-10-19.v2.receipt.txt`. It records device UUIDs, shard offsets and sizes, host dispatch, queue-submit API time, fence-wait wall time, calibrated GPU intervals, bytes, and parity. Fence-wait wall time overlaps GPU execution. Device allocator high-water was not instrumented, and the cross-device reduction is host-staged.

The engine smoke regression is `evidence/TP_UNEVEN_GEMV_ROOFLINE_REGRESSION_2026-10-19.receipt.txt`: the roofline target built and generated four TinyLlama tokens with exit code 0, `STRICT_VIOLATION=0`, and `PLANNED_CPU_GEMV=0`. It reported `GPU_DEVICES=1` and `FORWARD_LAYERS=0`, so this run is not multi-GPU or resident-forward certification.

## Two-device inference smoke and regression

A controlled TinyLlama four-token run opened the R9700 and RX 7800 XT together under the existing **layer-parallel** policy. The plan assigned layers 0–10 to the R9700 and 11–21 to the RX 7800 XT. Per-device counters reported 2,148 and 2,154 successful Vulkan GEMVs respectively, with 4,302 planned GPU GEMVs, zero planned CPU GEMVs, and no strict-fallback violation. This demonstrates that both devices receive real model GEMV work in the current layer-parallel path; it does not demonstrate tensor-parallel sharding or a peer transfer.

The same fixed prompt, model SHA-256, greedy settings, and profiler executable were run once on the R9700 alone and once with both GPUs. The single-GPU stream was `6000 16000 16000 16000`; the two-device stream was `6000 20000 6000 6000`, so only the first of four tokens agreed. Decode rates were 0.1096 and 0.1520 tokens/sec, but the output mismatch and single sample make this unsuitable as a performance result. The engine emitted zero layer-completion and GPU-forward-layer counts in both profile witnesses despite 616 matching debug layer-enter/exit lines in the two-device run. The per-layer counters are therefore not usable as certification evidence yet.

This is a correctness regression in the existing two-device layer-parallel smoke path. It leaves Gate 10 **OPEN / NOT STARTED for tensor parallelism** and establishes a new blocker: compare full logits and trace the first divergence before attempting TP certification. The compact receipt is `evidence/TP_UNEVEN_MULTI_GPU_LAYER_SMOKE_2026-10-19.receipt.txt`; its raw logs are in the ignored `build_modelroute/receipts/` directory and are identified by SHA-256 in the receipt.

Radeon GPU Analyzer is available from the verified 2.15.0.30 package and its offline Vulkan ISA/statistics are recorded above. Radeon GPU Profiler was not installed, so there is no live timeline or hardware-counter capture. A live RGP capture and alternate-order replay could further test stability and distinguish address alignment from cache/partition behavior. Add explicit planner coverage for `9 / 2 -> [5, 4]` and `9 / 4 -> [3, 2, 2, 2]`; the latter is planner-only on this two-discrete-GPU machine.

This host-reduced microbenchmark proves only sharded GEMV math and local timing. Gate 10 still requires actual tensor-parallel matrix sharding, cross-device activation/reduction transfer, no CPU fallback, allocation high-water, and full-logit parity. The real DeepSeek-V2-Lite dimensions listed above divide evenly at TP=2, so the synthetic ragged widths remain necessary.

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

`WIDTH_SWEEP_AND_ZERO_PAD_EXPERIMENT=PASS_MICROBENCH_ONLY`

`TWO_GPU_LAYER_PARALLEL_SMOKE=EXECUTED_BUT_GREEDY_PARITY_FAIL`

`REAL_TENSOR_PARALLEL_EXECUTION=NOT_IMPLEMENTED`

`GATE_10=NOT_STARTED`
