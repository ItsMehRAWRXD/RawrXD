# Deep2 100+ TPS decode-path audit — 2026-10-20

Status: **SOURCE_CHANGE_COMMITTED / STATIC_CONTRACT_CHECK_PASS / GPU_BENCHMARK_NOT_RUN / TPS_UNVERIFIED / FULL_MODEL_CERTIFICATION_UNCHANGED**.

## Evidence boundary

Source baseline: `28dbd46b79bd6b010f65e7e2e730a510e85b3438` (Oct. 20 Deep2 lineage, not default `main`).
Work branch: `perf/deep2-fused-host-gemv-20261020`. This work is **not merged** to `main`.
No models, source histories, or evidence files were deleted. No R9700/Vulkan or Qwen benchmark was launched.

## Concrete cause and corrected implementation

The engine-facing adapter previously performed three independent synchronous Vulkan submissions per warm host-operand GEMV:

1. `UploadVector`: staging-to-GPU copy and fence wait.
2. `DispatchGemvDevice`/`DispatchGemvQuant`: compute and fence wait.
3. `DownloadVector`: GPU-to-staging copy and fence wait.

The production backend already provides `RunWeightHostRoundTrip` for the same workload. It records the staging upload, weight dispatch, output download, and requisite barriers into a single fused command buffer, followed by one `EndFusedLayer` fence wait. The patches connect the previously bypassing CPUInference adapter to that existing backend.

- `src/deep2/vulkan_compute_engine_adapter.cpp`: route the existing F32 and explicitly supported quantized dispatch types through `RunWeightHostRoundTrip`, preserving caller semantics and backend counters. Reject other types rather than choosing a guess.
- `src/deep2/vulkan_compute_adapter_fused.cpp`: route Q4_K batch=1 through existing `RunWeightHostBatchQ4K` and Q6_K through `RunWeightHostRoundTrip`.
- `src/deep2/vulkan_compute.cpp`: snapshot the previous profiling lane tag before setting dual-lane mode; restore it at all four exits. Previous RAII initialization saved the new tag and never restored the original.

Expected benefit: fewer Vulkan submissions and CPU fence waits for the affected **host-operand compatibility path**. This does **not** prove any TPS value, GPU-only tensor residency across layers, or correctness for unsupported architectures. Other paths already use fused command buffers, so this is not a global 3x speedup.

## Source-level checks completed

- Comparison against baseline reports exactly three modified files.
- Adapter no longer calls the old per-operation `UploadVector`/`DownloadVector` chain for these methods.
- Quant Q4_K/Q6_K dispatches use existing fused methods, with no invented kernel.
- Backend `RunWeightHostRoundTrip` records exactly one `BeginFusedLayer`/`EndFusedLayer` sequence around the operations.
- Four lane restoration sites now preserve the previous lane.
- Root CMake includes both engine adapter translation units.

No CMake/MSVC build, parity test, GPU measurement or full-model certification was performed here. Static inspection is **not** a substitute for build and GPU validation.

## Resume-only acceptance ladder (not executed)

1. Build `deep2_engine_lib` in Release using the same Windows MSVC/Vulkan configuration and confirm the adapter methods link.
2. Run direct Q4_K, Q6_K, and F32 independent oracle parity with zero host fallback.
3. Run full-model certification (tensor inventory, all requested positions, independent reference and finite-logit checks); **component parity is not full-model certification**.
4. After explicit user resume, collect per-token `QueueSubmitCount`, wall decode ms/token, GPU timestamp duration, wait times, weights uploaded, cold/hot cache hits, CPU fallback count, model size/quant and thermal/power.
5. Compare identical models, token counts, context sizes, seeds, sampling modes, and residency state to the unpatched build; report paired single-stream TPS, not synthetic kernel TPS. Stop/revert on parity regression.
6. Diagnose remaining roofline separately: for dense decode, `TPS <= sustained effective weight-memory bandwidth / bytes_read_per_token` before any compute or synchronization overhead. For MoE, use measured active experts and PCIe transfers, never total-on-disk bytes alone.

The R9700/Vulkan and Qwen benchmark pause remains in force until the user explicitly resumes it.
