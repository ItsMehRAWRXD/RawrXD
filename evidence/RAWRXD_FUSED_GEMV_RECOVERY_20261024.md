# RAWRXD_FUSED_GEMV_RECOVERY_20261024

Status: SOURCE_PORT_PROPOSED / BUILD_PENDING / GPU_TOKEN_PARITY_PENDING / TPS_UNMEASURED.

Base: `feature/reap-deepseek-671b-150tps` at `3083edf6b6d226c335181ea21f80549adc6ee478`.
Source donor: `perf/deep2-fused-host-gemv-20261020`. No full-file donor replacement.

## Source modifications

- `src/deep2/vulkan_compute_engine_adapter.cpp`: port fused host F32 and quantized GEMV operations, with quant type 13 kept in the admissible list because it is supported by the current backend.
- `src/deep2/vulkan_compute_adapter_fused.cpp`: port fused Q4_K batch-1 and Q6_K host operand operations.
- `src/deep2/vulkan_compute.cpp`: snapshot q4kLane_ **before** assigning the dual lane tag to prevent restoration of the wrong lane at function exit.
- `tests/fused_host_gemv_source_contract.py`: source contract only; checks four adapter paths and lane save/restore order, not runtime correctness.
- `.github/workflows/deep2-fused-compat-admission.yml`: source gate and Windows x64 compile/link gate.

## Required promotion gate — do not mark PASS without receipts

1. Windows CI compile/link passes and touched Vulkan adapters are confirmed compiled in GPU-capable configuration.
2. On R9700 and RX 7800 XT, Q4_K/Q5_K/Q6_K/F32 independent-oracle outputs are numerically compared with the pre-port baseline.
3. Capture submission count, fence wait time, GPU times and transfer bytes before/after on identical warmed input.
4. Run multi-token model decode with deterministic seeds; compare logits/tokens, no unplanned fallbacks, and source-revision receipt.
5. Measure paired single-stream decode TPS (32/128/256 tokens), p50/p95 latency and thermal conditions on the same models; **150 TPS is a goal, not a measured result**.
6. Do not merge this experimental recovery to the canonical baseline or the default branch until those gates pass.

GitHub-hosted Windows runners are CPU-only for this GPU validation. A dedicated self-hosted dual AMD runner is necessary for actual throughput measurements.
