# Deep2 diagnostic batch-boundary correction — 2026-10-20

## Finding

`RR_GPU_CHECK=1` disabled executor-side batch joining in `OpLinear`, but the lower-level `QuantDot::DotBlocked` queue predicate still observed the global batch as active. It returned `true` while leaving the output vector untouched until `EndBatch`, so the per-op checker compared zero-filled output against the CPU reference and reported false `gpu=0` divergences.

## Correction

When `RR_GPU_CHECK` is set, `BeginBatchImpl` and `EndBatchImpl` become logical no-ops and `DotBlocked` executes synchronously. This preserves the diagnostic contract: every comparison observes a completed GPU result. Normal production batching is unchanged when the environment variable is absent.

## Validation

- Release targets: `deep2_exec_trace` and `deep2_gpu_certify` built successfully.
- Focused CTest: `deep2_qwen4exp_operator_gpu_probe` PASS; `deep2_generic_vulkan_quant_probe` PASS.
- Q5_K GPU certificate before this correction: GPU execution and zero CPU fallback observed; full independent parity remains unclosed.
- No physical-memory aliasing, ring-0 mapping, vulnerable-driver, or queue-dependency bypass was introduced.

## Remaining boundary

This corrects the measurement race; it does not certify Q5_K or Qwen35 full-model numerical parity. The production path still requires a completed per-op parity trace and a full-model independent reference receipt before promotion.
