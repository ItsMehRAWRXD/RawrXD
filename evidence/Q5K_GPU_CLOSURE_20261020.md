# Q5_K GPU closure attempt — 2026-10-20

## Scope

This receipt covers the native Deep2 quant-dot path for GGML `Q5_K` (type 13), including row-4 and row-8 Vulkan shaders. It is an execution-path receipt, not a full-model certification.

## Changes

- Added capability id `8` for `Q5_K` in the Deep2 executor and quant dispatcher.
- Added the GGML Q5_K row geometry (`176` bytes per 256 values) to host and Vulkan geometry checks.
- Added exact Q5_K scale/min, high-bit, and low-nibble decoding to `quant_dot_row8.comp` and `quant_dot_row4.comp`.
- Rebuilt row-4/row-8 SPIR-V variants and the `deep2_gpu_certify` / `deep2_exec_trace` targets.

## Evidence

Build:

```text
cmake --build F:\\rawrxd\\build --config Release --target deep2_gpu_certify deep2_exec_trace -- /m:1 /v:minimal
exit=0
```

Qwen3.5 40B one-token trace:

```text
ops_total=1059 ops_bound=1059 ops_unbound=0
weights_resolved=1275 weights_missing=0
unsupported_operations=0
[quant] w=blk.0.attn_qkv.weight kind=8 n_in=5120 n_out=10240 n_blk=20 rb=3520
cpu_operations=0
gpu_dispatches=1056
unexplained_fallbacks=0
backend_submits=1346 backend_waits=1346
backend_kernel_ms=1500.181 backend_gpu_ms=245.359
prefill_ms=25493.4
prefill_tps=0.04
FINAL_VERDICT=FAIL
```

The Q5_K projection reached the GPU path. The execution gate remains FAIL because the trace emits no independent reference receipt and the operation is dominated by host synchronization. `backend_waits` equals `backend_submits` for this one-token prefill.

Focused regression tests:

```text
ctest -R deep2_qwen4exp_operator_contract ... PASS
ctest -R deep2_generic_vulkan_quant_probe ... PASS
```

The full CTest battery remains red because several pre-existing executables are absent and H11 was invoked without its required model argument. Those failures are recorded rather than reclassified.

## Disposition

```ini
Q5K_GPU_DISPATCH = PASS
Q5K_CPU_FALLBACK = PASS_ZERO_IN_TRACE
Q5K_NUMERICAL_PARITY = NOT_RUN
QWEN35_FULL_MODEL = NOT_CERTIFIED
TPS_100_PLUS = NOT_ESTABLISHED
```

The next performance boundary is dependency-aware command submission and device-resident activation chaining. Removing the Q5_K fallback does not by itself eliminate the 1,346 fence waits observed in the trace.

Qwen3.5 one-token decode follow-up:

```text
decode_tokens=1
decode_ms=1056.7
decode_tps=0.946
cpu_operations_delta=0
gpu_dispatches_delta=818
backend_submits_total=2091 backend_waits_total=2091
FINAL_VERDICT=PASS
```

This is a functional GPU execution receipt for the exercised token, not a full-model parity certificate. It demonstrates that removing the Q5_K fallback is necessary but insufficient for high throughput: the decode path still performs one fence wait per submit and is far below 100 TPS.

## Q5_K high-bit plane correction — 2026-10-20 follow-up

Static comparison against the vendored GGML reference (`ggml_vec_dot_q5_K_q8_K_generic` and `dequantize_row_q5_K`) found that `qh` is a shared 32-byte plane; only `qs` advances by 32 bytes for each pair of 32-value groups. The CPU reference and all three Vulkan Q5_K decoders were corrected accordingly.

Build and shader compilation pass. A post-fix GPU differential run still reports a broader quant-dot parity failure in the current row-8 route (for example `blk.0.attn_q.weight` Q4_K: GPU row 337 = 0, CPU = -14.7562; Q5_K final logits remain `gpu_argmax=791`, `cpu_argmax=2`, cosine `0.9998509`, max absolute error `0.1466`). Therefore this correction is recorded as a source-level fix, not a numerical certification. The remaining row-kernel parity defect must be resolved before performance promotion.

```ini
Q5K_QH_LAYOUT = CORRECTED_AGAINST_GGML
Q5K_GPU_EXECUTION = PASS
Q5K_NUMERICAL_PARITY = FAIL
ROW8_QUANT_PARITY = FAIL
QWEN35_FULL_MODEL = NOT_CERTIFIED
```
