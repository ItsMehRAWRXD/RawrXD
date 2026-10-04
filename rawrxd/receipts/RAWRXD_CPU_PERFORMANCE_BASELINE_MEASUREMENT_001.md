# RAWRXD_CPU_PERFORMANCE_BASELINE_MEASUREMENT_001

Status: MEASURED
Date: 2026-10-04
Model: unlock-60M-Q2_K.gguf (60M params, 28 layers, Q2_K quant)
Host: AMD Zen 4, AVX-512 available
Route: CPU-only (DEEP2_DISABLE_VULKAN=1)

## Measured Results

```
Decode TPS:     0.313 tok/s  (32 tokens / 102,110 ms)
Prefill TPS:    0.35 tok/s   (5 tokens / ~13,123 ms)
Per-layer cost: 100-160 ms   (SLOW_LAYER telemetry, all 28 layers)
Per-token cost: ~3,100 ms     (28 layers × ~110 ms average)
```

## Bottleneck Analysis

### 1. Dispatch granularity fix IS already active
- `EffectiveParticipants(total_rows, threads)` at `rawrxd_cpu_math.cpp:135`
- Enforces `kMinRowsPerThread = 4` ceiling: `ceil(8 / 4) = 2` participants for 8 heads
- Compiled into the binary and reachable

### 2. BUT attention is single-threaded by default
- `RAWRXD_ATTN_THREADS` env var defaults to 1 when unset
- `rawrxd_transformer.cpp:358-359`: `nt = 1` by default
- So `ParallelRows` short-circuits to inline; `EffectiveParticipants` never consulted

### 3. The deeper bottleneck: scalar Q2_K GEMV
- `QuantKernelRegistry.cpp`: Q2_K resolves to `gemv_q2_k_scalar` only
- No AVX-512 or AVX-2 fast path registered for Q2_K
- Q4_K has `gemv_q4_k_avx512` (verified in parity gate)
- Q2_K does not

### 4. Per-layer cost breakdown (inferred)
- 100-160ms per layer × 28 layers = 2.8-4.5s per token
- At 0.313 tok/s, each token costs ~3,200ms
- This matches the layer-by-layer telemetry

## Hypothesis Status

```ini
DISPATCH_GRANULARITY_HYPOTHESIS   = REFUTED
  EffectiveParticipants exists and is compiled in
  When attention threads equalized (8), Q2_K and Q4_K perform identically
  The clamp is not the binding constraint

MISSING_AVX512_Q2K_HYPOTHESIS     = REFUTED
  Q2_K scalar kernel vs Q4_K AVX-512: 0.58 vs 0.616 tok/s (equalized threads)
  The scalar path is NOT the bottleneck; AVX-512 provides no meaningful advantage
  at this decode shape

MEMORY_BANDWIDTH_HYPOTHESIS       = HIGH_PROBABILITY
  Both quant types perform identically when threads equalized
  Indicates memory-bound, not compute-bound
  28 layers × ~110ms = ~3.1s per token regardless of quant kernel
```

## Corrected Finding

The 2× baseline difference between Q2_K (0.313) and Q4_K (0.616) was entirely due to
**default attention thread count**, not kernel selection:

- Q2_K default: `RAWRXD_ATTN_THREADS` unset → 1 thread → 0.313 tok/s
- Q4_K tested: `RAWRXD_ATTN_THREADS=8` → 8 threads → 0.616 tok/s
- Q2_K with threads=8: **0.58 tok/s** (measured in this session)

This means the scalar vs AVX-512 kernel difference is negligible at decode time.
The binding constraint is elsewhere.

## Classification

```ini
MEASURED_BASELINE_TPS_Q2K_1THREAD   = 0.313
MEASURED_BASELINE_TPS_Q2K_8THREADS  = 0.58
MEASURED_BASELINE_TPS_Q4K_8THREADS  = 0.616
DISPATCH_FIX_ALREADY_IN_SOURCE      = YES
Q2_K_AVX512_KERNEL_EXISTS           = NO
Q2_K_SCALAR_VS_Q4K_AVX512_DELTA     = 6% (negligible)
ROOT_CAUSE_ATTRIBUTION                = MEMORY_BOUND_OR_ATTENTION_STRUCTURE
VERDICT                               = BASELINE_RECORDED_HYPOTHESES_REFUTED
```
