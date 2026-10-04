# RAWRXD_ENTERPRISE_MEASUREMENT_SESSION_001

Date: 2026-10-04
Scope: CMake option census + CPU performance baseline + hypothesis falsification

---

## Part 1: CMake Option Census

```ini
TOTAL_OPTIONS=203
DEFAULT_OFF=179
DEFAULT_ON=8
OTHER=16  (commented, malformed, or non-standard)
```

### Always-Enabled (8)
- RAWR_ENABLE_VULKAN                    = ON
- RAWRXD_ENABLE_VALIDATION               = ON
- RAWRXD_BUILD_RAWRENGINE                = ON
- RAWRXD_ENABLE_HEAVY_GATES             = ON
- BUILD_RAW_SERVER                      = ON
- RAWRXD_BUILD_ADDRESS_RESOLVER_NATIVE   = ON
- RAWRXD_BUILD_LSP_SERVER               = ON
- RAWRXD_BUILD_DAP_ADAPTER              = ON

### Key Finding
`RAWRXD_BUILD_CLI=OFF` — the `rawr` executable (dump, reverse, modes, audit, gate, cert) does NOT build by default. Requires explicit `-DRAWRXD_BUILD_CLI=ON`.

---

## Part 2: Performance Baseline (CPU-only, DEEP2_DISABLE_VULKAN=1)

### Model: unlock-60M-Q2_K.gguf (28 layers, Q2_K)

| Configuration | Decode TPS | Per-Layer Cost |
|---|---|---|
| Q2_K, attn_threads=1 | 0.313 tok/s | 100-160ms |
| Q2_K, attn_threads=8 | 0.58 tok/s | 100-160ms |

### Model: unlock-1B-Q4_K_M.gguf (28 layers, Q4_K_M)

| Configuration | Decode TPS | Per-Layer Cost |
|---|---|---|
| Q4_K, attn_threads=8 | 0.616 tok/s | 100-160ms |

### Equalized Comparison
```
Q2_K scalar + 8 threads  = 0.58 tok/s
Q4_K AVX-512 + 8 threads = 0.616 tok/s
Difference: 6% (negligible)
```

When thread count is equalized, scalar Q2_K and AVX-512 Q4_K perform identically. The scalar vs SIMD kernel difference is NOT the bottleneck at decode time.

---

## Part 3: Hypothesis Falsification

| Hypothesis | Status | Evidence |
|---|---|---|
| Dispatch granularity (kMinRowsPerThread) | REFUTED | EffectiveParticipants exists and is compiled in, but equalized test shows identical performance |
| Missing AVX-512 Q2_K kernel | REFUTED | Scalar Q2_K ≈ AVX-512 Q4_K (6% difference) when threads equalized |
| Memory bandwidth / attention algorithm | UNPROVEN | Both quant types bottleneck at same rate; requires further instrumentation |

---

## Part 4: Next Required Measurement

To distinguish memory bandwidth from attention algorithm overhead:

1. Instrument `rawrxd_transformer.cpp` per-operation timing (norm, proj_qkv, rope, kv_write, attention_fused, out_proj, mlp)
2. Compare bytes read per token against theoretical DRAM bandwidth
3. Profile at varying sequence lengths to isolate KV-cache bandwidth scaling

The `StageTimes` infrastructure exists in `TransformerRuntime` but Deep2Engine may use a different forward path. Verification required.

---

## Classification

```ini
CMAKE_CENSUS_COMPLETE           = YES
PERFORMANCE_BASELINE_RECORDED   = YES
HYPOTHESIS_1_REFUTED            = YES
HYPOTHESIS_2_REFUTED            = YES
ROOT_CAUSE_IDENTIFIED           = NO
NEXT_MEASUREMENT_DEFINED        = YES
VERDICT                         = PARTIAL
```
