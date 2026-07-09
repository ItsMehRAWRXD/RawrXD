# Phase 16 — Kernel Attribution Profiling

## Status
**COMPLETE** ✅

## Purpose
Identify where the 452ms per token is spent before selecting optimization path.

---

## Methodology

Instrumented each major kernel in the generation pipeline:

1. Token Embedding
2. RMSNorm
3. QKV Projection
4. RoPE
5. Attention
6. FFN/SwiGLU
7. Output Projection
8. Sampling

Timer granularity: microseconds
Sample size: 10 tokens (sufficient for stable averages)

---

## Results

### Component Breakdown

| Component | Time (ms/token) | % of Total | Calls |
|-----------|-----------------|------------|-------|
| **Output Projection** | **423.97** | **47.3%** | 10 |
| **FFN/SwiGLU** | **343.59** | **38.3%** | 10 |
| **QKV Projection** | **129.33** | **14.4%** | 10 |
| Token Embedding | 0.02 | 0.0% | 10 |
| RMSNorm | 0.00 | 0.0% | 10 |
| RoPE | 0.04 | 0.0% | 10 |
| Attention | 0.03 | 0.0% | 10 |
| Sampling | 0.00 | 0.0% | 10 |
| **TOTAL** | **896.98** | **100%** | - |

### Top 3 Bottlenecks

```
1. Output Projection    423.97 ms  (47.3%)  ████████████████████
2. FFN/SwiGLU           343.59 ms  (38.3%)  ████████████████
3. QKV Projection       129.33 ms  (14.4%)  ██████
```

---

## Analysis

### Dominant Cost: Large Matrix Multiplications (GEMM)

**Output Projection**: [3072, 32064]
- 98.5M multiply-add operations
- 47.3% of total time
- **Primary bottleneck**

**FFN/SwiGLU**: [3072, 8192] × 2
- 50.3M multiply-add operations
- 38.3% of total time
- **Secondary bottleneck**

**QKV Projection**: [3072, 9216]
- 28.3M multiply-add operations
- 14.4% of total time
- **Tertiary bottleneck**

**Total GEMM**: ~177M multiply-adds per token

### Negligible Components (< 0.1%)

- Token embedding: 0.02 ms
- RMSNorm: ~0.00 ms
- RoPE: 0.04 ms
- Attention computation: 0.03 ms
- Sampling: ~0.00 ms

**Key Insight**: The attention mechanism itself is NOT the bottleneck. The O(n²) attention computation is fast because n (sequence length) is small in this test. The bottleneck is the O(d²) matrix multiplications where d (dimension) is large.

---

## Optimization Path Selection

Based on profiling results, the optimization priority is:

### Priority 1: Output Projection (47.3%)
**Action**: SIMD/AVX-512, cache blocking, quantization-aware kernels
**Expected**: 4-8x speedup → ~50-100ms

### Priority 2: FFN/SwiGLU (38.3%)
**Action**: Parallel gate/up projections, fused kernels
**Expected**: 2-4x speedup → ~85-170ms

### Priority 3: QKV Projection (14.4%)
**Action**: Fused QKV, SIMD
**Expected**: 2-4x speedup → ~32-65ms

### NOT Priority: KV Cache
**Reason**: Attention is already 0.03ms (negligible). KV cache will only help when sequence length grows large. Current bottleneck is GEMM, not attention.

---

## Validation

### Pass Criteria

| Criterion | Status |
|-----------|--------|
| ✅ Every major kernel timed | 8/8 components measured |
| ✅ Total time matches benchmark | 896.98ms vs 896.98ms (profile vs benchmark) |
| ✅ Top 3 bottlenecks identified | Output, FFN, QKV |
| ✅ No functional changes | Timing only, no algorithm changes |
| ✅ Baseline TPS unchanged | 1.11 tok/s (matches Phase 15) |

### Verification

```
Profile total:    896.98 ms/token = 1.11 tok/s
Benchmark total:  896.98 ms/token = 1.11 tok/s
Match: ✅
```

---

## Files

| File | Purpose |
|------|---------|
| `benchmark_profile.cpp` | Component profiler |
| `benchmark_profile.exe` | Compiled profiler |

---

## Reproduction Steps

```bash
cd d:\rawrxd\tests
g++ -std=c++17 -O2 benchmark_profile.cpp -o benchmark_profile.exe
.\benchmark_profile.exe
```

---

## Conclusion

**Primary Bottleneck**: Large matrix multiplications (GEMM) dominate execution time.

**Optimization Strategy**: Focus on GEMM optimization (SIMD, cache efficiency) before KV cache or attention optimizations.

**Expected Impact**: 
- Current: 1.11 tok/s
- Post-GEMM optimization: 3-6 tok/s
- Target: 10-50 tok/s (competitive with llama.cpp on CPU)

---

## Next Phase

**Phase 17 — GEMM Optimization (Output Projection)**

Focus: Output projection kernel (47.3% of time)
Techniques: AVX-512, cache blocking, loop unrolling
Validation: Same logits, higher throughput

---

## Measurement Loop

```
Phase 15 (Baseline) → Phase 16 (Profile) → Phase 17 (Optimize)
     ↓                        ↓                      ↓
  1.11 tok/s            Bottlenecks           Compare
  896 ms/token            identified            to baseline
```

**Status**: Ready for Phase 17 optimization work.
