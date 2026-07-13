# Performance Benchmark Baseline

## Date: 2026-07-09

---

## Executive Summary

Baseline benchmark completed for RawrXD Sovereign Inference Stack. **FFN is the primary bottleneck**, consuming ~90% of computation time.

---

## Benchmark Results

### Component Performance

| Component | Time (ms) | Throughput | Bottleneck? |
|-----------|-----------|------------|-------------|
| **Embedding** | ~0 | 300M tokens/sec | No (optimized away) |
| **Attention** | 1,582 | 1.36 GFLOP/s | Secondary |
| **FFN** | **15,015** | **4.00 GFLOP/s** | **PRIMARY** |
| **Sampling** | 196 | 5,092 samples/sec | No |

### Key Findings

1. **FFN is 9.5× slower than Attention** (15s vs 1.6s)
2. **FFN dominates total computation time** (~90%)
3. **Current GFLOPS is very low** (4 GFLOP/s vs theoretical 1000+ GFLOP/s for AVX-512)
4. **Massive optimization opportunity** - 100-1000× speedup possible

---

## Bottleneck Analysis

### FFN Computation Breakdown

```
FFN Layer (per token):
├── Gate Projection: [4096, 14336] = 58.9M params
├── Up Projection:   [4096, 14336] = 58.9M params
├── SiLU + Multiply: 14336 elements
└── Down Projection: [14336, 4096] = 58.9M params

Total per layer: ~176M FLOPs
For 34 layers: ~6B FLOPs per token
```

### Why FFN is Slow

1. **Large Matrix Multiplications**: 4096 × 14336 × 3 projections
2. **Memory Bandwidth Bound**: Weights don't fit in cache
3. **Scalar Implementation**: No SIMD utilization
4. **No Tiling**: Poor cache locality

---

## Comparison with llama.cpp

| Metric | RawrXD (Current) | llama.cpp | Gap |
|--------|------------------|-----------|-----|
| Tokens/sec | ~0.006 | ~30 | **5000×** |
| Latency/token | ~160s | ~33ms | **4800×** |
| FFN Time | 15s | ~50ms | **300×** |
| Attention Time | 1.6s | ~10ms | **160×** |

---

## Optimization Roadmap

### Phase 1: AVX-512 Kernels (Priority 1)

**Target: FFN MatMul**
- Implement 16-wide AVX-512 FMA for gate/up/down projections
- Expected speedup: **50-100×**
- Implementation time: 2-3 days

```cpp
// Current (scalar)
for (i = 0; i < M; i++)
  for (j = 0; j < N; j++)
    for (k = 0; k < K; k++)
      C[i,j] += A[i,k] * B[k,j]

// Optimized (AVX-512)
for (i = 0; i < M; i++)
  for (j = 0; j < N; j += 16)  // 16 floats per vector
    _mm512_fmadd_ps(a_vec, b_vec, c_vec)
```

### Phase 2: FlashAttention v2 (Priority 2)

**Target: Attention Computation**
- Tiled attention with O(1) memory
- Expected speedup: **10-20×**
- Implementation time: 3-4 days

### Phase 3: Multi-threading (Priority 3)

**Target: Parallel Heads**
- Process 32 attention heads in parallel
- Expected speedup: **8-16×** (on 16-core)
- Implementation time: 2-3 days

### Phase 4: Quantization (Priority 4)

**Target: Memory Bandwidth**
- Q4_K/Q8_0 weight storage
- Expected speedup: **2-4×** (memory bound)
- Implementation time: 5-7 days

---

## Expected Performance After Optimization

| Phase | Tokens/sec | Speedup | Cumulative |
|-------|------------|---------|------------|
| Baseline | 0.006 | 1× | 1× |
| AVX-512 FFN | 0.6 | 100× | 100× |
| FlashAttention | 6.0 | 10× | 1000× |
| Multi-threading | 48.0 | 8× | 8000× |
| Quantization | 96.0 | 2× | 16000× |
| **Target** | **30-50** | **5000-8000×** | - |

---

## Next Steps

### Immediate Actions

1. **Implement AVX-512 MatMul Kernel**
   - File: `kernel_dispatch.cpp`
   - Target: `MatMulF32_AVX512()`
   - Focus on FFN projections

2. **Profile with MASM Telemetry**
   - Measure per-layer cycles
   - Verify kernel dispatch
   - Track memory bandwidth

3. **Validate Correctness**
   - Compare outputs with scalar version
   - Max error < 1e-5
   - Run full model validation

### Success Criteria

- [ ] FFN time < 150ms (100× improvement)
- [ ] Attention time < 160ms (10× improvement)
- [ ] End-to-end tokens/sec > 1.0
- [ ] Numerical accuracy preserved

---

## Files Created

- `benchmark_suite.hpp/cpp` - Benchmark framework
- `test_benchmark.cpp` - Benchmark runner
- `benchmark_results.csv` - Raw results
- `benchmark_results.json` - Structured results
- `BENCHMARK_BASELINE.md` - This document

---

## Conclusion

The baseline benchmark confirms **FFN is the bottleneck**. With AVX-512 optimization, we can achieve **100× speedup** on FFN alone, bringing us significantly closer to production-grade performance.

**Ready to proceed with AVX-512 kernel implementation.**
