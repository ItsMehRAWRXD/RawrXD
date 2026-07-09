# Phase 19: QKV Projection Optimization

## Date
2026-07-09

## Context
Phase 18 successfully reduced FFN/SWiGLU from 38.3% to ~5-8% of runtime. The profiler-driven optimization loop has correctly identified the new bottleneck.

### Current Bottleneck Profile (Post-Phase 18)
```
QKV Projection
    ██████████            ~25-30% (129.33ms Phase 16)  ← NEW TARGET
FFN/SWiGLU
    ██                    ~5-8% (reduced from 38.3%)
Output Projection
    █                     ~3-5% (reduced from 47.3%)
```

## Baseline Configuration
- **Model**: Phi-3-mini-4k-instruct
- **Hidden dim**: 3072
- **Num heads**: 32
- **Head dim**: 96 (3072 / 32)
- **QKV dim**: 9216 (3072 * 3 for Q+K+V)

## QKV Projection Operation

### Mathematical Formulation
```
Input:  hidden[3072]

QKV = W_qkv[9216×3072] × hidden[3072]

Where:
    Q[3072] = QKV[0:3072]
    K[3072] = QKV[3072:6144]
    V[3072] = QKV[6144:9216]
```

### Memory Characteristics
- **W_qkv**: 9216 × 3072 × 4 bytes = 113.2 MB (Q4_0: ~14.1 MB)
- **Output**: 9216 floats = 36 KB
- **Compute**: 9216 × 3072 = 28.3M FMAs

## Optimization Contract

### Level 1 — Baseline Capture
Measure current QKV projection latency with scalar implementation.

### Level 2 — AVX2 SIMD
**Target**: Vectorize the inner accumulation loop.

**Implementation**:
```cpp
// Process 8 floats at a time
for (int j = 0; j <= dim - 8; j += 8) {
    __m256 w_vec = _mm256_loadu_ps(&weights[i * dim + j]);
    __m256 x_vec = _mm256_loadu_ps(&input[j]);
    sum_vec = _mm256_add_ps(sum_vec, _mm256_mul_ps(w_vec, x_vec));
}
```

**Expected Speedup**: 4-6x for compute-bound kernels.

### Level 3 — Threading
**Strategy**: Parallelize across QKV output dimension (9216 outputs).

**Rationale**: 
- Each Q/K/V head is independent
- No synchronization needed during compute
- Perfect embarrassingly parallel workload

**Implementation**:
```cpp
#pragma omp parallel for
for (int i = 0; i < qkv_dim; i++) {
    qkv_output[i] = compute_row(weights, input, i);
}
```

**Expected Speedup**: Near-linear with core count (up to ~8x on 8-core).

### Level 4 — Q4 Dequantization Fusion
**Current Flow**:
```
Q4_0 weights → Dequantize buffer → GEMM → Discard buffer
```

**Target Flow**:
```
Q4_0 block → Dequantize on-the-fly → Multiply-accumulate → Discard
```

**Benefit**: 4x reduction in memory bandwidth.

## Validation Protocol

### Correctness Criteria
```
✓ max_absolute_error < 0.999
✓ No NaN/Inf in output
✓ Deterministic (same input → same output)
✓ Q, K, V distributions match reference
```

### Performance Criteria
```
✓ QKV latency reduced vs baseline
✓ End-to-end TPS improves
✓ No regression in other components
```

## Success Metrics

### Minimum Acceptable
- Correctness: All validation criteria passed
- Performance: Any measurable speedup (>1.0x)

### Target
- Level 2 (AVX2): 4-6x speedup
- Level 3 (+Threads): 8-12x speedup  
- Level 4 (+Q4 fusion): 12-20x speedup

### Stretch
- Combined optimization: 15-25x speedup
- QKV becomes non-dominant (<10% of runtime)

## Integration Plan

### Phase 19.1: Baseline Capture
- [ ] Create `qkv_optimization_test.cpp`
- [ ] Measure baseline QKV latency
- [ ] Validate correctness against reference

### Phase 19.2: AVX2 Implementation
- [ ] Vectorize QKV projection
- [ ] Validate numerical correctness
- [ ] Measure speedup

### Phase 19.3: Multithreading
- [ ] Parallelize across QKV output dimension
- [ ] Tune thread count
- [ ] Measure scaling efficiency

### Phase 19.4: Q4 Fusion (Optional)
- [ ] Implement on-the-fly dequantization
- [ ] Validate with real Q4_0 weights
- [ ] Measure memory bandwidth reduction

## Expected Outcome

After Phase 19:
```
QKV Projection:
    ██                    reduced from ~25-30%
    
Attention:
    █████                 becomes new dominant
    
FFN/SWiGLU:
    ██                    remains minor
    
Output Projection:
    █                     remains minor
```

The optimization loop continues. Each improvement creates a new, measurable target.

## Files to Create
1. `PHASE_19_QKV_OPTIMIZATION.md` (this document)
2. `tests/qkv_optimization_test.cpp` (test harness)
3. `PHASE_19_RESULTS.md` (results after completion)
