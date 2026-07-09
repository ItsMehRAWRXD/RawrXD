# Phase 18: FFN/SwiGLU Optimization

## Date
2026-07-09

## Context
Phase 17 successfully reduced Output Projection from 47.3% to a minor component of runtime. The profiler-driven optimization loop has correctly identified the new bottleneck.

### Current Bottleneck Profile (Post-Phase 17)
```
FFN/SwiGLU
    ████████████████████  38.3% (343.59ms)  ← NEW TARGET
QKV Projection
    ███████               14.4% (129.33ms)
Output Projection
    █                     ~7% (reduced from 47.3%)
```

## Baseline Configuration
- **Model**: Phi-3-mini-4k-instruct
- **Hidden dim**: 3072
- **FFN dim**: 8192 (intermediate size)
- **Operations**: SiLU(Gate) * Up → Down projection

## FFN/SwiGLU Operation

### Mathematical Formulation
```
Input:  hidden[3072]

Step 1: Gate projection
    gate[8192] = SiLU(W_gate[8192×3072] × hidden[3072])

Step 2: Up projection  
    up[8192] = W_up[8192×3072] × hidden[3072]

Step 3: Element-wise multiply
    fused[8192] = gate[8192] ⊙ up[8192]

Step 4: Down projection
    output[3072] = W_down[3072×8192] × fused[8192]
```

### Memory Characteristics
- **W_gate**: 8192 × 3072 × 4 bytes = 100.5 MB (Q4_0: ~12.5 MB)
- **W_up**: 8192 × 3072 × 4 bytes = 100.5 MB (Q4_0: ~12.5 MB)
- **W_down**: 3072 × 8192 × 4 bytes = 100.5 MB (Q4_0: ~12.5 MB)
- **Total**: ~301.5 MB FP32, ~37.5 MB Q4_0

## Optimization Contract

### Level 1 — Loop Analysis
**Hypothesis**: Baseline i-j ordering may not be optimal for FFN dimensions.

**Test Matrix**:
| Layout | Access Pattern | Hypothesis |
|--------|---------------|------------|
| i-j (baseline) | Row-major weights | Cache-friendly for weights |
| j-i | Column-major traversal | Better for output reuse |
| Tiled | Blocked access | L1/L2 cache optimization |

**Validation**: Measure both, select winner based on wall-clock time.

### Level 2 — AVX2 SIMD
**Target**: Vectorize the inner accumulation loop.

**Implementation**:
```cpp
// Scalar baseline
for (int j = 0; j < dim; j++) {
    sum += weights[i * dim + j] * input[j];
}

// AVX2 vectorized
for (int j = 0; j < dim; j += 8) {
    __m256 w = _mm256_loadu_ps(&weights[i * dim + j]);
    __m256 x = _mm256_loadu_ps(&input[j]);
    sum_vec = _mm256_fmadd_ps(w, x, sum_vec);
}
```

**Expected Speedup**: 4-6x for compute-bound kernels.

### Level 3 — Threading
**Strategy**: Parallelize across output dimension.

**Rationale**: 
- Each output neuron is independent
- No synchronization needed during compute
- Perfect embarrassingly parallel workload

**Implementation**:
```cpp
#pragma omp parallel for
for (int i = 0; i < output_dim; i++) {
    output[i] = compute_row(weights, input, i);
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

**Benefit**: 4x reduction in memory bandwidth (Q4_0 uses 4.5 bits vs 32 bits).

**Challenge**: Must handle quantization scales per 32-element block.

## Validation Protocol

### Correctness Criteria
```
✓ max_absolute_error < 0.999
✓ No NaN/Inf in output
✓ Deterministic (same input → same output)
✓ Output distribution matches reference
```

### Performance Criteria
```
✓ FFN latency reduced vs baseline
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
- FFN becomes non-dominant (<15% of runtime)

## Integration Plan

### Phase 18.1: Baseline Capture
- [ ] Create `ffn_optimization_test.cpp`
- [ ] Measure baseline FFN latency
- [ ] Validate correctness against reference

### Phase 18.2: Loop Analysis
- [ ] Test i-j vs j-i ordering
- [ ] Select optimal layout
- [ ] Document cache behavior

### Phase 18.3: AVX2 Implementation
- [ ] Vectorize gate projection
- [ ] Vectorize up projection
- [ ] Vectorize down projection
- [ ] Validate numerical correctness

### Phase 18.4: Multithreading
- [ ] Parallelize across output dimension
- [ ] Tune thread count
- [ ] Measure scaling efficiency

### Phase 18.5: Q4 Fusion (Optional)
- [ ] Implement on-the-fly dequantization
- [ ] Validate with real Q4_0 weights
- [ ] Measure memory bandwidth reduction

## Expected Outcome

After Phase 18:
```
FFN/SwiGLU:
    ███                   reduced from 38.3%
    
QKV Projection:
    ███████               becomes new dominant (~25-30%)
    
Output Projection:
    █                     remains minor
```

The optimization loop continues. Each improvement creates a new, measurable target.

## Files to Create
1. `PHASE_18_FFN_OPTIMIZATION.md` (this document)
2. `tests/ffn_optimization_test.cpp` (test harness)
3. `PHASE_18_RESULTS.md` (results after completion)
