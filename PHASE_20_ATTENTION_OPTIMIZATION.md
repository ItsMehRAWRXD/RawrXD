# Phase 20: Attention Optimization

## Date
2026-07-09

## Context
Phases 17-19 successfully optimized all three major GEMM operations:
- Output Projection: 43.3x speedup
- FFN/SWiGLU: 43.5x speedup  
- QKV Projection: 69.5x speedup

The profiler-driven optimization loop has correctly identified the new bottleneck.

### Current Bottleneck Profile (Post-Phase 19)
```
Attention (Self-Attention)
    ███████               ~15-20% (NEW TARGET)
All GEMM Operations
    █                     ~5-8% combined (reduced from 99.9%)
```

## Baseline Configuration
- **Model**: Phi-3-mini-4k-instruct
- **Num heads**: 32
- **Head dim**: 96 (3072 / 32)
- **Seq length**: Variable (1 for decode, up to 4096 for prefill)

## Attention Operation

### Mathematical Formulation (Decode - Single Token)
```
Input:  Q[3072], K_cache[seq_len][3072], V_cache[seq_len][3072]

Step 1: Reshape Q into heads
    Q_h[32][96] = reshape(Q[3072])

Step 2: Compute attention scores for each head
    for head h in 0..31:
        for position pos in 0..seq_len-1:
            score[pos] = dot(Q_h[h], K_cache[pos][h]) / sqrt(96)

Step 3: Softmax over scores
    weights = softmax(scores)

Step 4: Weighted sum of values
    output[h] = sum(pos, weights[pos] * V_cache[pos][h])

Step 5: Reshape output
    output[3072] = reshape(output_h[32][96])
```

### Memory Characteristics
- **Q**: 3072 floats = 12 KB
- **K_cache**: seq_len × 3072 floats = 12 KB × seq_len
- **V_cache**: seq_len × 3072 floats = 12 KB × seq_len
- **Compute**: O(seq_len × heads × head_dim) per token

## Optimization Contract

### Level 1 — Baseline Capture
Measure current attention latency with scalar implementation.

### Level 2 — AVX2 SIMD
**Target**: Vectorize the dot product computation.

**Implementation**:
```cpp
// Dot product with AVX2
float dot_product_avx2(const float* a, const float* b, int n) {
    __m256 sum_vec = _mm256_setzero_ps();
    for (int i = 0; i <= n - 8; i += 8) {
        __m256 a_vec = _mm256_loadu_ps(&a[i]);
        __m256 b_vec = _mm256_loadu_ps(&b[i]);
        sum_vec = _mm256_add_ps(sum_vec, _mm256_mul_ps(a_vec, b_vec));
    }
    // Horizontal sum
    return sum_array[0] + ... + sum_array[7];
}
```

**Expected Speedup**: 4-6x for compute-bound dot products.

### Level 3 — Threading
**Strategy**: Parallelize across attention heads.

**Rationale**: 
- Each of the 32 heads is independent
- No synchronization needed during compute
- Perfect embarrassingly parallel workload

**Implementation**:
```cpp
#pragma omp parallel for
for (int h = 0; h < num_heads; h++) {
    compute_attention_head(Q_h[h], K_cache, V_cache, output[h]);
}
```

**Expected Speedup**: Near-linear with core count (up to ~8x on 8-core for 32 heads).

### Level 4 — Cache Optimization
**Strategy**: Block K/V cache access for better L2/L3 utilization.

**Current**: Random access pattern across cache
**Target**: Sequential blocks fitting in L2 cache

## Validation Protocol

### Correctness Criteria
```
✓ max_absolute_error < 0.999
✓ No NaN/Inf in output
✓ Deterministic (same input → same output)
✓ Attention weights sum to 1.0 (softmax property)
✓ Output distribution matches reference
```

### Performance Criteria
```
✓ Attention latency reduced vs baseline
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
- Level 4 (+Cache opt): 12-16x speedup

### Stretch
- Combined optimization: 15-20x speedup
- Attention becomes non-dominant (<5% of runtime)

## Integration Plan

### Phase 20.1: Baseline Capture
- [ ] Create `attention_optimization_test.cpp`
- [ ] Measure baseline attention latency
- [ ] Validate correctness against reference

### Phase 20.2: AVX2 Implementation
- [ ] Vectorize dot product computation
- [ ] Vectorize softmax computation
- [ ] Validate numerical correctness
- [ ] Measure speedup

### Phase 20.3: Multithreading
- [ ] Parallelize across attention heads
- [ ] Tune thread count
- [ ] Measure scaling efficiency

### Phase 20.4: Cache Optimization (Optional)
- [ ] Implement blocked cache access
- [ ] Measure L2/L3 hit rate improvement
- [ ] Validate performance gain

## Expected Outcome

After Phase 20:
```
All Operations:
    █                     ~5-8% combined
    
No single dominant bottleneck
→ System is memory-bandwidth bound
→ Next phase: Memory optimization / Q4 fusion
```

The optimization loop continues. Once attention is optimized, the system will likely be memory-bandwidth bound, shifting focus to quantization and memory access patterns.

## Files to Create
1. `PHASE_20_ATTENTION_OPTIMIZATION.md` (this document)
2. `tests/attention_optimization_test.cpp` (test harness)
3. `PHASE_20_RESULTS.md` (results after completion)
