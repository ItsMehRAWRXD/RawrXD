# Phase 17 — Output Projection GEMM Optimization

## Status
**IN PROGRESS**

## Contract

### Preserve
- **Input**: `hidden_state[embed_dim]` (3072 floats)
- **Output**: `logits[vocab_size]` (32064 floats)
- **Operation**: `logits[i] = sum(hidden[j] * W[j][i])`

### Baseline (Phase 16)
```
Latency: 423.97 ms/token
Throughput: 2.36 tok/s (for this kernel)
```

### Acceptance Criteria
1. **Correctness**: `max_absolute_error < 0.999` vs baseline
2. **Performance**: Measurable speedup vs 423.97ms baseline
3. **Numerical Stability**: No NaN/Inf in output

---

## Optimization Levels

### Level 1: Loop Ordering & Cache-Friendly Traversal
**Technique**: Change loop order for better cache locality
```
Baseline:  for i in vocab: for j in embed: sum += W[i][j] * hidden[j]
Optimized: for j in embed: for i in vocab: logits[i] += W[i][j] * hidden[j]
```
**Expected**: 1.5-2x speedup

### Level 2: Q4 Dequantization Fusion
**Technique**: Fuse weight dequantization with GEMM
```
Current: Dequantize all weights → Store → GEMM
Optimized: Dequantize on-the-fly during dot product
```
**Expected**: 2-4x speedup (reduces memory bandwidth)

### Level 3: AVX2/AVX-512 Vectorization
**Technique**: SIMD vectorized dot products
```
AVX2:  8 floats per instruction (256-bit)
AVX-512: 16 floats per instruction (512-bit)
```
**Expected**: 4-8x speedup

### Level 4: Multithreaded GEMM
**Technique**: Parallelize over output dimension
```
Thread 0: Compute logits[0..799]
Thread 1: Compute logits[800..1599]
...
```
**Expected**: Near-linear scaling with cores

---

## Validation Protocol

### Step 1: Reference Output
Generate reference logits using baseline scalar implementation.

### Step 2: Optimized Output
Generate logits using optimized implementation.

### Step 3: Numerical Comparison
```
max_error = max(|optimized[i] - reference[i]|)
mean_error = mean(|optimized[i] - reference[i]|)
```

### Step 4: Performance Measurement
```
Before: 423.97 ms
After:   XXX.XX ms
Speedup: X.XXx
```

---

## Implementation Plan

1. Create `gemm_output_projection_baseline()` - Reference scalar implementation
2. Create `gemm_output_projection_optimized()` - Optimized version
3. Create validation harness comparing outputs
4. Benchmark both implementations
5. Document speedup and correctness

---

## Success Criteria

```
✅ Correctness: max_absolute_error < 0.999
✅ Speedup: > 2x minimum, target 4-8x
✅ No functional changes to API
✅ Reproducible benchmark results
```
