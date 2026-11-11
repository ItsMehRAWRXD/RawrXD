# Empirical Evidence Summary

**Date**: 2026-07-09  
**Status**: Partially Validated

---

## Verified Claims ✅

### 1. Numerical Correctness (test_quantized_matmul.exe)

**Raw Output:**
```
[1/4] Testing quantization round-trip...
  Original size: 4096 bytes
  Quantized size: 1024 bytes
  Compression: 4:1
  Error: 5.54%
  ✓ Quantization error within bounds (< 10%)

[2/4] Testing matrix multiplication correctness...
  Matrix: 256 x 512
  Error: 6.68%
  ✓ MatMul error within bounds
```

**Evidence:**
- Quantization error: **5.54%** (measured)
- MatMul error: **6.68%** (measured)
- Both within acceptable bounds (< 10%)

### 2. Compression Ratio (test_quantized_matmul.exe)

**Raw Output:**
```
  Original size: 4096 bytes
  Quantized size: 1024 bytes
  Compression: 4:1
```

**Evidence:**
- 4:1 compression for weights (measured)
- 7.111× overall model compression (from test_real_ministral.exe)

### 3. Router Detection (test_production_router.exe)

**Raw Output:**
```
Test 1: ministral3_q4_0.gguf - PASS
Test 2: model_Q4_0.gguf - PASS
Test 3: llama3.2-3b-Q4_0.gguf - PASS
Test 4: model_fp32.gguf - PASS
Test 5: model_q8_0.gguf - PASS
Test 6: gemma3-1b-Q2_K.gguf - PASS

Passed: 6/6
```

**Evidence:**
- 100% detection accuracy (6/6 tests)
- Correctly routes Q4_0 to quantized backend
- Correctly routes non-Q4_0 to standard backend

### 4. Real Model Loading (test_real_ministral.exe)

**Raw Output:**
```
[1/4] Loading GGUF info...
  File size: 4.844 GB
  Tensors loaded: 50
  ✓ GGUF loaded successfully

[3/4] Running quantized inference benchmark...
  Matrix size: 4096 x 14336
  Weights: 58.720M
  Quantized size: 31.500 MB
  Compression ratio: 7.111x
  Iterations: 100
  Time: 4.972s
  Performance: 2.36 GFLOPS
```

**Evidence:**
- Successfully loads real 4.8GB ministral3_q4_0.gguf
- 50 tensors parsed
- 2.36 GFLOPS measured performance

### 5. Projected Throughput (test_quantized_matmul.exe)

**Raw Output:**
```
  Results:
    Time: 4431.24 ms
    Performance: 2.7 GFLOPS
    Memory: 1.3 GB/s

  Projected (34 layers):
    160.2 tok/s
```

**Evidence:**
- Projection based on measured MatMul performance
- 160.2 tok/s projected (exceeds 100+ target)

---

## Unverified Claims ⚠️

### 1. Actual End-to-End Throughput

**Status:** Not measured

The 131 tok/s and 160.2 tok/s figures are **projections** based on MatMul kernel benchmarks, not actual token generation measurements.

**What's missing:**
- Full transformer forward pass with all layers
- Actual token generation loop
- KV cache operations
- Attention computation
- Sampling overhead

### 2. Memory Usage Reduction

**Status:** Calculated but not measured

The 8× memory reduction (52GB → 6.5GB) is based on:
- 4:1 weight compression (calculated)
- 7.111× model compression (measured from file sizes)

**What's missing:**
- Peak RSS measurements
- Working set size during inference
- KV cache memory growth
- Memory fragmentation

### 3. Logit Comparison vs FP32

**Status:** Not performed

No comparison of outputs against FP32 reference implementation.

---

## Honest Assessment

### What We Know (Measured)

| Metric | Value | Source |
|--------|-------|--------|
| Quantization error | 5.54% | test_quantized_matmul.exe |
| MatMul error | 6.68% | test_quantized_matmul.exe |
| Compression | 4:1 (weights) | test_quantized_matmul.exe |
| Model compression | 7.111× | test_real_ministral.exe |
| Router accuracy | 100% (6/6) | test_production_router.exe |
| MatMul GFLOPS | 2.7 | test_quantized_matmul.exe |
| Real model load | ✓ | test_real_ministral.exe |

### What We Don't Know (Not Measured)

| Metric | Claim | Status |
|--------|-------|--------|
| End-to-end tok/s | 131-160 | ⚠️ Projection only |
| Memory reduction | 8× | ⚠️ Calculated, not measured |
| Logit accuracy | vs FP32 | ❌ Not compared |
| Cold start latency | - | ❌ Not measured |
| Long-context perf | - | ❌ Not measured |

---

## Conclusion

**The Q4_0 integration is architecturally sound and unit-tested, but production performance claims require end-to-end validation.**

### Verified ✅
- Router detection logic
- Quantization numerical correctness
- MatMul kernel correctness
- Real model loading
- Compression ratios

### Not Verified ❌
- Actual token generation throughput
- Memory usage at runtime
- Comparison against reference implementation
- Multi-format support (Q4_K_M, Q5_K_M, etc.)

**Recommendation:** Before claiming production readiness, run:
1. Full transformer end-to-end benchmark
2. Memory profiling with RSS measurements
3. Logit comparison against llama.cpp
4. Multi-format regression tests
