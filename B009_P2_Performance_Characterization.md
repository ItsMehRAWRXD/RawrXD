# B009-P2 Performance Characterization: True Batched GEMM

## Executive Summary

B009-P2 replaces the superficial layer-outer batching with a true AVX-512 batched GEMM kernel that processes 8 token rows simultaneously per output column. The result is a **44% reduction in T=128 prefill time** and a fundamental change in scaling behavior.

---

## Certification Matrix

| T | Prefill (ms) | Decode (ms) | Total (ms) | MatMul | AVX512Kernels | Status |
|---|-------------|-------------|-----------|--------|-----------------|--------|
| 1 | 2,553 | — | 2,553 | 155 | 0 | ✅ PASS |
| 3 | 3,455 | 2,534 | 6,189 | **1** | 154 | ✅ PASS |
| 10 | 7,530 | 2,520 | 10,250 | **1** | 154 | ✅ PASS |
| 32 | 20,632 | 2,668 | 23,500 | **1** | 154 | ✅ PASS |
| 128 | 78,111 | 2,627 | 80,738 | **1** | 154 | ✅ PASS |

**Exit codes:** All 0. Token generation verified for T=3,10,32,128.

---

## Scaling Analysis

### Before (Superficial Batching)
```
T=3    →  4,552 ms  (~1,517 ms per token)
T=10   → 13,130 ms  (~1,313 ms per token)
T=32   → 35,942 ms  (~1,123 ms per token)
T=128  → 139,513 ms  (~1,090 ms per token)
```
Scaling was roughly linear: each additional token added ~1.1s of layer time.

### After (True Batched GEMM)
```
T=3    →   3,455 ms  (~1,152 ms per token)
T=10   →   7,530 ms  (~  753 ms per token)
T=32   →  20,632 ms  (~  645 ms per token)
T=128  →  78,111 ms  (~  610 ms per token)
```
Scaling is now sublinear: per-token cost drops as T increases because the AVX-512 kernel amortizes weight loads across 8 rows.

### Speedup Factors
| T | Prefill Before | Prefill After | Speedup |
|---|---------------|---------------|---------|
| 3 | 4,552 ms | 3,455 ms | **1.32×** |
| 10 | 13,130 ms | 7,530 ms | **1.74×** |
| 32 | 35,942 ms | 20,632 ms | **1.74×** |
| 128 | 139,513 ms | 78,111 ms | **1.79×** |

The speedup increases with T because the kernel's 8-row parallelism becomes more effective as the batch size grows.

---

## Structural Counter Analysis

### Before B009-P2
```
ForwardBatch=1  MatMul=463  BatchedMatMul=154  WeightLookup=617
```
- 463 MatMul calls = 154 projections × ~3 tokens (not exactly 3× because some paths differ)
- Each batched matmul still dispatched individual token-level GEMMs

### After B009-P2
```
ForwardBatch=1  MatMul=1  BatchedMatMul=154  WeightLookup=155  AVX512Kernels=154
```
- **MatMul dropped from 463 → 1** (99.8% reduction)
- **AVX512Kernels = 154** — every batched projection now uses the AVX-512 kernel
- **WeightLookup = 155** — one lookup per projection + one for output layer

This proves the architecture is no longer pretending to batch.

---

## Kernel Design

`BatchedGemmResident_AVX512()` processes the GEMM as:
```
for each output column m:
    for each chunk of 8 tokens:
        load weight row W[m][0..K-1]
        accumulate 8 dot products simultaneously via AVX-512 FMAs
        store 8 outputs
    scalar tail for remaining T%8 tokens
```

Register usage: 8 accumulators + 1 weight load = 9 ZMM registers (well under 32 limit).
Memory bandwidth: weight loaded once per 8 output rows (8× reuse factor).

---

## Next Bottlenecks (In Order of Expected Impact)

### 1. Scalar Tail for T % 8
For T=3, 37.5% of tokens fall through to the scalar tail loop. For T=10, 25%. This is the easiest win — process 4 tokens with a half-width kernel, or 2 tokens with quarter-width.

### 2. Attention Batching
The attention computation (Q×K^T, softmax, ×V) is still token-serial in the decode path. For prefill, the Q/K/V projections are batched but the attention softmax and KV cache updates may not be.

### 3. Kernel Width Expansion
Current kernel processes 8 rows. Expanding to 16 rows would require 16 accumulators + 1 weight = 17 ZMM registers (still under 32). This would further amortize weight loads and improve T=32/128 scaling.

### 4. Dequantization Overhead
The B015 materialization path dequantizes weights on first use. For T=128, this happens once per projection then the weight is resident. But the materialization itself is single-threaded and may be significant for cold-start scenarios.

### 5. Output Projection
`output.weight` (vocab × dim = 32000 × 2048) is the largest matrix and currently goes through the same path. Its size means it may not fit in the 512MB pool alongside 22 layers × 7 projections.

---

## Conclusion

B009-P2 is a genuine breakthrough. The prefill path now dispatches batched GEMM rather than repeatedly invoking single-token GEMM. The 44% T=128 speedup and the structural counter proof (MatMul=1, AVX512Kernels=154) demonstrate that the optimization is real, not cosmetic.

The next optimization should be driven by a fresh profile of the new kernel, because the bottleneck has shifted from "too many kernel calls" to "kernel efficiency and tail handling."

---

*Commit: 585e3fec0 — "B009-P2: Implement true AVX-512 batched GEMM kernel"*
*Date: 2026-08-12*
