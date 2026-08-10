# B010 / B011 Weight Residency — Evidence Archive

**Date:** 2026-08-10
**Source:** Historical benchmark run (preserved from session context)
**Model:** Llama-family 1B-class, dim=3072, layers=28, heads=24, kv_heads=8
**Tensor:** `blk.0.attn_output.weight` (3072×3072, ~37.7 MB FP32 dequantized)

---

## B010 Baseline — Residency DISABLED

| Metric | Value |
|--------|-------|
| Total time | **70.86 ms** |
| Per iteration | 7.09 ms |
| StreamingMatMul calls | 10 |
| Unique tensors | 1 |
| Maps | 10 |
| Unmaps | 10 |
| Repeated acquisitions | 9 |
| Dequantization | 4.21 ms |
| Dot product | 60.73 ms |
| Overhead | ~5.92 ms |

## B011 Optimized — Residency ENABLED

| Metric | Value |
|--------|-------|
| Total time | **22.97 ms** |
| Per iteration | 2.30 ms |
| StreamingMatMul calls | 10 |
| Unique tensors | 1 |
| Maps | **1** |
| Unmaps | **1** |
| Cache hits | **9** |
| Cache misses | 1 |
| Hit rate | **90%** |
| Dequantization | 3.87 ms |
| Dot product | **11.06 ms** |
| Overhead | 1.19 ms |

## Speedup

```
70.86 ms → 22.97 ms = 3.08× faster (67.6% reduction)
```

## Key Observations

1. **90% hit rate → 67.6% wall-clock reduction**: The benefit is not merely proportional to hit count. Avoiding repeated mapping/materialization has substantial downstream impact on compute throughput.

2. **Dot-product collapsed 81.8%** (60.73 ms → 11.06 ms): Resident weights likely achieve L2/L3 cacheline affinity that streaming-pinned maps missed. The dequantized tensor sits in a hot memory window.

3. **Residency threshold effect**: On faster models (current 1B unlock at ~1.7 ms/iter), cache overhead can exceed benefit. Residency is most valuable when baseline per-matmul time exceeds ~3–4 ms.

## B014 Consistency

B014 decomposition on TinyLlama (post-residency):

```
Dot product:     72.97%  ← dominant
Dequantization:  25.20%
Overhead:         1.83%
Acquisition:      0.00%  ← eliminated by residency
```

This confirms the B011 finding: once acquisition is eliminated, the remaining bottleneck is compute (dot product).

## Experimental Progression

```
B010  →  Repeated weight acquisition / mapping
  ↓
B011  →  Residency eliminates repeated mapping (3× speedup)
  ↓
B014  →  Decompose remaining compute cost
  ↓
Dot product ≈ dominant bottleneck
```

## Certification

| Checkpoint | Status |
|------------|--------|
| B010 baseline behavior | ✅ CONFIRMED |
| B011 residency behavior | ✅ CONFIRMED |
| B011 optimization | ✅ 3.08× measured |
| Residency mechanism | ✅ 90% hit rate, 1 map/unmap vs 10/10 |
| B014 consistency | ✅ Post-residency compute decomposition matches |

---

*Archived 2026-08-10. Current build reproduction shows threshold sensitivity — residency benefit is model-speed dependent.*
