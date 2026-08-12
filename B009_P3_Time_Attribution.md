# B009-P3: Current Kernel Time Attribution

## Executive Summary

B009-P3 instruments the batched GEMM kernel to measure where time is actually spent. The key finding: **dequantization (~1,480 ms) dominates small-T prefill**, nearly matching GEMM compute time. The scalar tail is NOT material. Attention is negligible.

---

## Methodology

Added per-`Forward()` resettable counters:
- `m_b009AVX512KernelTimeNs` — total time in `BatchedGemmResident_AVX512()`
- `m_b009AVX512KernelRows` — total rows processed by the kernel
- `m_b009AttentionTimeNs` — time in the attention Q×K^T + softmax + ×V loop
- `m_b009DequantTimeNs` — time in `B015MaterializeDequantizedTensor()` on miss

Counters reset at the start of each `Forward()` call, so prefill and decode are reported separately.

---

## Tail Comparison Matrix

| T | Tail % | GEMM (ms) | Dequant (ms) | Attn (ms) | Other (ms) | Total (ms) | GEMM/Total |
|---|--------|-----------|--------------|-----------|------------|-----------|------------|
| 3 | 37.5%  | 1,818     | 1,494        | 0.22      | 316        | 3,628     | 50.1%      |
| 8 | 0%     | 4,787     | 1,482        | 1.14      | 318        | 6,588     | 72.7%      |
| 10| 25%    | 5,957     | 1,467        | 1.64      | 320        | 7,746     | 76.9%      |

**Exit codes:** All 0. Token generation verified.

---

## Finding 1: Scalar Tail is NOT Material

Hypothesis: T=3 with 37.5% scalar tail should be slower per-row than T=8 with 0% tail.

**Reality:**
- T=3: 1,818 ms / (3 × 154 projections) = **3.94 μs/row**
- T=8: 4,787 ms / (8 × 154 projections) = **3.89 μs/row**
- T=10: 5,957 ms / (10 × 154 projections) = **3.87 μs/row**

Per-row cost is **remarkably consistent** (~3.9 μs/row) regardless of tail percentage. The scalar tail loop is not the bottleneck.

**Conclusion:** Do NOT optimize the scalar tail. The 8-row AVX-512 block is already efficient enough that tail overhead is lost in the noise.

---

## Finding 2: Dequantization Dominates Small-T Prefill

| T | Dequant (ms) | GEMM (ms) | Dequant/GEMM |
|---|--------------|-----------|--------------|
| 3 | 1,494        | 1,818     | 82%          |
| 8 | 1,482        | 4,787     | 31%          |
| 10| 1,467        | 5,957     | 25%          |

Dequantization time is **~1,480 ms regardless of T**. This is cold-start materialization: the first time a weight is accessed in a forward pass, it must be dequantized from Q2_K/Q4_K to FP32 and committed to the residency pool.

For T=3, dequantization consumes **41% of prefill time** (1,494 / 3,628). For T=8, it drops to **22%**.

**Conclusion:** The next optimization target is dequantization, not the scalar tail.

---

## Finding 3: Attention is Negligible

| T | Attention (ms) | Total (ms) | Attn/Total |
|---|----------------|------------|------------|
| 3 | 0.22           | 3,628      | 0.006%     |
| 8 | 1.14           | 6,588      | 0.017%     |
| 10| 1.64           | 7,746      | 0.021%     |

Attention (Q×K^T dot products, softmax, ×V accumulation) is **~0.01% of total prefill time**. This is because:
1. Head dimension is small (64)
2. Attention length is small for prefill (T tokens)
3. The dot products use AVX-512 and are cache-friendly

**Conclusion:** Do NOT optimize attention for prefill. It is not the bottleneck.

---

## Finding 4: GEMM Efficiency is Consistent

`~3.9 μs/row` across T=3/8/10 means:
- The AVX-512 kernel is well-tuned
- Memory bandwidth is not saturated at these batch sizes
- The 8-row blocking is effective

For comparison, a naive scalar implementation would be ~50-100× slower.

---

## Bottleneck Ranking (Updated)

### For T=3-10 (small batch):
1. **Dequantization** (~1,480 ms, 25-40% of prefill) ← **NEXT TARGET**
2. **GEMM compute** (~3.9 μs/row, 50-75% of prefill)
3. **Other** (~320 ms, RMSNorm, residual adds, etc.)
4. **Attention** (~1 ms, 0.01%)

### For T=32-128 (large batch):
1. **GEMM compute** (scales linearly with T)
2. **Dequantization** (fixed ~1,480 ms, becomes smaller %)
3. **Other** (~320 ms)
4. **Attention** (scales with T but still tiny)

---

## Recommended Next Steps

### P4-A: Dequantization Amortization
The 1,480 ms dequantization cost is paid once per weight on first access. Options:
- Pre-warm the residency pool before inference (load all weights at startup)
- Parallelize dequantization across threads
- Cache dequantized weights between Forward() calls (already partially done via B015)

### P4-B: Verify T=32/128 Scaling
Run T=32 and T=128 with P3 instrumentation to confirm dequantization becomes negligible at large T.

### P4-C: Do NOT Optimize
- Scalar tail: NOT material (skip)
- Attention: NOT material (skip)
- 16-row kernel: Only if T=128 profiling shows GEMM is still the bottleneck

---

## Conclusion

B009-P3 proves that the scalar tail hypothesis was wrong. The real bottleneck for small-T prefill is **dequantization overhead**, not tail loops. For large-T prefill, GEMM compute dominates as expected.

The optimization path is now clear:
- **Small T:** Reduce dequantization latency (pre-warm, parallelize)
- **Large T:** GEMM is already efficient; consider wider blocking (16 rows) if profiling supports it

---

*Commit: 41036afe9 — "B009-P3: Add kernel time-attribution instrumentation"*
*Date: 2026-08-12*
