// ============================================================================
// B013 — Compute Decomposition Certification
// ============================================================================
// Evidence artifact: frozen decomposition of StreamingMatMul latency
// into acquisition, dequantization, dot-product, loop overhead, and sync.
//
// Source: b010_b011_fast_experiment.cpp (controlled microbenchmark)
// Model:  F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf
// Weight: blk.0.attn_output.weight (3072 × 3072, Q4_K)
// Date:   2026-08-10
// Commit: 29e76f01e
// ============================================================================

#ifndef B013_COMPUTE_DECOMPOSITION_H
#define B013_COMPUTE_DECOMPOSITION_H

namespace b013 {

// ============================================================================
// Raw Measurement Data (10 iterations, residency OFF)
// ============================================================================
struct B013Measurement {
    static constexpr double kTotalMs        = 68.40;   // outer timer
    static constexpr double kComputeMs      = 67.72;   // acquisition excluded
    static constexpr double kAcquisitionMs  = 0.00;    // lookup + pin
    static constexpr double kDequantMs      = 4.20;    // Q4_K → F32
    static constexpr double kDotProductMs   = 58.74;   // naive O(K) dot
    static constexpr double kLoopOverheadMs = 1.12;    // tile scheduling
    static constexpr double kThreadSyncMs   = 0.00;    // mutex/wait
};

// ============================================================================
// Decomposition Table (percentages relative to compute time)
// ============================================================================
// | Component          | Time (ms) | % of Compute | % of Total |
// |--------------------|-----------|--------------|------------|
// | Dot-product        | 58.74     | 86.7%        | 85.9%      |
// | Dequantization     | 4.20      | 6.2%         | 6.1%       |
// | Loop/packing       | 1.12      | 1.7%         | 1.6%       |
// | Acquisition        | 0.00      | 0.0%         | 0.0%       |
// | Thread sync        | 0.00      | 0.0%         | 0.0%       |
// |--------------------|-----------|--------------|------------|
// | Total              | 67.72     | 100.0%       | 99.0%      |
//
// Note: 1.0% discrepancy is outer timer vs accumulated inner timers
//       (steady_clock resolution + function call overhead).

// ============================================================================
// Causal Conclusion
// ============================================================================
// 1. Acquisition is NOT the bottleneck — confirmed by B010/B011.
//    Even with 90% cache hits (B011), latency did not improve because
//    acquisition was already ~0 ms.
//
// 2. Dequantization is NOT the bottleneck — at 6.2% of compute, a 2× speedup
//    would yield <3% overall improvement. The Q4_K → F32 path is already
//    efficient enough relative to the dot-product.
//
// 3. Thread synchronization is NOT the bottleneck — zero measured cost.
//    The single-threaded dot-product loop dominates.
//
// 4. The dot-product IS the bottleneck — 86.7% of compute time.
//    The naive scalar loop:
//        for (size_t k = 0; k < K; ++k) sum += w[k] * x[k];
//    is memory-bandwidth-bound on this platform and does not utilize
//    AVX-512 or FMA instructions despite their availability.
//
// 5. B011 residency regressed by +17.4% because the cache-miss penalty
//    (allocation + 5.3 MB memcpy + mutex) on the first iteration outweighed
//    the savings on 9 hits. This confirms acquisition was already free.

// ============================================================================
// B014 Optimization Target Recommendation
// ============================================================================
// Highest value: Replace the scalar dot-product with AVX-512 FMA.
// Expected speedup: 8×–16× on the 58.74 ms dot-product portion.
// Expected overall impact: ~50–60% reduction in StreamingMatMul latency.
//
// Secondary target: Cache-blocking / tiling for the dequant+dot tile loop
// to improve L1/L2 locality when K=3072 exceeds cache line size.
//
// Do NOT target: dequantization, acquisition, threading, residency.
// These are confirmed non-bottlenecks by B013.

} // namespace b013

#endif // B013_COMPUTE_DECOMPOSITION_H
