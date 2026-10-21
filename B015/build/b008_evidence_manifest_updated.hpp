// ============================================================================
// B008: Evidence Manifest — Updated with B013 / B014 / B015
// ============================================================================
// Chronological gate registry. Append-only. Each gate frozen once certified.
// ============================================================================

#ifndef B008_EVIDENCE_MANIFEST_H
#define B008_EVIDENCE_MANIFEST_H

#include <cstdint>

namespace b008 {

// ============================================================================
// Gate B010: Baseline StreamingMatMul (weight residency OFF)
// ============================================================================
// Certified: 2026-08-10
// Hardware: AMD Radeon RX 7800 XT, 64 GB DDR5-5600, Zen 4
// Model:    unlock-1B (Q4_K_M)
//
// Metric                Value
// ------------------    -------
// Total time            70.86 ms
// Maps / unmaps         10
// Per-iteration         ~1.7 ms
// Dot-product (scalar)  ~58.7 ms
// Dequantization        ~4.2 ms
// Loop overhead         ~1.1 ms
//
// Status: FROZEN — baseline for all residency comparisons.
// ----------------------------------------------------------------------------
struct B010_Evidence {
    static constexpr double total_ms        = 70.86;
    static constexpr int    map_unmap_count = 10;
    static constexpr double dotproduct_ms   = 58.74;
    static constexpr double dequantize_ms   = 4.20;
    static constexpr double loop_ms         = 1.12;
    static constexpr bool   certified       = true;
};

// ============================================================================
// Gate B011: Weight Residency Cache ON
// ============================================================================
// Certified: 2026-08-10
// Same hardware / model as B010.
//
// Metric                Value
// ------------------    -------
// Total time            22.97 ms
// Maps / unmaps         1
// Cache hit rate        90%
//
// Speedup vs B010:      3.08×
//
// Threshold finding:
//   On fast config (~1.7 ms/iter) residency shows REGRESSION (0.92×, +8.8%).
//   Minimum viable latency for residency caching: ~3–4 ms per matmul.
//   Below threshold, cache-management overhead dominates.
//
// Status: FROZEN — residency validated with threshold documented.
// ----------------------------------------------------------------------------
struct B011_Evidence {
    static constexpr double total_ms        = 22.97;
    static constexpr int    map_unmap_count = 1;
    static constexpr double hit_rate        = 0.90;
    static constexpr double speedup_vs_b010 = 3.08;
    static constexpr double threshold_ms    = 3.5;  // min viable per-matmul
    static constexpr bool   certified       = true;
};

// ============================================================================
// Gate B013: B010→B011 Transition Archive
// ============================================================================
// Certified: 2026-08-10
// Commit:   Archive B010/B011 weight residency evidence with historical
//           3.08x speedup data and threshold analysis.
//
// Key invariant: Residency caching is NOT universally beneficial.
//                It is conditionally beneficial when per-matmul latency
//                exceeds the management overhead threshold (~3–4 ms).
//
// Status: FROZEN — transition evidence preserved in git history.
// ----------------------------------------------------------------------------
struct B013_Evidence {
    static constexpr double archived_speedup = 3.08;
    static constexpr double regression_case  = 0.92;  // fast-path regression
    static constexpr bool   certified        = true;
};

// ============================================================================
// Gate B014: AVX-512 Dot-Product Optimization + Runtime Decomposition
// ============================================================================
// Certified: 2026-08-10
// Target:    Replace scalar loop in StreamingMatMul with DotProduct_AVX512.
// Compile:   /arch:AVX512 (MSVC) required for __AVX512F__ macro.
//
// Metric                Before (Scalar)   After (AVX-512)   Speedup
// ------------------    ----------------  ---------------   -------
// Dot-product           58.74 ms          5.68 ms           10.3×
// Total StreamingMatMul 68.40 ms          15.54 ms          4.4×
// Dequantization        4.20 ms           4.17 ms           ~1×
// Loop overhead         1.12 ms           1.17 ms           ~1×
//
// Runtime Decomposition (measured via B014 profiler, 590 invocations):
//   mean_total_ms   = 14.184 ms
//   mean_acq_ms     = 0.000 ms   (0.00%)
//   mean_dequant_ms = 4.127 ms  (29.10%)
//   mean_dot_ms     = 9.890 ms  (69.73%)
//   mean_overhead_ms= 0.167 ms   (1.18%)
//   aggregate_total = 8368.671 ms
//
// Bottleneck shift:     Dot-product → Dequantization (4.127 ms now dominant).
// Next gate:            B015 (dequantization vectorization).
//
// Status: FROZEN — kernel in tests/b014_avx512_dotproduct_certification.h
// ----------------------------------------------------------------------------
struct B014_Evidence {
    static constexpr double dotproduct_scalar_ms = 58.74;
    static constexpr double dotproduct_avx512_ms = 5.68;
    static constexpr double dotproduct_speedup   = 10.34;
    static constexpr double total_scalar_ms      = 68.40;
    static constexpr double total_avx512_ms      = 15.54;
    static constexpr double total_speedup        = 4.40;
    // Runtime-certified per-invocation means (B014 profiler, decode_length=1)
    static constexpr double runtime_mean_total_ms   = 14.184;
    static constexpr double runtime_mean_acq_ms     = 0.000;
    static constexpr double runtime_mean_dequant_ms = 4.127;
    static constexpr double runtime_mean_dot_ms     = 9.890;
    static constexpr double runtime_mean_overhead_ms= 0.167;
    static constexpr double runtime_dequant_pct     = 29.10;
    static constexpr double runtime_dot_pct         = 69.73;
    static constexpr double runtime_overhead_pct    = 1.18;
    static constexpr bool   certified               = true;
};

// ============================================================================
// Gate B015: AVX-512 Q4_K_M Dequantization (READY FOR CERTIFICATION)
// ============================================================================
// Target:    Vectorize Q4_K_M 4-bit unpack + scale/min apply.
// Expected:  2–4× dequantization speedup (4.127 ms → ~1.0–2.0 ms).
// Kernel:    b015::DequantizeBlock_Q4K_AVX512()
// File:      B015/build/b015_dequantize_q4k_avx512.hpp
//
// Precondition: __AVX512F__ + /arch:AVX512 compile flag.
// Fallback:     b015::DequantizeBlock_Q4K_Scalar() (bit-exact reference).
//
// B014 Baseline (runtime-certified):
//   mean_dequant_ms = 4.127 ms (29.10% of per-invocation total)
//   This is the control path against which B015 speedup is measured.
//
// Status: READY FOR CERTIFICATION — kernel staged, correctness + benchmark
//         required before production integration.
// ----------------------------------------------------------------------------
struct B015_Evidence {
    static constexpr double b014_baseline_dequant_ms = 4.127;  // Runtime-certified
    static constexpr double b014_baseline_total_ms     = 14.184; // Runtime-certified
    static constexpr double goal_dequantize_ms         = 1.50;   // 2.75× target
    static constexpr double goal_total_ms              = 11.50;  // 14.184 - 2.6
    static constexpr bool   certified                  = false;  // pending correctness+benchmark
};

// ============================================================================
// Gate B016: Loop / Packing Overhead (QUEUED)
// ============================================================================
// Target:    tile_buf allocation/reuse, iteration setup cost.
// Baseline:  1.17 ms loop overhead (B014 post-AVX512).
// Expected:  1.5–2× via pre-allocated tile pool or stack tiles.
//
// Status: QUEUED — blocked on B015 certification.
// ----------------------------------------------------------------------------
struct B016_Evidence {
    static constexpr double baseline_loop_ms = 1.17;
    static constexpr bool   certified        = false;
};

// ============================================================================
// Gate B017: End-to-End Inference Sweep (QUEUED)
// ============================================================================
// Target:    B007-style prefill/decode on TinyLlama + Phi-3.
// Purpose:   Validate real-world impact of B014+B015 stack.
// Expected:  Measurable TPS improvement in decode path.
//
// Status: QUEUED — blocked on B015+B016 certification.
// ----------------------------------------------------------------------------
struct B017_Evidence {
    static constexpr bool certified = false;
};

// ============================================================================
// Aggregate summary
// ============================================================================
inline void PrintManifestSummary() {
    // B010 baseline
    // B011 residency (3.08× archived)
    // B013 transition archive
    // B014 AVX-512 dot-product (10.3× dot, 4.4× total)
    // B015 dequantization (pending)
    // B016 loop overhead (queued)
    // B017 e2e sweep (queued)
}

} // namespace b008

#endif // B008_EVIDENCE_MANIFEST_H
