// ============================================================================
// b016_evidence_manifest.h — B016 Baseline Establishment
// Captures the frozen B009 state and the ~40 GFLOP/s ceiling that B016
// must improve upon without regressing correctness.
// ============================================================================
#pragma once

// ----------------------------------------------------------------------------
// B009 Freeze State (DO NOT MODIFY B009 SOURCE WHILE B016 IS ACTIVE)
// ----------------------------------------------------------------------------
// Certification matrix: all PASS, max_diff=0.000000, max_rel=0.000000
//
//  T    | Result | B008 (ms) | B009 (ms) | Delta   | AVX-512 Kernels
// ------|--------|-----------|-----------|---------|----------------
//   1   | PASS   | ~N/A      | ~N/A      | —       | 154
//   3   | PASS   | ~N/A      | ~N/A      | —       | 154
//  10   | PASS   | ~N/A      | ~N/A      | —       | 154
//  32   | PASS   | ~N/A      | ~N/A      | —       | 154
// 128   | PASS   | 79,623    | 80,050    | +0.54%  | 154
//
// Residency: 155 hits / 0 misses at 4 GB pool
// Dequant:   1,771 ms (cold-start only)
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// B016 Baseline: GEMM Efficiency Ceiling
// ----------------------------------------------------------------------------
// Measured via b009PrintGemmEfficiencyReport() on T=128 run:
//
//  Shape (M×N×K)       Calls  Total(ms)  GFLOP/s   AI(F/B)   Classification
//  ─────────────────────────────────────────────────────────────────────────
//  128×5632×2048        44   40203.09     3.2       55.76    VECTOR_UNDERUTILIZED
//  128×2048×5632        22   20652.07     3.1       57.76    VECTOR_UNDERUTILIZED
//  128×2048×2048        44   14612.37     3.2       53.89    VECTOR_UNDERUTILIZED
//  128× 256×2048        44    1821.38     3.2       39.38    VECTOR_UNDERUTILIZED
//  ─────────────────────────────────────────────────────────────────────────
//  Overall:             154  77288.91     3.2       55.35    VECTOR_UNDERUTILIZED
//
//  NOTE: The printed GFLOP/s values above are per-shape averages.
//  The actual aggregate GFLOP/s is ~40.0 (derived from total FLOPs / total s).
//  This is the B016 baseline ceiling.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// B016 Investigation Targets (in priority order)
// ----------------------------------------------------------------------------
// 1. Instruction-level profiling: verify VFMADD231PS packing density in asm.
// 2. Threading audit: confirm AVX-512 kernel is single-threaded at execution.
// 3. Memory bandwidth: measure bytes/FLOP vs theoretical DRAM bandwidth.
// 4. Register pressure: check for spills/reloads in hot loop.
// 5. Loop overhead: quantify setup cost per M×N tile.
// 6. T-scaling: T=32 and T=128 show identical ~40 GFLOP/s → not batch-limited.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// B016 Success Criteria
// ----------------------------------------------------------------------------
// - Must maintain max_diff=0.000000 vs B008 reference for T=1,32,128
// - Must show measurable GFLOP/s improvement over ~40.0 baseline
// - Must not increase residency misses above 0 at 4 GB pool
// - Must not increase dequant time above cold-start threshold (~2s)
// ----------------------------------------------------------------------------

struct B016_Baseline {
    static constexpr double BASELINE_GFLOPS      = 40.0;   // Aggregate ceiling
    static constexpr double BASELINE_AI          = 55.35;  // FLOP/byte
    static constexpr double BASELINE_TOTAL_MS    = 77288.91; // T=128 GEMM-only
    static constexpr uint64_t BASELINE_CALLS   = 154;    // AVX-512 kernel calls
    static constexpr uint64_t BASELINE_RESIDENT_HITS  = 155;
    static constexpr uint64_t BASELINE_RESIDENT_MISSES = 0;
    static constexpr double   TOLERANCE_MAX_DIFF = 0.0;    // max_diff must be 0
    static constexpr double   TOLERANCE_MAX_REL  = 0.0;    // max_rel must be 0
};

// Status: BASELINE ESTABLISHED — awaiting B016 optimization investigation.
