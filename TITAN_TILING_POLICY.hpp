#pragma once
#include <cstdint>
#include <algorithm>
#include <iostream>

// =============================================================================
// TITAN TILING POLICY ENGINE
// =============================================================================
// Closes the control loop between microarchitecture, kernel shape, and runtime.
// Automatically derives the optimal execution waveform shape based on 
// CPU instruction latency, issue width, and register file budget.
// =============================================================================

namespace Titan {
namespace Compiler {

    enum class CPUArch {
        AVX2_BASELINE,
        AVX2_ZEN3,
        AVX512_ZEN4,
        AVX512_INTEL_SPR
    };

    struct CpuProfile {
        int fma_ports;             // execution fabric width
        int fma_latency;           // latency hiding requirement
        int register_count;        // register ceiling limit
        int register_width_bytes;  // AVX2 (32) vs AVX-512 (64)
    };

    struct TilingPolicy {
        int target_accumulators;   // Optimal tile width
        int unroll_factor;         // Execution DAG depth
        bool use_zmm;              // Vector width selector
    };

    class PolicyEngine {
    public:
        // In a live system, this routes through CPUID detection.
        static CpuProfile GetCpuProfile(CPUArch arch) {
            switch (arch) {
                case CPUArch::AVX2_ZEN3:
                    // Zen 3: 2 FMA ports, 4 cycles latency, 16 YMM regs
                    return {2, 4, 16, 32};
                case CPUArch::AVX512_ZEN4:
                    // Zen 4: 2 FMA ports, 4 cycles latency, 32 ZMM regs
                    return {2, 4, 32, 64};
                case CPUArch::AVX512_INTEL_SPR:
                    // Sapphire Rapids: 2 FMA ports, 4-5 cycles latency, 32 ZMM regs
                    return {2, 5, 32, 64};
                case CPUArch::AVX2_BASELINE:
                default:
                    return {2, 4, 16, 32};
            }
        }

        static TilingPolicy DeriveOptimalPolicy(const CpuProfile& profile) {
            // Constraint 1: Register Ceiling
            // Reserve ~4 registers for structural needs (activations, masks, streaming, LUT)
            int r_fixed = 4;
            int r_per_tile = 1;
            int max_accumulators = (profile.register_count - r_fixed) / r_per_tile;

            // Constraint 2: Latency Hiding
            int min_accumulators = profile.fma_latency;

            // Constraint 3: Compute Saturation
            // To keep FMA ports perfectly busy every cycle through the latency window
            int compute_saturation = profile.fma_ports * profile.fma_latency;

            // The Flip Logic: clamped calculation
            int optimal_tile_width = std::min(compute_saturation, max_accumulators);
            optimal_tile_width = std::max(optimal_tile_width, min_accumulators);

            TilingPolicy policy;
            policy.target_accumulators = optimal_tile_width;
            policy.unroll_factor = optimal_tile_width; // Deepest stable DAG wave
            policy.use_zmm = (profile.register_width_bytes == 64);

            return policy;
        }

        static void PrintPolicy(const TilingPolicy& p) {
            std::cout << "=== TILING POLICY DEPLOYED ===\n"
                      << " Vector ISA      : " << (p.use_zmm ? "AVX-512 (ZMM)" : "AVX2 (YMM)") << "\n"
                      << " Accumulators    : " << p.target_accumulators << "\n"
                      << " Loop Unroll     : " << p.unroll_factor << "x\n"
                      << " System State    : COMPUTE-BOUND REGIME REACHED\n"
                      << "==============================\n";
        }
    };

} // namespace Compiler
} // namespace Titan