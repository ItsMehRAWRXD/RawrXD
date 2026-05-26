#pragma once
#include <string>
#include <sstream>

// =============================================================================
// TITAN ACCUMULATOR MODEL & PREFETCH ORCHESTRATOR
// =============================================================================
// Integrates Little's Law (WIP = Throughput * Latency) to derive the precise
// accumulator array size, and orchestrates L1/L2 prefetch hinting to ensure
// the memory subsystem delivers data just before the FP execution ports 
// consume it.
// =============================================================================

namespace Titan {
namespace Compiler {

    class AccumulatorModel {
    public:
        // By Little's Law: 
        // 2 FMA Ports * 4 Cycle Latency = 8 Accumulators
        static constexpr int OPTIMAL_UNROLL_FACTOR = 8;
        static constexpr int L1_PREFETCH_STRIDE_BYTES = 256; 
        static constexpr int L2_PREFETCH_STRIDE_BYTES = 512;

        static std::string EmitPrefetchedWavefront() {
            std::stringstream ss;
            
            ss << "; ==================================================================\n";
            ss << "; FUSED REGISTER-BLOCKED KERNEL (" << OPTIMAL_UNROLL_FACTOR << "x UNROLL) WITH L1 PREFETCH\n";
            ss << "; ==================================================================\n";
            ss << "; YMM0-YMM7 : Accumulator Chain\n";
            ss << "; YMM8      : Broadcasted Activation / Weight Block\n";
            ss << "; RSI       : Stream Pointer\n";
            ss << "; RBX       : End Boundary\n";

            ss << ".little_law_loop:\n";
            
            // Inject Prefetch Hinting (fetch for future iteration)
            ss << "    prefetcht0 [rsi + " << L1_PREFETCH_STRIDE_BYTES << "] ; L1 Prefetch (temporal locality)\n";
            ss << "    prefetcht1 [rsi + " << L2_PREFETCH_STRIDE_BYTES << "] ; L2 Prefetch (hide DRAM latency)\n\n";

            // Execution Chain
            for(int i = 0; i < OPTIMAL_UNROLL_FACTOR; i++) {
                int offset = i * 32; // 256-bit (32 bytes) per YMM
                // Port 0/1 interleaving is handled organically by OoO engine 
                // due to the completely independent destination registers.
                ss << "    vfmadd231ps ymm" << i << ", ymm8, [rsi + " << std::hex << offset << "h]  ; Chain " << (i+1) << "\n";
            }

            ss << "\n    add rsi, " << std::hex << (OPTIMAL_UNROLL_FACTOR * 32) << "h\n";
            ss << "    cmp rsi, rbx\n";
            ss << "    jb .little_law_loop\n\n";

            return ss.str();
        }

        static std::string EmitHorizontalReduction() {
            std::stringstream ss;
            ss << "; --- HORIZONTAL REDUCTION (" << OPTIMAL_UNROLL_FACTOR << " to 1) ---\n";
            // Tree reduction for 8 registers
            ss << "    vaddps ymm0, ymm0, ymm1\n";
            ss << "    vaddps ymm2, ymm2, ymm3\n";
            ss << "    vaddps ymm4, ymm4, ymm5\n";
            ss << "    vaddps ymm6, ymm6, ymm7\n";

            ss << "    vaddps ymm0, ymm0, ymm2\n";
            ss << "    vaddps ymm4, ymm4, ymm6\n";

            ss << "    vaddps ymm0, ymm0, ymm4 ; Final single 256-bit vector\n";
            return ss.str();
        }
    };

} // namespace Compiler
} // namespace Titan