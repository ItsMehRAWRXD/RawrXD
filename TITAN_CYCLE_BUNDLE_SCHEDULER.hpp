#pragma once
#include <string>
#include <sstream>
#include <vector>

// =============================================================================
// TITAN CYCLE BUNDLE SCHEDULER (SOFTWARE VLIW PIPELINE)
// =============================================================================
// Transitions the engine from "loop execution" to "cycle-accurate bundle scheduling".
// We treat the x86 Out-of-Order execution engine as an in-order VLIW machine
// by issuing exactly the correct ratio of instructions per cycle to perfectly
// map to the underlying execution ports without invoking the rename bottleneck.
// =============================================================================

namespace Titan {
namespace Compiler {

    struct MicroOpBundle {
        std::string port_0_1_fma;   // Compute operations (FMA)
        std::string port_2_3_agu;   // Address Generation + Load
        std::string port_5_alu;     // Logic, Shuffle, or Pointer Math
        std::string comment;
    };

    class CycleBundleScheduler {
    public:
        // Generates a VLIW-like execution graph locked to the FMA latency
        static std::string EmitSoftwarePipelinedGraph(int accumulators = 8, bool use_zmm = false) {
            std::stringstream ss;
            std::string reg_prefix = use_zmm ? "zmm" : "ymm";
            
            ss << "; ==================================================================\n";
            ss << "; SOFTWARE-PIPELINED CYCLE BUNDLE ENGINE\n";
            ss << "; Regime: TRUE COMPUTE-BOUND (Stage C)\n";
            ss << "; ==================================================================\n";
            ss << ".vliw_bundle_loop:\n\n";

            // In a fully unrolled block, we interleave instructions such that
            // every cycle bundle explicitly utilizes 1 Load, 1-2 FMA, and 1 ALU.
            
            for (int i = 0; i < accumulators; i++) {
                int load_offset = i * (use_zmm ? 64 : 32);
                int acc_idx = i;
                
                ss << "    ; --- BUNDLE " << i << " ---\n";
                // Port 2 or 3: Load next activation
                ss << "    vmovups " << reg_prefix << "0, [rsi + " << std::hex << load_offset << "h]  ; AGU Port 2/3\n";
                
                // Port 0 or 1: Fused Multiply-Add
                // Using ymm8 as the broadcasted weight
                ss << "    vfmadd231ps " << reg_prefix << acc_idx << ", " << reg_prefix << "0, " << reg_prefix << "8 ; FMA Port 0/1\n";
                
                // Port 5: Loop math or prefetch scattered into the ALU slot to avoid FMA contention
                if (i == 0) {
                    // Inject prefetch into the first bundle's AGU/ALU slack
                    ss << "    prefetcht0 [rsi + 200h]            ; AGU Port 2/3 Hint\n";
                } else if (i == accumulators - 1) {
                    // Update pointer in the last bundle
                    ss << "    add rsi, " << std::hex << (accumulators * (use_zmm ? 64 : 32)) << "h      ; ALU Port 1/5\n";
                } else if (i == accumulators - 2) {
                    // Compare against boundary
                    ss << "    cmp rsi, rbx                     ; ALU Port\n";
                } else {
                    ss << "    ; (ALU Slot Idle)\n";
                }
                
                ss << "\n";
            }

            // Macro-fused branch to top
            ss << "    jb .vliw_bundle_loop             ; Branch Port\n\n";

            return ss.str();
        }
    };

} // namespace Compiler
} // namespace Titan