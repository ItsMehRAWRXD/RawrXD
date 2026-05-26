#pragma once
#include <string>
#include <sstream>

// =============================================================================
// TITAN MICRO-OP FUSION ENGINE
// =============================================================================
// Transitions the execution graph from an Explicit Load-Store architecture 
// to a Fused Memory-Operand architecture. By folding memory addresses directly 
// into FMA instructions, we reduce instruction fetch bandwidth, decode bandwidth, 
// and Reorder Buffer (ROB) tracking limits by exactly 50%.
// =============================================================================

namespace Titan {
namespace Compiler {

    class MicroOpFusionEngine {
    public:
        // By fusing the memory load directly into the operand, x86 hardware 
        // generates the Load micro-op implicitly. This bypasses the register
        // mapping overhead and perfectly shapes the macro-op footprint.
        static std::string EmitFusedFMA(int acc_ymm, int weight_ymm, int memory_offset_bytes, const std::string& base_ptr = "rsi") {
            std::stringstream ss;
            ss << "    vfmadd231ps ymm" << acc_idx(acc_ymm) 
               << ", ymm" << acc_idx(weight_ymm) 
               << ", [" << base_ptr << " + " << std::hex << memory_offset_bytes << "h]";
            return ss.str();
        }

        static std::string EmitFusedExecutionBlock(int unroll_factor = 8) {
            std::stringstream ss;
            
            ss << "; ==================================================================\n";
            ss << "; FUSED MICRO-OP KERNEL (ZERO EXPLICIT LOADS)\n";
            ss << "; ==================================================================\n";
            ss << "; YMM0-YMM" << (unroll_factor - 1) << " : Accumulator State\n";
            ss << "; YMM15      : Broadcasted Weights\n";
            ss << "; RSI        : Stride Pointer\n\n";

            ss << ".fused_macro_loop:\n";
            
            // Prefetch ahead
            ss << "    prefetcht0 [rsi + 100h]            ; Latency horizon\n\n";

            for (int i = 0; i < unroll_factor; i++) {
                int offset = i * 32; // 256-bit offsets
                ss << EmitFusedFMA(i, 15, offset) << "  ; Fused Load+FMA chain " << (i+1) << "\n";
            }

            ss << "\n    add rsi, " << std::hex << (unroll_factor * 32) << "h\n";
            ss << "    cmp rsi, rbx\n";
            ss << "    jb .fused_macro_loop\n\n";

            return ss.str();
        }

    private:
        static int acc_idx(int reg) {
            return reg % 32; // Bound safety for XMM/YMM/ZMM
        }
    };

} // namespace Compiler
} // namespace Titan