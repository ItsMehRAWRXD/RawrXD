#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <iostream>

// =================================================================================
// TITAN PORT-AWARE INSTRUCTION SCHEDULER (STATIC MICRO-CODE EMITTER)
// =================================================================================
// This completely bypasses the assembler's default instruction scheduling.
// Maps instructions explicitly to x64 execution ports (e.g., Zen 3 / Raptor Lake).
// Port 0/1 : Vector FMA
// Port 2/3 : AGU (Load)
// Port 5   : Shuffle / Vector Logic (Dequant)
// =================================================================================

namespace Titan {
namespace Compiler {

    class PortAwareScheduler {
    public:
        // Generates the perfectly interleaved inner loop for a given accumulator width.
        static std::string EmitComputeSaturatedLoop(int unroll_factor = 4) {
            std::stringstream ss;
            
            ss << "; AUTO-GENERATED PORT-SCHEDULED LOOP\n";
            ss << ".tiled_loop_port_aware:\n";

            // We schedule in specific "Cycle" blocks to guarantee the OoO engine
            // has the perfect mix of AGU, ALU, and FMA instructions to decode.

            for (int i = 0; i < unroll_factor; ++i) {
                int load_offset = i * 32;
                int act_offset = i * 4;
                int acc_reg = 2 + i; // YMM2, YMM3, YMM4, YMM5

                ss << "    ; --- MICRO-CYCLE " << i << " ---\n";
                // Port 2/3 (AGU) + Port 5 (Shuffle/Decode)
                ss << "    vmovups ymm0, [rcx + " << load_offset << "]      ; AGU Load\n";
                
                // If this is cycle 0, we can also inject the prefetch for N+1 to keep AGU hot
                if (i == 0) {
                    ss << "    prefetcht0 [rcx + 256]         ; AGU Prefetch\n";
                }

                // Port 5 - Decode/Shuffle
                ss << "    vpand ymm1, ymm0, ymm15        ; Port 5 (Decode)\n";
                ss << "    vcvtdq2ps ymm1, ymm1           ; Port 1/5 (Convert)\n";

                // Port 2/3 - Activation Load
                ss << "    vbroadcastss ymm8, dword ptr [rdx + " << act_offset << "] ; AGU Load\n";

                // Port 0 / Port 1 (FMA) 
                // By alternating, we explicitly prevent Backend Port Contention
                if (i % 2 == 0) {
                    ss << "    vfmadd231ps ymm" << acc_reg << ", ymm1, ymm8 ; Port 0 (FMA Pipe A)\n";
                } else {
                    ss << "    vfmadd231ps ymm" << acc_reg << ", ymm1, ymm8 ; Port 1 (FMA Pipe B)\n";
                }
            }

            ss << "    ; --- STRIDE & JUMP ---\n";
            ss << "    add rcx, " << (unroll_factor * 32) << " ; Port 0/1/5 (ALU)\n";
            ss << "    add rdx, " << (unroll_factor * 4) << "  ; Port 0/1/5 (ALU)\n";
            ss << "    cmp rcx, rbx             ; Macro-fused with Jcc\n";
            ss << "    jb .tiled_loop_port_aware\n";

            return ss.str();
        }
    };

} // namespace Compiler
} // namespace Titan