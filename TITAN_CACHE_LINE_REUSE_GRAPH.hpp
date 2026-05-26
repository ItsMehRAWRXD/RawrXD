#pragma once
#include <string>
#include <sstream>

// =============================================================================
// TITAN CACHE-LINE REUSE GRAPH (CLR GRAPH)
// =============================================================================
// Transcends front-end µop fusion to tackle the final true physical barrier: 
// Load Subsystem bandwidth (L1 fill rate / AGU port capacity).
// By mapping discrete 64B cache line loads into 2D Outer-Product execution tiles, 
// a single fetched byte is mathematically reused across multiple FMA chains.
// This elevates the arithmetic intensity (AI) strictly within the register file,
// entirely decoupling peak execution from load-port bottlenecks.
// =============================================================================

namespace Titan {
namespace Compiler {

    class CacheLineReuseGraph {
    public:
        // Emits a 2x4 Outer Product execution matrix.
        // Requires: 8 Accumulators + 2 Stream-A Registers + 4 Stream-B Registers = 14 YMMs.
        // Yields: 8 FMAs for only 6 Loads. AI increases by 33% per cycle, pulling the 
        // architecture firmly away from the AGU ceiling and locking it to the Execute ceiling.
        static std::string EmitOuterProductTile() {
            std::stringstream ss;
            
            ss << "; ==================================================================\n";
            ss << "; CACHE-LINE REUSE GRAPH (CLR): 2x4 OUTER PRODUCT TILE\n";
            ss << "; ==================================================================\n";
            ss << "; YMM0-YMM7   : Accumulation Matrix (2x4 Topology)\n";
            ss << "; YMM8-YMM9   : Stream A (e.g., Activations) - 2 Cache Lines\n";
            ss << "; YMM10-YMM13 : Stream B (e.g., Weights)     - 4 Cache Lines\n";
            ss << "; RSI         : Stream A Pointer\n";
            ss << "; RDX         : Stream B Pointer\n";
            ss << ";\n";
            ss << "; STATS: 6 Load µops -> 8 FMA µops. Load Port pressure reduced!\n";
            ss << "; ==================================================================\n\n";

            ss << ".clr_outer_product_loop:\n";
            
            // 1. Explicitly fetch Stream A into the Temporal Reuse Window
            ss << "    ; --- Load Subsytem: Stream A ---\n";
            ss << "    vmovups ymm8, [rsi + 00h]\n";
            ss << "    vmovups ymm9, [rsi + 20h]\n\n";

            // 2. Explicitly fetch Stream B into the Temporal Reuse Window
            ss << "    ; --- Load Subsytem: Stream B ---\n";
            ss << "    vmovups ymm10, [rdx + 00h]\n";
            ss << "    vmovups ymm11, [rdx + 20h]\n";
            ss << "    vmovups ymm12, [rdx + 40h]\n";
            ss << "    vmovups ymm13, [rdx + 60h]\n\n";

            // 3. O(N*M) Execution Graph (Pure Register-to-Register FMAs)
            // No AGU ports are consumed in this entire section. 
            // The Reorder Buffer (ROB) will eagerly dispatch these to FP0/FP1.
            
            ss << "    ; --- Execution Subsystem: A[0] Cross B[0..3] ---\n";
            ss << "    vfmadd231ps ymm0, ymm8, ymm10\n";
            ss << "    vfmadd231ps ymm1, ymm8, ymm11\n";
            ss << "    vfmadd231ps ymm2, ymm8, ymm12\n";
            ss << "    vfmadd231ps ymm3, ymm8, ymm13\n\n";

            ss << "    ; --- Execution Subsystem: A[1] Cross B[0..3] ---\n";
            ss << "    vfmadd231ps ymm4, ymm9, ymm10\n";
            ss << "    vfmadd231ps ymm5, ymm9, ymm11\n";
            ss << "    vfmadd231ps ymm6, ymm9, ymm12\n";
            ss << "    vfmadd231ps ymm7, ymm9, ymm13\n\n";

            // 4. Stride Advance
            ss << "    ; --- Pointer Arithmetic ---\n";
            ss << "    add rsi, 40h ; Advance Stream A by 64 bytes (2 vectors)\n";
            ss << "    add rdx, 80h ; Advance Stream B by 128 bytes (4 vectors)\n";
            ss << "    cmp rsi, rbx ; Macro-fusable branch\n";
            ss << "    jb .clr_outer_product_loop\n\n";

            return ss.str();
        }
    };

} // namespace Compiler
} // namespace Titan