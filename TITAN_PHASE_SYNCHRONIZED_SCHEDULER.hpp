#pragma once
#include <string>
#include <sstream>

// =============================================================================
// TITAN PHASE-SYNCHRONIZED TILE SCHEDULER
// =============================================================================
// Implements "Queue Equilibrium Execution" where Performance (T) is:
// T = min(BW_L1_L2, ROB_drain, FMA_ports, AGU_ports)
//
// This decoupled control system phase-locks:
// 1. Accumulator lifetime (FMA latency horizon)
// 2. Prefetch distance (ROB occupancy window alignment)
// 3. Tile size (L1 fill cadence)
// 4. Unroll depth (Scheduler wakeup/dependency DAG width)
// =============================================================================

namespace Titan {
namespace Scheduler {

    struct PhaseSynchronizedParameters {
        int unrollDepth;          // Scheduler saturation geometry (DAG width)
        int tileSizeBytes;        // L1 fill cadence alignment
        int prefetchDistanceBytes;// ROB occupancy window alignment 
        int accumulators;         // FMA latency horizon matching
    };

    class PhaseLockController {
    public:
        // Calculates the intersection where all 4 hardware constraints equilibrate.
        // N=8 remains the stable fixed point.
        static constexpr PhaseSynchronizedParameters CalculateEquilibrium(
            int robSize = 256,       // Microarchitectural ROB capacity
            int uOpsPerIter = 10     // Estimated micro-fused op footprint
        ) {
            PhaseSynchronizedParameters params;
            // The dependency graph diameter that saturates the FMA latency window (4-5 cycles)
            params.accumulators = 8;
            params.unrollDepth = 8;
            
            // Tile size aligned to L1 fill cadence (e.g., 256 bytes per 8x YMM iterations)
            params.tileSizeBytes = params.accumulators * 32;

            // Phase the prefetch distance exactly to the ROB occupancy boundary.
            // If the ROB holds ~256 instructions and an iteration is ~10 uOps, 
            // the pipeline contains 25 in-flight iterations.
            // 25 iterations * 256 bytes = 6.4KB of in-flight ILP execution logic.
            // We set prefetch to bracket this window exactly.
            params.prefetchDistanceBytes = (robSize / uOpsPerIter) * params.tileSizeBytes;

            return params;
        }

        static std::string EmitCoupledControlLoop(const PhaseSynchronizedParameters& params) {
            std::stringstream ss;
            ss << "; ==================================================================\n";
            ss << "; TITAN PHASE-SYNCHRONIZED TILE SCHEDULER (QUEUE EQUILIBRIUM)\n";
            ss << "; ==================================================================\n";
            ss << "; Equilibrium Parameters:\n";
            ss << "; Accumulators: " << params.accumulators << " (Scheduler Graph Diameter)\n";
            ss << "; Tile Size: " << params.tileSizeBytes << " bytes (L1 Fill Cadence)\n";
            ss << "; Prefetch Phase Horizon: " << std::hex << params.prefetchDistanceBytes << "h bytes (ROB Occupancy)\n";
            ss << "; ==================================================================\n\n";
            
            ss << "    ; [Phase 0] L1 Pre-Fill Boundary (Overcoming initial cold-miss pipeline bubble)\n";
            for (int i = 0; i < params.tileSizeBytes; i += 64) {
                 ss << "    prefetchnta [rsi + " << std::hex << i << "h]\n";
            }
            ss << "\n";

            ss << ".phase_locked_execution_loop:\n";
            ss << "    ; [Phase 1] Align Prefetch Memory Subsystem Queue to ROB drain rate\n";
            ss << "    prefetchnta [rsi + " << std::hex << params.prefetchDistanceBytes << "h]\n\n";

            ss << "    ; [Phase 2] Execution Graph Queue (Micro-fission: AGU + FMA via Scheduler Wakeup)\n";
            ss << "    ; Retire system continuously drains 8-wide window seamlessly.\n";
            for (int i = 0; i < params.accumulators; ++i) {
                // ymm(i) = ymm(i) + (ymm(i+8) * [mem])
                ss << "    vfmadd231ps ymm" << i << ", ymm" << (i + 8) << ", [rsi + " << std::hex << (i * 32) << "h]\n";
            }
            
            ss << "\n";
            ss << "    ; [Phase 3] Advance Memory Subsystem Queue Alignment\n";
            ss << "    add rsi, " << std::hex << params.tileSizeBytes << "h\n";
            ss << "    cmp rsi, rbx\n";
            ss << "    jb .phase_locked_execution_loop\n";

            return ss.str();
        }
    };

} // namespace Scheduler
} // namespace Titan