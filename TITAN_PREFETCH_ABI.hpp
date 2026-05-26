#pragma once
#include <string>
#include <sstream>

// =============================================================================
// TITAN INSTRUCTION FUSION & PREFETCH ABI
// =============================================================================
// Defines the Host-to-Kernel contract for Cache-Line Pre-Warming.
// By utilizing PREFETCHNTA (Non-Temporal Prefetch), the memory controller 
// streams tensor blocks into a minimal cache footprint (usually avoiding L3 pollution)
// exactly just-in-time for the Fused Load-Op execution. This prevents the Memory
// Controller from stalling the decoupled execution execution ports.
// =============================================================================

namespace Titan {
namespace Memory {

    class PrefetchOrchestrator {
    public:
        // Calculate the temporal horizon based on DRAM latency vs Loop Cycle time.
        // Assuming ~200 cycles of DRAM latency and our fused N=8 loop processes 
        // 256 bytes every ~4-5 core cycles (when fully pipeline saturated).
        // Prefetch Distance = (DRAM_LATENCY / LOOP_CYCLES) * BYTES_PER_LOOP 
        //                   = (200 / 5) * 256 = 10,240 bytes roughly.
        static constexpr int PREFETCH_HORIZON_BYTES = 10 * 1024; // 10KB Look-ahead horizon

        static std::string EmitPreWarmPreamble(const std::string& stream_ptr = "rsi") {
            std::stringstream ss;
            
            ss << "; ==================================================================\n";
            ss << "; HOST-ABI: CACHE PRE-WARM HORIZON\n";
            ss << "; ==================================================================\n";
            ss << "; Dispatcher guarantees the first iterations are completely hot in L1\n";
            ss << "; before the instruction loop begins, masking initial memory fetch penalty.\n";
            
            // Pre-warm the first 256 bytes (4 cache lines = 1 iteration)
            for(int i = 0; i < 4; ++i) {
                ss << "    prefetchnta [" << stream_ptr << " + " << std::hex << (i * 64) << "h]\n";
            }
            ss << "\n";
            return ss.str();
        }

        static std::string EmitSteadyStatePrefetch(const std::string& stream_ptr = "rsi", int offset_interval_bytes = 64) {
            std::stringstream ss;
            ss << "    ; --- DISPATCHER CONTRACT: NON-TEMPORAL PREFETCH ---\n";
            // Emit PREFETCHNTA to prevent L3 cache thrashing (since large tensor 
            // streams are only read strictly once per pass during inference).
            ss << "    prefetchnta [" << stream_ptr << " + " << std::hex << PREFETCH_HORIZON_BYTES << "h]\n";
            return ss.str();
        }
    };

} // namespace Memory
} // namespace Titan