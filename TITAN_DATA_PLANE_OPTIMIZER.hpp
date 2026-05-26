#pragma once
#include <string>
#include <sstream>

// =============================================================================
// TITAN DATA PLANE OPTIMIZER
// =============================================================================
// Transitions the architecture into Memory Hierarchy Management. 
// Uses Non-Temporal (NT) hints (vmovntps / vmovntdq) to bypass the cache hierarchy 
// when writing large accumulation buffers out to main memory, preventing cache pollution
// and sustaining peak L1 bandwidth for the fused execution pipeline.
// =============================================================================

namespace Titan {
namespace Memory {

    class DataPlaneOptimizer {
    public:
        // Cache size heuristic (e.g., L3 size assumption)
        static constexpr size_t L3_CACHE_THRESHOLD_BYTES = 8 * 1024 * 1024; // 8MB

        enum class StoreStrategy {
            TEMPORAL_CACHED,
            NON_TEMPORAL_BYPASS
        };

        static StoreStrategy DetermineStoreStrategy(size_t buffer_size) {
            // If the buffer exceeds the typical L3 threshold, streaming stores 
            // prevent thrashing the cache hierarchy.
            if (buffer_size >= L3_CACHE_THRESHOLD_BYTES) {
                return StoreStrategy::NON_TEMPORAL_BYPASS;
            }
            return StoreStrategy::TEMPORAL_CACHED;
        }

        static std::string EmitStoreInstruction(int ymm_src, const std::string& dest_operand, StoreStrategy strategy) {
            std::stringstream ss;
            if (strategy == StoreStrategy::NON_TEMPORAL_BYPASS) {
                ss << "    vmovntps " << dest_operand << ", ymm" << ymm_src << " ; NT Store (Cache Bypass)";
            } else {
                ss << "    vmovups " << dest_operand << ", ymm" << ymm_src << "  ; Temporal Store (Cached)";
            }
            return ss.str();
        }

        static std::string EmitHorizontalReductionAndStore(StoreStrategy strategy) {
            std::stringstream ss;
            ss << "; --- HORIZONTAL REDUCTION & STORE PHASE (N=8) ---\n";
            // 8-to-1 reduction map
            ss << "    vaddps ymm0, ymm0, ymm1\n";
            ss << "    vaddps ymm2, ymm2, ymm3\n";
            ss << "    vaddps ymm4, ymm4, ymm5\n";
            ss << "    vaddps ymm6, ymm6, ymm7\n";

            ss << "    vaddps ymm0, ymm0, ymm2\n";
            ss << "    vaddps ymm4, ymm4, ymm6\n";

            ss << "    vaddps ymm0, ymm0, ymm4\n";

            // Final store using optimal Data Plane Strategy
            ss << EmitStoreInstruction(0, "[rdi]", strategy) << "\n";
            
            // SFENCE required after non-temporal stores to ensure memory ordering
            if (strategy == StoreStrategy::NON_TEMPORAL_BYPASS) {
                ss << "    sfence ; Memory barrier for NT stores\n";
            }
            return ss.str();
        }
    };

} // namespace Memory
} // namespace Titan