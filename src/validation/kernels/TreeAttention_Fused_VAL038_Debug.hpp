#pragma once
#include <cstdint>
#include <cstddef>
#include <atomic>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-038 Debug Interface
// ═══════════════════════════════════════════════════════════════════════════════
// Exposes debug counters from assembly kernel for loop validation
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// Debug counters exported from assembly
extern "C" {
    extern uint64_t debug_q_iterations;      // Number of query iterations
    extern uint64_t debug_k_iterations;      // Number of key iterations (total)
    extern uint64_t debug_k_max_per_q;         // Max keys processed per query
    extern uint64_t debug_abort_counter;       // Watchdog abort trigger count
    extern uint64_t debug_iteration_count;     // Global iteration watchdog
}

// Reset all debug counters
inline void ResetDebugCounters() {
    debug_q_iterations = 0;
    debug_k_iterations = 0;
    debug_k_max_per_q = 0;
    debug_abort_counter = 0;
    debug_iteration_count = 0;
}

// Get debug statistics
struct DebugStats {
    uint64_t qIterations;
    uint64_t kIterations;
    uint64_t kMaxPerQ;
    uint64_t abortCount;
    uint64_t watchdogCount;
    float avgKeysPerQuery;
};

inline DebugStats GetDebugStats() {
    DebugStats stats;
    stats.qIterations = debug_q_iterations;
    stats.kIterations = debug_k_iterations;
    stats.kMaxPerQ = debug_k_max_per_q;
    stats.abortCount = debug_abort_counter;
    stats.watchdogCount = debug_iteration_count;
    stats.avgKeysPerQuery = (debug_q_iterations > 0) 
        ? (float)debug_k_iterations / debug_q_iterations 
        : 0.0f;
    return stats;
}

} // namespace RawrXD
