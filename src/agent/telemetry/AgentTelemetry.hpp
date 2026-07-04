// AgentTelemetry.hpp — C++ wrapper for MASM telemetry
// Include in ArenaAllocator, Agent loops, and Swarm channels

#pragma once
#include <cstdint>
#include <atomic>

// ============================================================================
// EXTERN DECLARATIONS — MASM functions
// ============================================================================
extern "C" {
    void AgentTelemetry_RecordAllocation(uint64_t size);
    void AgentTelemetry_RecordFree(uint64_t size);
    uint64_t AgentTelemetry_GetArenaUsed(void);
    void AgentTelemetry_Reset(void);
    void AgentTelemetry_RecordProposalGenerated(void);
    void AgentTelemetry_RecordProposalApplied(void);
    void AgentTelemetry_RecordLoopIteration(void);
    void AgentTelemetry_RecordSwarmLatency(uint64_t microseconds);
    void AgentTelemetry_UpdateStateChecksum(uint64_t checksum);
    void AgentTelemetry_DumpToBuffer(void* outBuffer);
}

// ============================================================================
// C++ WRAPPER — RAII helpers for automatic instrumentation
// ============================================================================

namespace RawrXD {
namespace Telemetry {

// Scoped allocation tracker (RAII)
class ScopedAllocation {
    uint64_t m_size;
public:
    explicit ScopedAllocation(uint64_t size) : m_size(size) {
        AgentTelemetry_RecordAllocation(size);
    }
    ~ScopedAllocation() {
        AgentTelemetry_RecordFree(m_size);
    }
    // Non-copyable
    ScopedAllocation(const ScopedAllocation&) = delete;
    ScopedAllocation& operator=(const ScopedAllocation&) = delete;
};

// Scoped latency tracker (TSC-based)
class ScopedLatency {
    uint64_t m_startTsc;
    double m_tscFreqGHz;
public:
    ScopedLatency() {
        m_startTsc = __rdtsc();
        // TSC frequency calibration would go here
        m_tscFreqGHz = 3.0; // Assume 3GHz for now
    }
    ~ScopedLatency() {
        uint64_t elapsedTsc = __rdtsc() - m_startTsc;
        uint64_t elapsedUs = static_cast<uint64_t>(
            elapsedTsc / (m_tscFreqGHz * 1000.0)
        );
        AgentTelemetry_RecordSwarmLatency(elapsedUs);
    }
};

// Inline helpers for hot paths
inline void RecordAllocation(uint64_t size) {
    AgentTelemetry_RecordAllocation(size);
}

inline void RecordFree(uint64_t size) {
    AgentTelemetry_RecordFree(size);
}

inline void RecordProposalGenerated() {
    AgentTelemetry_RecordProposalGenerated();
}

inline void RecordProposalApplied() {
    AgentTelemetry_RecordProposalApplied();
}

inline void RecordLoopIteration() {
    AgentTelemetry_RecordLoopIteration();
}

inline uint64_t GetArenaUsed() {
    return AgentTelemetry_GetArenaUsed();
}

inline void Reset() {
    AgentTelemetry_Reset();
}

} // namespace Telemetry
} // namespace RawrXD

// ============================================================================
// CONVENIENCE MACROS — Drop-in instrumentation
// ============================================================================

// Track allocation in current scope
#define TELEMETRY_ALLOC(size) \
    RawrXD::Telemetry::ScopedAllocation _telemetry_alloc(size)

// Track latency in current scope
#define TELEMETRY_LATENCY() \
    RawrXD::Telemetry::ScopedLatency _telemetry_latency

// Increment counters
#define TELEMETRY_PROPOSAL_GENERATED() \
    AgentTelemetry_RecordProposalGenerated()

#define TELEMETRY_PROPOSAL_APPLIED() \
    AgentTelemetry_RecordProposalApplied()

#define TELEMETRY_LOOP_ITERATION() \
    AgentTelemetry_RecordLoopIteration()

// Raw allocation tracking (for manual use)
#define TELEMETRY_RECORD_ALLOC(size) \
    AgentTelemetry_RecordAllocation(size)

#define TELEMETRY_RECORD_FREE(size) \
    AgentTelemetry_RecordFree(size)
