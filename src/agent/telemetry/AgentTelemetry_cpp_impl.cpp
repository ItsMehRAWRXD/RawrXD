// AgentTelemetry_cpp_impl.cpp — C++ implementation matching MASM interface
// Use this when MASM object isn't available (MinGW builds)
// Exports same symbols as AgentTelemetry.asm for drop-in replacement

#include <windows.h>
#include <cstdint>
#include <atomic>

// ============================================================================
// TELEMETRY STRUCTURE — Matches MASM layout exactly
// ============================================================================
#pragma pack(push, 1)
struct alignas(64) AgentTelemetryStruct {
    std::atomic<uint64_t> arenaUsedBytes{0};
    std::atomic<uint64_t> vramUsedBytes{0};
    std::atomic<uint32_t> proposalsGenerated{0};
    std::atomic<uint32_t> proposalsApplied{0};
    std::atomic<uint64_t> totalSwarmLatencyUs{0};
    std::atomic<uint32_t> loopCount{0};
    std::atomic<uint64_t> stateChecksum{0};
    uint8_t _padding[64 - (8*2 + 4*2 + 8 + 4 + 8)];
};
#pragma pack(pop)

// Global instance - exported for C linkage
extern "C" {
    __declspec(dllexport) AgentTelemetryStruct g_telemetry;
    
    // Individual exports for direct access
    __declspec(dllexport) uint64_t g_AgentTelemetry_arenaUsedBytes = 0;
    __declspec(dllexport) uint64_t g_AgentTelemetry_vramUsedBytes = 0;
    __declspec(dllexport) uint32_t g_AgentTelemetry_proposalsGenerated = 0;
    __declspec(dllexport) uint32_t g_AgentTelemetry_proposalsApplied = 0;
    __declspec(dllexport) uint64_t g_AgentTelemetry_totalSwarmLatencyUs = 0;
    __declspec(dllexport) uint32_t g_AgentTelemetry_loopCount = 0;
    __declspec(dllexport) uint64_t g_AgentTelemetry_stateChecksum = 0;
}

// ============================================================================
// C INTERFACE FUNCTIONS — Match MASM exports exactly
// ============================================================================

extern "C" {

__declspec(dllexport) void AgentTelemetry_RecordAllocation(uint64_t size) {
    g_telemetry.arenaUsedBytes.fetch_add(size, std::memory_order_relaxed);
    g_AgentTelemetry_arenaUsedBytes = g_telemetry.arenaUsedBytes.load();
}

__declspec(dllexport) void AgentTelemetry_RecordFree(uint64_t size) {
    g_telemetry.arenaUsedBytes.fetch_sub(size, std::memory_order_relaxed);
    g_AgentTelemetry_arenaUsedBytes = g_telemetry.arenaUsedBytes.load();
}

__declspec(dllexport) uint64_t AgentTelemetry_GetArenaUsed(void) {
    return g_telemetry.arenaUsedBytes.load(std::memory_order_relaxed);
}

__declspec(dllexport) void AgentTelemetry_Reset(void) {
    g_telemetry.arenaUsedBytes.store(0, std::memory_order_relaxed);
    g_telemetry.vramUsedBytes.store(0, std::memory_order_relaxed);
    g_telemetry.proposalsGenerated.store(0, std::memory_order_relaxed);
    g_telemetry.proposalsApplied.store(0, std::memory_order_relaxed);
    g_telemetry.totalSwarmLatencyUs.store(0, std::memory_order_relaxed);
    g_telemetry.loopCount.store(0, std::memory_order_relaxed);
    g_telemetry.stateChecksum.store(0, std::memory_order_relaxed);
    
    // Update exported globals
    g_AgentTelemetry_arenaUsedBytes = 0;
    g_AgentTelemetry_vramUsedBytes = 0;
    g_AgentTelemetry_proposalsGenerated = 0;
    g_AgentTelemetry_proposalsApplied = 0;
    g_AgentTelemetry_totalSwarmLatencyUs = 0;
    g_AgentTelemetry_loopCount = 0;
    g_AgentTelemetry_stateChecksum = 0;
}

__declspec(dllexport) void AgentTelemetry_RecordProposalGenerated(void) {
    g_telemetry.proposalsGenerated.fetch_add(1, std::memory_order_relaxed);
    g_AgentTelemetry_proposalsGenerated = g_telemetry.proposalsGenerated.load();
}

__declspec(dllexport) void AgentTelemetry_RecordProposalApplied(void) {
    g_telemetry.proposalsApplied.fetch_add(1, std::memory_order_relaxed);
    g_AgentTelemetry_proposalsApplied = g_telemetry.proposalsApplied.load();
}

__declspec(dllexport) void AgentTelemetry_RecordLoopIteration(void) {
    g_telemetry.loopCount.fetch_add(1, std::memory_order_relaxed);
    g_AgentTelemetry_loopCount = g_telemetry.loopCount.load();
}

__declspec(dllexport) void AgentTelemetry_RecordSwarmLatency(uint64_t microseconds) {
    g_telemetry.totalSwarmLatencyUs.fetch_add(microseconds, std::memory_order_relaxed);
    g_AgentTelemetry_totalSwarmLatencyUs = g_telemetry.totalSwarmLatencyUs.load();
}

__declspec(dllexport) void AgentTelemetry_UpdateStateChecksum(uint64_t checksum) {
    g_telemetry.stateChecksum.store(checksum, std::memory_order_relaxed);
    g_AgentTelemetry_stateChecksum = checksum;
}

} // extern "C"
