// AgentTelemetry.h — Non-blocking telemetry for 24h agent stress test
// Zero-overhead atomic counters, TSC-based latency measurement
// Build: Include in Agent_ExecuteCommand and swarm dispatcher

#ifndef AGENT_TELEMETRY_H
#define AGENT_TELEMETRY_H

#include <windows.h>
#include <cstdint>
#include <atomic>

// ============================================================================
// TELEMETRY STRUCT — 64-byte aligned for cache efficiency
// ============================================================================
#pragma pack(push, 1)
struct alignas(64) AgentTelemetry {
    // Memory metrics (updated per-command)
    std::atomic<uint64_t> vramUsed;           // GPU memory in bytes
    std::atomic<uint64_t> heapUsed;           // CPU heap in bytes
    std::atomic<uint64_t> peakVram;           // High water mark
    std::atomic<uint64_t> peakHeap;           // High water mark
    
    // Performance metrics (TSC-based)
    std::atomic<uint64_t> swarmLatencyTsc;    // Cumulative TSC ticks
    std::atomic<uint32_t> swarmMessageCount;  // Messages sent/received
    std::atomic<uint32_t> contextSwitches;    // OS switches per tick
    
    // State fidelity (hourly checkpoint hash)
    std::atomic<uint64_t> memoryFidelity;     // XXH64 of agent state
    std::atomic<uint32_t> fidelityVariance;   // Drift from baseline (x10000)
    
    // Workload metrics
    std::atomic<uint32_t> proposalsGenerated; // Code suggestions
    std::atomic<uint32_t> proposalsApplied;   // Actually patched
    std::atomic<uint32_t> filesIngested;      // Source files parsed
    std::atomic<uint32_t> errorsCaught;         // Exceptions handled
    
    // Timing
    uint64_t testStartTime;                   // GetTickCount64()
    uint64_t lastCheckpointTime;              // 15-min intervals
    
    // Padding to 64 bytes (cache line alignment)
    uint8_t _padding[64 - (8*4 + 8*2 + 4*8 + 8*2)];
};
#pragma pack(pop)

// ============================================================================
// GLOBAL INSTANCE — Thread-safe singleton
// ============================================================================
extern AgentTelemetry g_telemetry;

// ============================================================================
// INLINE HOOKS — Zero-overhead when disabled
// ============================================================================

// Initialize telemetry at test start
inline void Telemetry_Init() {
    memset(&g_telemetry, 0, sizeof(g_telemetry));
    g_telemetry.testStartTime = GetTickCount64();
    g_telemetry.lastCheckpointTime = g_telemetry.testStartTime;
}

// Memory snapshot (call at command entry)
inline void Telemetry_SnapshotMemory() {
    // Heap usage
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        uint64_t heap = pmc.WorkingSetSize;
        g_telemetry.heapUsed.store(heap, std::memory_order_relaxed);
        
        // Update peak
        uint64_t peak = g_telemetry.peakHeap.load(std::memory_order_relaxed);
        while (heap > peak && !g_telemetry.peakHeap.compare_exchange_weak(
            peak, heap, std::memory_order_relaxed)) {}
    }
    
    // VRAM (if GPU available - stub for now)
    // TODO: Query DXGI adapter for dedicated video memory
    // g_telemetry.vramUsed.store(vram, std::memory_order_relaxed);
}

// Swarm latency measurement (TSC-based)
inline uint64_t Telemetry_SwarmLatencyStart() {
    return __rdtsc();
}

inline void Telemetry_SwarmLatencyEnd(uint64_t startTsc) {
    uint64_t elapsed = __rdtsc() - startTsc;
    g_telemetry.swarmLatencyTsc.fetch_add(elapsed, std::memory_order_relaxed);
    g_telemetry.swarmMessageCount.fetch_add(1, std::memory_order_relaxed);
}

// Context switch tracking
inline void Telemetry_ContextSwitch() {
    g_telemetry.contextSwitches.fetch_add(1, std::memory_order_relaxed);
}

// Workload metrics
inline void Telemetry_ProposalGenerated() {
    g_telemetry.proposalsGenerated.fetch_add(1, std::memory_order_relaxed);
}

inline void Telemetry_ProposalApplied() {
    g_telemetry.proposalsApplied.fetch_add(1, std::memory_order_relaxed);
}

inline void Telemetry_FileIngested() {
    g_telemetry.filesIngested.fetch_add(1, std::memory_order_relaxed);
}

inline void Telemetry_ErrorCaught() {
    g_telemetry.errorsCaught.fetch_add(1, std::memory_order_relaxed);
}

// State fidelity (XXH64 hash of agent memory)
inline void Telemetry_UpdateFidelity(uint64_t stateHash) {
    g_telemetry.memoryFidelity.store(stateHash, std::memory_order_relaxed);
}

// ============================================================================
// AGENT COMMAND WRAPPER — Drop-in replacement for Agent_ExecuteCommand
// ============================================================================

typedef void (*AgentCommandFunc)(const char* cmd, char* output, size_t outLen);

inline void Telemetry_WrappedCommand(AgentCommandFunc fn, 
                                      const char* cmd, 
                                      char* output, 
                                      size_t outLen) {
    // Pre-command snapshot
    Telemetry_SnapshotMemory();
    uint64_t startTsc = __rdtsc();
    
    // Execute command
    fn(cmd, output, outLen);
    
    // Post-command metrics
    uint64_t elapsed = __rdtsc() - startTsc;
    Telemetry_SwarmLatencyEnd(startTsc);
    Telemetry_ContextSwitch();
}

// ============================================================================
// CHECKPOINTING — 15-minute intervals
// ============================================================================

struct TelemetryCheckpoint {
    uint64_t timestamp;
    AgentTelemetry snapshot;
    uint64_t stateHash;  // XXH64 of full telemetry struct
};

inline bool Telemetry_ShouldCheckpoint() {
    uint64_t now = GetTickCount64();
    uint64_t elapsed = now - g_telemetry.lastCheckpointTime;
    return elapsed > (15 * 60 * 1000);  // 15 minutes in ms
}

inline void Telemetry_DoCheckpoint(TelemetryCheckpoint* outCheckpoint) {
    outCheckpoint->timestamp = GetTickCount64();
    memcpy(&outCheckpoint->snapshot, &g_telemetry, sizeof(g_telemetry));
    
    // Simple hash of telemetry data
    uint64_t hash = 0x9E3779B97F4A7C15ULL;  // Golden ratio
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&g_telemetry);
    for (size_t i = 0; i < sizeof(g_telemetry); i += 8) {
        hash ^= *reinterpret_cast<const uint64_t*>(data + i);
        hash *= 0xC6A4A7935BD1E995ULL;  // FNV prime
    }
    outCheckpoint->stateHash = hash;
    
    g_telemetry.lastCheckpointTime = outCheckpoint->timestamp;
}

// ============================================================================
// EXPORTS FOR C LINKAGE
// ============================================================================

extern "C" {
    __declspec(dllexport) void AgentTelemetry_Init();
    __declspec(dllexport) void AgentTelemetry_Snapshot();
    __declspec(dllexport) uint64_t AgentTelemetry_GetHeapUsed();
    __declspec(dllexport) uint64_t AgentTelemetry_GetVramUsed();
    __declspec(dllexport) uint32_t AgentTelemetry_GetSwarmLatencyUs();
    __declspec(dllexport) uint64_t AgentTelemetry_GetMemoryFidelity();
    __declspec(dllexport) void AgentTelemetry_DumpToFile(const char* path);
}

#endif // AGENT_TELEMETRY_H
