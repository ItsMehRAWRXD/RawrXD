// ============================================================================
// ArenaTelemetry.hpp - Memory Arena Telemetry for RawrXD Agent Stress Test
// ============================================================================
// Drop-in instrumentation for SovereignArena allocation tracking
// Thread-safe, minimal overhead on hot paths
//
// Copyright (c) 2026 RawrXD Project
// ============================================================================

#pragma once
#include <atomic>
#include <cstdint>
#include <cstddef>

#ifdef _WIN32
#include <intrin.h>  // For __rdtsc
#endif

namespace RawrXD {
namespace Telemetry {

// ============================================================================
// Arena Allocation Metrics
// ============================================================================
struct ArenaMetrics {
    // Memory tracking (bytes)
    std::atomic<uint64_t> totalAllocated{0};      // Total bytes ever allocated
    std::atomic<uint64_t> currentUsed{0};           // Current bump offset
    std::atomic<uint64_t> peakUsed{0};              // High water mark
    std::atomic<uint64_t> committedBytes{0};          // Actually committed
    
    // Operation counts
    std::atomic<uint64_t> allocCount{0};            // Number of allocations
    std::atomic<uint64_t> commitCalls{0};           // VirtualAlloc commits
    std::atomic<uint64_t> extensionCount{0};        // Arena chain length
    
    // Error tracking
    std::atomic<uint64_t> failedAllocs{0};          // Null returns
    std::atomic<uint64_t> oomEvents{0};             // Out-of-memory events
    
    // Fragmentation metrics
    std::atomic<uint64_t> alignmentWaste{0};        // Bytes lost to alignment
    std::atomic<uint64_t> slackSpace{0};             // Unused space at end
    
    // Timing (microseconds, sampled)
    std::atomic<uint64_t> allocTimeUs{0};            // Cumulative allocation time
    std::atomic<uint64_t> commitTimeUs{0};           // Cumulative commit time
    
    // Watermark monitoring
    float GetFragmentationRatio() const {
        uint64_t used = currentUsed.load();
        uint64_t waste = alignmentWaste.load();
        return used > 0 ? static_cast<float>(waste) / static_cast<float>(used) : 0.0f;
    }
    
    float GetUtilizationRatio() const {
        uint64_t used = currentUsed.load();
        uint64_t committed = committedBytes.load();
        return committed > 0 ? static_cast<float>(used) / static_cast<float>(committed) : 0.0f;
    }
    
    float GetAvgAllocTimeUs() const {
        uint64_t time = allocTimeUs.load();
        uint64_t count = allocCount.load();
        return count > 0 ? static_cast<float>(time) / static_cast<float>(count) : 0.0f;
    }
    
    void RecordAllocation(size_t size, size_t alignedSize) {
        totalAllocated += size;
        currentUsed += alignedSize;
        allocCount++;
        
        // Update peak
        uint64_t current = currentUsed.load();
        uint64_t peak = peakUsed.load();
        while (current > peak && !peakUsed.compare_exchange_weak(peak, current)) {}
        
        // Track alignment waste
        if (alignedSize > size) {
            alignmentWaste += (alignedSize - size);
        }
    }
    
    void RecordCommit(size_t bytes) {
        committedBytes += bytes;
        commitCalls++;
    }
    
    void RecordFailedAlloc() {
        failedAllocs++;
    }
    
    void RecordOomEvent() {
        oomEvents++;
    }
    
    void RecordExtension() {
        extensionCount++;
    }
    
    void Reset() {
        totalAllocated = 0;
        currentUsed = 0;
        peakUsed = 0;
        committedBytes = 0;
        allocCount = 0;
        commitCalls = 0;
        extensionCount = 0;
        failedAllocs = 0;
        oomEvents = 0;
        alignmentWaste = 0;
        slackSpace = 0;
        allocTimeUs = 0;
        commitTimeUs = 0;
    }
};

// ============================================================================
// Global Telemetry Instance
// ============================================================================
inline ArenaMetrics g_ArenaMetrics;

// ============================================================================
// RAII Timer for Allocation Latency (sampled)
// ============================================================================
class ScopedAllocTimer {
public:
    ScopedAllocTimer() : start_(ReadTimestamp()) {}
    
    ~ScopedAllocTimer() {
        uint64_t end = ReadTimestamp();
        uint64_t us = (end - start_) / 1000; // Approximate TSC to μs
        g_ArenaMetrics.allocTimeUs += us;
    }
    
private:
    uint64_t start_;
    
    static uint64_t ReadTimestamp() {
#ifdef _WIN32
        return __rdtsc();
#else
        // Fallback for non-Windows
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL + ts.tv_nsec / 1000;
#endif
    }
};

// ============================================================================
// Arena Guard - RAII wrapper with telemetry
// ============================================================================
template<typename ArenaType>
class InstrumentedArenaGuard {
public:
    explicit InstrumentedArenaGuard(ArenaType* arena) : arena_(arena) {}
    
    ~InstrumentedArenaGuard() {
        if (arena_) {
            // Log final metrics on destruction
            g_ArenaMetrics.slackSpace += CalculateSlack();
        }
    }
    
    // Disable copy/move
    InstrumentedArenaGuard(const InstrumentedArenaGuard&) = delete;
    InstrumentedArenaGuard& operator=(const InstrumentedArenaGuard&) = delete;
    InstrumentedArenaGuard(InstrumentedArenaGuard&&) = delete;
    InstrumentedArenaGuard& operator=(InstrumentedArenaGuard&&) = delete;
    
private:
    ArenaType* arena_;
    
    size_t CalculateSlack() const {
        // Arena-specific slack calculation
        return 0; // Override per arena type
    }
};

// ============================================================================
// Checkpoint Functions
// ============================================================================

// Get current metrics as JSON string (for logging)
inline std::string GetMetricsJson() {
    char buffer[1024];
    snprintf(buffer, sizeof(buffer),
        "{"
        "\"timestamp\":%llu,"
        "\"totalAllocated\":%llu,"
        "\"currentUsed\":%llu,"
        "\"peakUsed\":%llu,"
        "\"committed\":%llu,"
        "\"allocCount\":%llu,"
        "\"commitCalls\":%llu,"
        "\"extensions\":%llu,"
        "\"failedAllocs\":%llu,"
        "\"oomEvents\":%llu,"
        "\"alignmentWaste\":%llu,"
        "\"fragmentationRatio\":%.4f,"
        "\"utilizationRatio\":%.4f,"
        "\"avgAllocTimeUs\":%.4f"
        "}",
        static_cast<unsigned long long>(time(nullptr)),
        g_ArenaMetrics.totalAllocated.load(),
        g_ArenaMetrics.currentUsed.load(),
        g_ArenaMetrics.peakUsed.load(),
        g_ArenaMetrics.committedBytes.load(),
        g_ArenaMetrics.allocCount.load(),
        g_ArenaMetrics.commitCalls.load(),
        g_ArenaMetrics.extensionCount.load(),
        g_ArenaMetrics.failedAllocs.load(),
        g_ArenaMetrics.oomEvents.load(),
        g_ArenaMetrics.alignmentWaste.load(),
        g_ArenaMetrics.GetFragmentationRatio(),
        g_ArenaMetrics.GetUtilizationRatio(),
        g_ArenaMetrics.GetAvgAllocTimeUs()
    );
    return std::string(buffer);
}

// Reset all metrics (call at test start)
inline void ResetMetrics() {
    g_ArenaMetrics.Reset();
}

// Check if any critical thresholds exceeded
inline bool CheckCriticalThresholds() {
    // Fail if any allocations failed
    if (g_ArenaMetrics.failedAllocs.load() > 0) {
        return false;
    }
    
    // Warn if fragmentation > 30%
    if (g_ArenaMetrics.GetFragmentationRatio() > 0.30f) {
        // Log warning but don't fail
    }
    
    // Warn if > 100 arena extensions
    if (g_ArenaMetrics.extensionCount.load() > 100) {
        // Log warning but don't fail
    }
    
    return true;
}

} // namespace Telemetry
} // namespace RawrXD

// ============================================================================
// C-Compatible API for MASM Integration
// ============================================================================

extern "C" {

// Increment allocation counter from assembly
inline void RawrXD_Telemetry_RecordAlloc(uint64_t size, uint64_t alignedSize) {
    RawrXD::Telemetry::g_ArenaMetrics.RecordAllocation(size, alignedSize);
}

// Record failed allocation
inline void RawrXD_Telemetry_RecordFailedAlloc() {
    RawrXD::Telemetry::g_ArenaMetrics.RecordFailedAlloc();
}

// Record commit
inline void RawrXD_Telemetry_RecordCommit(uint64_t bytes) {
    RawrXD::Telemetry::g_ArenaMetrics.RecordCommit(bytes);
}

// Record extension
inline void RawrXD_Telemetry_RecordExtension() {
    RawrXD::Telemetry::g_ArenaMetrics.RecordExtension();
}

// Get metrics JSON (caller must free with RawrXD_FreeString)
const char* RawrXD_Telemetry_GetMetricsJson();

// Reset metrics
void RawrXD_Telemetry_Reset();

} // extern "C"
