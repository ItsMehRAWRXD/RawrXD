// ============================================================================
// VRAMLease.hpp - MARS: Memory Allocation + Routing System
// Dynamic tensor ownership lease. No permanent GPU assignment.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Lease State
// ============================================================================
enum class LeaseState {
    UNASSIGNED,      // Not yet placed
    RESIDENT,        // On GPU VRAM
    MIGRATING,       // In-flight copy
    EVICTED,         // On host / SSD
    REBUILDING,      // Reconstructing from shards
    FAILED           // Faulted, needs recovery
};

// ============================================================================
// VRAM Lease
// GPU ownership becomes a lease, not a permanent assignment.
// ============================================================================
struct VRAMLease {
    uint64_t    tensorId      = 0;
    std::string name;           // Tensor name from GGUF

    int         currentGPU    = -1;   // -1 = host / unassigned
    int         preferredGPU  = -1;   // User or heuristic preference

    size_t      bytes         = 0;
    uint64_t    offset        = 0;    // Offset within GPU memory pool

    float       priority      = 1.0f; // Higher = less likely to evict
    bool        hotpatchable  = true; // Can be moved at runtime
    bool        pinned        = false; // If true, never migrate

    LeaseState  state         = LeaseState::UNASSIGNED;

    // Timing for migration decisions
    uint64_t    lastAccessTick = 0;
    uint64_t    migrateCount   = 0;

    // Fault recovery
    bool        needsRebuild   = false;
    int         originalGPU    = -1; // For rollback

    bool IsResident() const {
        return state == LeaseState::RESIDENT;
    }
    bool IsOnHost() const {
        return state == LeaseState::EVICTED || currentGPU < 0;
    }
};

// ============================================================================
// GPU State Snapshot
// ============================================================================
struct GPUState {
    int     index;
    size_t  vramTotal;
    size_t  vramFree;
    size_t  vramUsed;
    float   load;        // 0.0 - 1.0 compute utilization
    float   bandwidth;   // GB/s
    float   latencyMs;   // Average kernel latency
    bool    healthy;
};

// ============================================================================
// Dynamic Parity
// Runtime balancing state for dual-GPU systems.
// ============================================================================
struct DynamicParity {
    GPUState gpu[2];

    size_t vramFree(int idx) const {
        return (idx >= 0 && idx < 2) ? gpu[idx].vramFree : 0;
    }
    float load(int idx) const {
        return (idx >= 0 && idx < 2) ? gpu[idx].load : 1.0f;
    }
    float bandwidth(int idx) const {
        return (idx >= 0 && idx < 2) ? gpu[idx].bandwidth : 0.0f;
    }
    bool canMoveTensor(int from, int to) const {
        if (from < 0 || to < 0 || from >= 2 || to >= 2) return false;
        if (from == to) return true;
        if (!gpu[from].healthy || !gpu[to].healthy) return false;
        return true;
    }
    int bestGPUForBandwidth(size_t bytes) const {
        // Prefer GPU with more free VRAM for high-bandwidth tensors
        if (gpu[0].vramFree >= bytes && gpu[1].vramFree >= bytes) {
            return (gpu[0].bandwidth > gpu[1].bandwidth) ? 0 : 1;
        }
        if (gpu[0].vramFree >= bytes) return 0;
        if (gpu[1].vramFree >= bytes) return 1;
        return -1;
    }
    int bestGPUForLatency() const {
        // Prefer GPU with lower load for low-latency tensors
        if (gpu[0].latencyMs < gpu[1].latencyMs) return 0;
        return 1;
    }
};

} // namespace MARS
} // namespace Deep2
