// ============================================================================
// OSResource.hpp — Universal Resource Objects
// CPU, GPU, RAM, Storage, Network, etc. become first-class runtime objects
// with a common contract. The registry tracks their state.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <atomic>
#include <vector>
#include <chrono>

namespace RawrXD::OS {

// ---------------------------------------------------------------------------
// Resource kinds — exhaustive, fail-closed
// ---------------------------------------------------------------------------
enum class ResourceKind : uint8_t {
    Unknown     = 0,
    CPU         = 1,
    GPU         = 2,
    RAM         = 3,
    VRAM        = 4,
    Storage     = 5,
    Network     = 6,
    Display     = 7,
    Input       = 8,
    Filesystem  = 9,
    Process     = 10,
    Thread      = 11,
    IPC         = 12,
    Timer       = 13,
    Security    = 14,
    Power       = 15,
    VirtualMem  = 16,
    NUMA        = 17,
};

// ---------------------------------------------------------------------------
// Resource state
// ---------------------------------------------------------------------------
enum class ResourceState : uint8_t {
    Unknown     = 0,
    Available   = 1,   // Ready to be allocated
    Reserved    = 2,   // Held by a capability
    Busy        = 3,   // Actively in use
    Degraded    = 4,   // Partially available
    Exhausted   = 5,   // No capacity remaining
    Offline     = 6,   // Not present / removed
    Error       = 7,   // Fault detected
};

// ---------------------------------------------------------------------------
// Resource metrics — live measurement
// ---------------------------------------------------------------------------
struct ResourceMetrics {
    std::atomic<uint64_t> totalCapacity{0};    // Total available
    std::atomic<uint64_t> usedCapacity{0};     // Currently in use
    std::atomic<uint64_t> reservedCapacity{0}; // Reserved but not yet used
    std::atomic<uint64_t> peakUsage{0};        // Historical peak
    std::atomic<uint64_t> allocationCount{0};  // Total allocations
    std::atomic<uint64_t> releaseCount{0};     // Total releases

    uint64_t available() const {
        uint64_t total = totalCapacity.load();
        uint64_t used = usedCapacity.load();
        uint64_t reserved = reservedCapacity.load();
        return (total > used + reserved) ? total - used - reserved : 0;
    }

    double utilization() const {
        uint64_t total = totalCapacity.load();
        uint64_t used = usedCapacity.load();
        return total > 0 ? static_cast<double>(used) / total : 0.0;
    }
};

// ---------------------------------------------------------------------------
// Resource — first-class runtime object
// ---------------------------------------------------------------------------
struct Resource {
    std::string id;                 // Unique resource ID
    std::string name;               // Human-readable
    ResourceKind kind = ResourceKind::Unknown;
    ResourceState state = ResourceState::Unknown;
    ResourceMetrics metrics;

    // Owner tracking — which capability currently holds this resource
    std::atomic<uint64_t> holderCapabilityId{0};  // 0 = unowned

    // Platform-specific info
    std::string platformId;         // OS-level device ID / path
    std::string vendor;             // Hardware vendor
    std::string model;              // Hardware model

    // NUMA / topology
    uint32_t numaNode = 0;
    uint32_t socketId = 0;

    // Capabilities — what operations this resource supports
    std::vector<std::string> supportedOperations;

    // Can this resource be shared?
    bool shareable = true;
    bool hotSwappable = false;

    // Health
    std::atomic<bool> healthy{true};
    std::atomic<uint64_t> lastCheckedNs{0};

    // Metadata
    std::unordered_map<std::string, std::string> metadata;

    bool isAvailable(uint64_t amount = 1) const {
        return state == ResourceState::Available &&
               healthy.load() &&
               metrics.available() >= amount;
    }
};

// ---------------------------------------------------------------------------
// Resource allocation token — RAII-style reservation
// ---------------------------------------------------------------------------
struct ResourceAllocation {
    std::string resourceId;
    std::string capabilityId;
    uint64_t amount = 0;
    uint64_t allocatedAtNs = 0;
    bool exclusive = false;
    bool released = false;
};

} // namespace RawrXD::OS