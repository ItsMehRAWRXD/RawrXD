// =============================================================================
// RawRamXD.hpp - Software-Defined AI Memory Fabric
// =============================================================================
// A scheduler-controlled memory fabric that unifies VRAM, RAM, and storage
// into one predictive, telemetry-driven resource for AI inference
// =============================================================================

#ifndef RAWRAMXD_HPP
#define RAWRAMXD_HPP

#include <cstdint>
#include <cstddef>
#include <memory>
#include <atomic>
#include <vector>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <functional>
#include <chrono>

// =============================================================================
// RawRamXD Core Types
// =============================================================================

namespace rawramxd {

using Handle = uint64_t;
using VirtualAddress = uint64_t;
using PhysicalAddress = uint64_t;

// Memory tiers
enum class Tier : uint8_t {
    VRAM = 0,       // GPU VRAM - fastest, smallest
    RAM = 1,        // System RAM - medium speed
    NVMe = 2,       // NVMe/SSD - backing store
    HDD = 3,        // HDD - cold storage
    COUNT = 4
};

// Residency states
enum class ResidencyState : uint8_t {
    UNMAPPED = 0,       // Not allocated
    RESIDENT = 1,       // In current tier, ready
    MIGRATING = 2,      // Moving between tiers
    EVICTED = 3,        // In lower tier
    PREFETCHING = 4,    // Loading proactively
    FAULTING = 5        // On-demand load in progress
};

// Access patterns
enum class AccessPattern : uint8_t {
    WEIGHTS = 0,        // Read-mostly, large
    KV_CACHE = 1,       // Read-write, medium lifetime
    ACTIVATIONS = 2,    // Short-lived, compute-heavy
    SCRATCH = 3,       // Temporary buffers
    UNIFORM = 4         // Unknown/generic
};

// Migration priority
enum class MigrationPriority : uint8_t {
    CRITICAL = 0,       // Block compute until done
    HIGH = 1,           // ASAP, may overlap
    NORMAL = 2,         // Standard queue
    LOW = 3,            // Background, best effort
    PREFETCH = 4        // Speculative
};

// =============================================================================
// RawRamXD Handle - Every allocation gets one
// =============================================================================

struct RawRamXDHandle {
    Handle id;                          // Unique identifier
    VirtualAddress vaddr;               // Virtual address in fabric
    size_t size;                        // Size in bytes
    
    // Residency tracking
    Tier currentTier;                   // Where it lives now
    Tier preferredTier;                 // Where it wants to be
    ResidencyState state;               // Current state
    
    // Access statistics
    std::atomic<uint64_t> accessCount{0};
    std::atomic<uint64_t> lastAccessTime{0};
    std::atomic<uint64_t> bytesRead{0};
    std::atomic<uint64_t> bytesWritten{0};
    
    // Classification
    AccessPattern pattern;              // How it's used
    MigrationPriority priority;         // Migration urgency
    
    // Physical backing (opaque to users)
    void* physicalPtr;                  // Current physical location
    void* vramPtr;                      // If in VRAM
    void* ramPtr;                       // If in RAM
    void* nvmeHandle;                   // If in NVMe
    
    // Metadata
    const char* name;                   // Debug name
    uint32_t flags;                     // Behavior flags
};

// =============================================================================
// Telemetry & Statistics
// =============================================================================

struct TierStats {
    std::atomic<uint64_t> totalBytes{0};
    std::atomic<uint64_t> usedBytes{0};
    std::atomic<uint64_t> freeBytes{0};
    std::atomic<uint64_t> migrationInBytes{0};
    std::atomic<uint64_t> migrationOutBytes{0};
    std::atomic<uint64_t> faultCount{0};
    std::atomic<uint64_t> prefetchHits{0};
    std::atomic<uint64_t> prefetchMisses{0};
};

struct RawRamXDStats {
    TierStats tiers[static_cast<size_t>(Tier::COUNT)];
    
    // Performance metrics
    std::atomic<double> avgMigrationTimeMs{0.0};
    std::atomic<double> avgFaultLatencyMs{0.0};
    std::atomic<double> currentTPS{0.0};
    std::atomic<double> targetTPS{0.0};
    
    // Scheduler metrics
    std::atomic<uint64_t> migrationsQueued{0};
    std::atomic<uint64_t> migrationsCompleted{0};
    std::atomic<uint64_t> activePrefetches{0};
    std::atomic<uint64_t> residencyDecisions{0};
    
    // Memory pressure
    std::atomic<float> vramPressure{0.0f};      // 0.0 - 1.0
    std::atomic<float> ramPressure{0.0f};
    std::atomic<float> nvmeBandwidthUsed{0.0f};
};

// =============================================================================
// Residency Engine - The Brain
// =============================================================================

class ResidencyEngine {
public:
    virtual ~ResidencyEngine() = default;
    
    // Core residency decisions
    virtual Tier decidePlacement(const RawRamXDHandle* handle) = 0;
    virtual MigrationPriority decideUrgency(const RawRamXDHandle* handle) = 0;
    virtual bool shouldPrefetch(const RawRamXDHandle* handle) = 0;
    virtual bool shouldEvict(const RawRamXDHandle* handle) = 0;
    
    // Telemetry feedback
    virtual void onMigrationComplete(Handle handle, Tier from, Tier to, double latencyMs) = 0;
    virtual void onFault(Handle handle, Tier needed) = 0;
    virtual void onAccess(Handle handle, size_t bytes) = 0;
    virtual void updatePressure(Tier tier, float pressure) = 0;
    
    // Policy control
    virtual void setTargetTPS(double tps) = 0;
    virtual void setAggressiveness(float level) = 0;  // 0.0 = conservative, 1.0 = aggressive
};

// =============================================================================
// RawRamXD Fabric - Main API
// =============================================================================

class RawRamXDFabric {
public:
    static RawRamXDFabric& instance();
    
    // Initialization
    bool initialize(size_t vramSize, size_t ramSize, size_t nvmeSize);
    void shutdown();
    
    // Allocation API
    Handle allocate(size_t size, const char* name = nullptr, 
                    AccessPattern pattern = AccessPattern::UNIFORM);
    void deallocate(Handle handle);
    
    // Residency API
    bool ensureInVRAM(Handle handle);           // Block until in VRAM
    bool ensureInRAM(Handle handle);            // Block until at least in RAM
    void touch(Handle handle);                  // Mark as recently used
    void migrate(Handle handle, Tier target);   // Request migration
    void prefetch(Handle handle);               // Proactive load
    
    // Query API
    RawRamXDHandle* resolve(Handle handle);
    Tier currentTier(Handle handle);
    ResidencyState residency(Handle handle);
    bool isResident(Handle handle, Tier tier);
    
    // Telemetry
    RawRamXDStats stats();
    void trace(Handle handle, std::function<void(const RawRamXDHandle*)> callback);
    void dumpState();
    
    // Scheduler control
    void setResidencyEngine(std::unique_ptr<ResidencyEngine> engine);
    void setPolicy(const std::string& policy);  // "aggressive", "balanced", "conservative"
    
    // Integration hooks
    void* vramPtr(Handle handle);               // Get VRAM pointer if resident
    void* ramPtr(Handle handle);                // Get RAM pointer if resident
    
private:
    RawRamXDFabric() = default;
    ~RawRamXDFabric() = default;
    RawRamXDFabric(const RawRamXDFabric&) = delete;
    RawRamXDFabric& operator=(const RawRamXDFabric&) = delete;
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// =============================================================================
// C API for Integration
// =============================================================================

extern "C" {

// Lifecycle
bool rawramxd_init(uint64_t vram_bytes, uint64_t ram_bytes, uint64_t nvme_bytes);
void rawramxd_shutdown();

// Allocation
uint64_t rawramxd_alloc(size_t size, const char* name, uint8_t pattern);
void rawramxd_free(uint64_t handle);

// Residency
bool rawramxd_ensure_vram(uint64_t handle);
bool rawramxd_ensure_ram(uint64_t handle);
void rawramxd_touch(uint64_t handle);
void rawramxd_migrate(uint64_t handle, uint8_t tier);
void rawramxd_prefetch(uint64_t handle);

// Query
uint8_t rawramxd_current_tier(uint64_t handle);
uint8_t rawramxd_residency(uint64_t handle);
void* rawramxd_vram_ptr(uint64_t handle);
void* rawramxd_ram_ptr(uint64_t handle);

// Telemetry
void rawramxd_stats(void* stats_out);
void rawramxd_dump();

} // extern "C"

// =============================================================================
// Integration Helpers
// =============================================================================

// RAII wrapper
class RawRamXDTensor {
public:
    RawRamXDTensor(size_t size, const char* name = nullptr,
                   AccessPattern pattern = AccessPattern::UNIFORM);
    ~RawRamXDTensor();
    
    // No copy, move only
    RawRamXDTensor(const RawRamXDTensor&) = delete;
    RawRamXDTensor& operator=(const RawRamXDTensor&) = delete;
    RawRamXDTensor(RawRamXDTensor&& other) noexcept;
    RawRamXDTensor& operator=(RawRamXDTensor&& other) noexcept;
    
    // Access
    Handle handle() const { return handle_; }
    void* vram() { return RawRamXDFabric::instance().vramPtr(handle_); }
    void* ram() { return RawRamXDFabric::instance().ramPtr(handle_); }
    
    // Residency
    bool ensureVRAM() { return RawRamXDFabric::instance().ensureInVRAM(handle_); }
    void touch() { RawRamXDFabric::instance().touch(handle_); }
    
private:
    Handle handle_;
};

// Scoped residency guard
class VRAMResidencyGuard {
public:
    explicit VRAMResidencyGuard(Handle handle);
    ~VRAMResidencyGuard();
    
    bool acquired() const { return acquired_; }
    
private:
    Handle handle_;
    bool acquired_;
};

} // namespace rawramxd

#endif // RAWRAMXD_HPP