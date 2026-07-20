/*===========================================================================
 * tensor_residency.hpp
 *
 * VAL-031.1 Local Sovereign Memory Fabric
 *
 * Unified tensor residency abstraction:
 *   - Single machine (L0-L3)
 *   - Multiple NUMA domains (L3-L4)
 *   - Multiple machines (L4-L5)
 *
 * The protocol does not know the difference.
 *
 * Hierarchy:
 *   L0: Registers (compute)
 *   L1: L1 Cache (32KB)
 *   L2: L2 Cache (1-4MB)
 *   L3: System RAM (local)
 *   L4: NVMe/SSD (local)
 *   L5: Remote nodes (network)
 *
 * Core abstraction: resolve tensor address, not fetch tensor
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstring>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <mutex>

namespace RawrXD {
namespace Memory {

// Residency states
enum class ResidencyState : uint8_t {
    EVICTED = 0,    // Not resident anywhere
    COLD = 1,       // On disk/NVMe
    WARM = 2,       // In RAM but not recently used
    HOT = 3,        // Recently accessed, in cache
    PINNED = 4      // Locked in memory, cannot evict
};

// Domain types (L0-L5)
enum class DomainType : uint8_t {
    REGISTER = 0,   // L0: CPU registers
    L1_CACHE = 1,   // L1: L1 cache
    L2_CACHE = 2,   // L2: L2 cache
    SYSTEM_RAM = 3, // L3: Main memory
    LOCAL_DISK = 4, // L4: NVMe/SSD
    REMOTE_NODE = 5 // L5: Network attached
};

// Tensor residency descriptor
struct TensorResidency {
    uint64_t tensorId;           // Unique tensor identifier
    uint32_t domainId;           // Which domain (NUMA node, remote host)
    DomainType domainType;       // L0-L5 classification
    uint64_t address;            // Virtual address in domain
    uint64_t size;               // Size in bytes
    ResidencyState state;        // HOT/WARM/COLD/EVICTED
    uint64_t version;            // For cache coherence
    std::atomic<uint64_t> lastAccess; // LRU tracking

    TensorResidency()
        : tensorId(0), domainId(0), domainType(DomainType::SYSTEM_RAM),
          address(0), size(0), state(ResidencyState::EVICTED), version(0), lastAccess(0) {}
};

// Residency lookup result
struct ResidencyLookup {
    bool found;                  // Was tensor found?
    bool local;                  // Is it in local memory?
    uint64_t latencyUs;          // Expected access latency
    TensorResidency residency;   // Full residency info

    ResidencyLookup() : found(false), local(false), latencyUs(0) {}
};

// Memory domain interface
class MemoryDomain {
public:
    virtual ~MemoryDomain() = default;

    // Domain properties
    virtual DomainType GetType() const = 0;
    virtual uint32_t GetDomainId() const = 0;
    virtual uint64_t GetCapacity() const = 0;
    virtual uint64_t GetAvailable() const = 0;

    // Tensor operations
    virtual bool Allocate(uint64_t tensorId, uint64_t size, uint64_t& outAddress) = 0;
    virtual bool Free(uint64_t tensorId) = 0;
    virtual bool Read(uint64_t address, void* data, uint64_t size) = 0;
    virtual bool Write(uint64_t address, const void* data, uint64_t size) = 0;

    // Residency management
    virtual bool Evict(uint64_t tensorId) = 0;
    virtual bool Promote(uint64_t tensorId) = 0;
    virtual bool Pin(uint64_t tensorId) = 0;
    virtual bool Unpin(uint64_t tensorId) = 0;

    // Performance metrics
    virtual uint64_t GetLatencyNs() const = 0;
    virtual uint64_t GetBandwidthBps() const = 0;
};

// Local RAM domain (L3)
class LocalRAMDomain : public MemoryDomain {
public:
    LocalRAMDomain(uint32_t domainId, uint64_t capacity);
    ~LocalRAMDomain() override;

    DomainType GetType() const override { return DomainType::SYSTEM_RAM; }
    uint32_t GetDomainId() const override { return domainId_; }
    uint64_t GetCapacity() const override { return capacity_; }
    uint64_t GetAvailable() const override;

    bool Allocate(uint64_t tensorId, uint64_t size, uint64_t& outAddress) override;
    bool Free(uint64_t tensorId) override;
    bool Read(uint64_t address, void* data, uint64_t size) override;
    bool Write(uint64_t address, const void* data, uint64_t size) override;

    bool Evict(uint64_t tensorId) override;
    bool Promote(uint64_t tensorId) override;
    bool Pin(uint64_t tensorId) override;
    bool Unpin(uint64_t tensorId) override;

    uint64_t GetLatencyNs() const override { return 100; }  // ~100ns for RAM
    uint64_t GetBandwidthBps() const override { return 50ULL * 1024 * 1024 * 1024; }  // 50 GB/s

private:
    uint32_t domainId_;
    uint64_t capacity_;
    uint64_t used_;

    struct Allocation {
        uint64_t address;
        uint64_t size;
        ResidencyState state;
        bool pinned;
    };

    std::unordered_map<uint64_t, Allocation> allocations_;
    std::mutex mutex_;
    uint8_t* memoryPool_;
    uint64_t nextAddress_;
};

// Residency manager - unified interface
class ResidencyManager {
public:
    ResidencyManager();
    ~ResidencyManager();

    // Initialize with local domains
    bool Initialize();

    // Register a domain
    void RegisterDomain(std::shared_ptr<MemoryDomain> domain);

    // Core API: resolve tensor address
    ResidencyLookup Resolve(uint64_t tensorId);

    // Ensure tensor is resident at specified level
    bool EnsureResident(uint64_t tensorId, DomainType minLevel);

    // Migrate tensor between domains
    bool Migrate(uint64_t tensorId, uint32_t targetDomain);

    // Evict least recently used tensors
    size_t EvictLRU(uint64_t bytesToFree);

    // Pin tensor (prevent eviction)
    bool Pin(uint64_t tensorId);
    bool Unpin(uint64_t tensorId);

    // Statistics
    struct Stats {
        uint64_t totalLookups;
        uint64_t localHits;
        uint64_t remoteHits;
        uint64_t misses;
        uint64_t migrations;
        uint64_t evictions;
        double avgLatencyUs;
    };
    Stats GetStats() const;

private:
    std::unordered_map<uint64_t, TensorResidency> residencyTable_;
    std::unordered_map<uint32_t, std::shared_ptr<MemoryDomain>> domains_;
    std::mutex tableMutex_;

    Stats stats_;

    // Internal helpers
    std::shared_ptr<MemoryDomain> FindBestDomain(DomainType minLevel);
    bool PerformMigration(uint64_t tensorId, std::shared_ptr<MemoryDomain> source,
                          std::shared_ptr<MemoryDomain> target);
};

// C API exports
extern "C" {
    __declspec(dllexport) void* RawrXD_ResidencyManager_Create();
    __declspec(dllexport) void RawrXD_ResidencyManager_Destroy(void* handle);
    __declspec(dllexport) int RawrXD_ResidencyManager_Initialize(void* handle);
    __declspec(dllexport) int RawrXD_ResidencyManager_Resolve(void* handle, uint64_t tensorId,
                                                               uint64_t* outAddress, uint32_t* outDomain);
    __declspec(dllexport) int RawrXD_ResidencyManager_Migrate(void* handle, uint64_t tensorId, uint32_t targetDomain);
}

} // namespace Memory
} // namespace RawrXD
