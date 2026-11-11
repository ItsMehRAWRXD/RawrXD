// =============================================================================
// RawRamXD.hpp - Software-Defined AI Memory Fabric
// =============================================================================
// Unifies VRAM, RAM, and storage as one predictive, scheduler-controlled resource
// =============================================================================

#ifndef RAWRAMXD_HPP
#define RAWRAMXD_HPP

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <chrono>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawRamXD {

// =============================================================================
// Constants & Types
// =============================================================================

constexpr size_t PAGE_SIZE = 4096;
constexpr size_t HUGE_PAGE_SIZE = 2 * 1024 * 1024;  // 2MB
constexpr size_t DEFAULT_PREFETCH_WINDOW = 256 * 1024 * 1024;  // 256MB
constexpr size_t DEFAULT_EVICTION_THRESHOLD = 80;  // 80% full triggers eviction

// Memory tier types
enum class MemoryTier : uint8_t {
    GPU_VRAM = 0,      // Fastest - GPU dedicated memory
    SYSTEM_RAM = 1,    // Fast - CPU system memory
    NVME_SSD = 2,      // Medium - NVMe storage
    SATA_SSD = 3,      // Slow - SATA SSD
    HDD = 4,           // Slowest - Hard disk
    TIER_COUNT = 5
};

// Page states
enum class PageState : uint8_t {
    FREE = 0,
    ALLOCATED = 1,
    MAPPED = 2,
    PREFETCHED = 3,
    EVICTING = 4,
    MIGRATING = 5,
    COMPRESSED = 6,
    PINNED = 7
};

// Access patterns for prediction
enum class AccessPattern : uint8_t {
    SEQUENTIAL = 0,    // Linear access (weights, embeddings)
    RANDOM = 1,        // Random access (attention)
    STRIDED = 2,       // Strided access (activations)
    GATHER = 3,        // Gather/scatter (sparse)
    UNKNOWN = 4
};

// Scheduler priorities
enum class SchedulePriority : uint8_t {
    CRITICAL = 0,      // Must be resident immediately
    HIGH = 1,          // Prefetch aggressively
    NORMAL = 2,        // Standard prefetch
    LOW = 3,           // On-demand only
    BACKGROUND = 4     // Evict first
};

// =============================================================================
// Forward Declarations
// =============================================================================

class MemoryFabric;
class TierManager;
class PredictiveEngine;
class Scheduler;
class MemoryRegion;
struct PageEntry;
struct MigrationTask;

// =============================================================================
// Core Data Structures
// =============================================================================

struct PhysicalAddress {
    uint64_t address;
    MemoryTier tier;
    
    bool operator==(const PhysicalAddress& other) const {
        return address == other.address && tier == other.tier;
    }
};

struct VirtualAddress {
    uint64_t address;
    uint32_t generation;  // For ABA protection
};

struct PageEntry {
    VirtualAddress virtAddr;
    PhysicalAddress physAddr;
    size_t size;
    PageState state;
    AccessPattern pattern;
    SchedulePriority priority;
    
    // Statistics
    uint64_t lastAccessTime;
    uint64_t accessCount;
    uint64_t prefetchHits;
    uint64_t prefetchMisses;
    
    // Compression
    bool isCompressed;
    size_t compressedSize;
    
    // Links
    PageEntry* nextLRU;
    PageEntry* prevLRU;
};

struct MigrationTask {
    VirtualAddress virtAddr;
    MemoryTier sourceTier;
    MemoryTier targetTier;
    SchedulePriority priority;
    std::function<void(bool)> callback;
    uint64_t submitTime;
};

struct FabricStats {
    std::atomic<uint64_t> totalAllocations{0};
    std::atomic<uint64_t> totalDeallocations{0};
    std::atomic<uint64_t> tierMigrations{0};
    std::atomic<uint64_t> prefetchHits{0};
    std::atomic<uint64_t> prefetchMisses{0};
    std::atomic<uint64_t> evictionCount{0};
    std::atomic<uint64_t> compressionCount{0};
    std::atomic<uint64_t> decompressionCount{0};
    
    // Per-tier stats
    struct TierStats {
        std::atomic<uint64_t> bytesUsed{0};
        std::atomic<uint64_t> bytesFree{0};
        std::atomic<uint64_t> pageFaults{0};
        std::atomic<uint64_t> migrationsIn{0};
        std::atomic<uint64_t> migrationsOut{0};
    };
    TierStats tierStats[static_cast<size_t>(MemoryTier::TIER_COUNT)];
};

// =============================================================================
// Memory Region
// =============================================================================

class MemoryRegion {
public:
    MemoryRegion(void* cpuPtr, uint64_t gpuPtr, size_t size, MemoryTier tier);
    ~MemoryRegion();
    
    // Accessors
    void* GetCpuPointer() const { return cpuPtr_; }
    uint64_t GetGpuPointer() const { return gpuPtr_; }
    size_t GetSize() const { return size_; }
    MemoryTier GetTier() const { return tier_; }
    PageState GetState() const { return state_; }
    
    // Operations
    bool MigrateTo(MemoryTier newTier);
    bool Prefetch();
    bool Evict();
    bool Pin();
    bool Unpin();
    
    // Statistics
    uint64_t GetAccessCount() const { return accessCount_.load(); }
    uint64_t GetLastAccessTime() const { return lastAccessTime_.load(); }
    
private:
    void* cpuPtr_;
    uint64_t gpuPtr_;
    size_t size_;
    MemoryTier tier_;
    PageState state_;
    SchedulePriority priority_;
    
    std::atomic<uint64_t> accessCount_{0};
    std::atomic<uint64_t> lastAccessTime_{0};
    std::atomic<bool> pinned_{false};
    
    mutable std::mutex mutex_;
};

// =============================================================================
// Predictive Engine
// =============================================================================

class PredictiveEngine {
public:
    PredictiveEngine();
    ~PredictiveEngine();
    
    // Pattern detection
    AccessPattern DetectPattern(const std::vector<uint64_t>& accessHistory);
    
    // Prefetch prediction
    std::vector<uint64_t> PredictNextAccesses(
        uint64_t currentAddress,
        AccessPattern pattern,
        size_t count
    );
    
    // Working set prediction
    std::vector<uint64_t> PredictWorkingSet(
        const std::vector<uint64_t>& recentAccesses,
        size_t maxSize
    );
    
    // Update model with actual access
    void RecordAccess(uint64_t address, bool wasPrefetched);
    
    // Get prediction accuracy
    double GetAccuracy() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// =============================================================================
// Tier Manager
// =============================================================================

class TierManager {
public:
    TierManager();
    ~TierManager();
    
    // Initialize tiers
    bool Initialize();
    
    // Tier information
    size_t GetTierSize(MemoryTier tier) const;
    size_t GetTierFree(MemoryTier tier) const;
    size_t GetTierUsed(MemoryTier tier) const;
    float GetTierUtilization(MemoryTier tier) const;
    
    // Allocation
    PhysicalAddress Allocate(MemoryTier tier, size_t size);
    void Free(PhysicalAddress addr, size_t size);
    
    // Migration
    bool Migrate(PhysicalAddress source, MemoryTier targetTier, 
                 PhysicalAddress& target);
    
    // Compression
    bool Compress(PhysicalAddress addr, size_t& compressedSize);
    bool Decompress(PhysicalAddress addr, size_t originalSize);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// =============================================================================
// Scheduler
// =============================================================================

class Scheduler {
public:
    Scheduler(TierManager* tierManager, PredictiveEngine* predictor);
    ~Scheduler();
    
    // Start/stop
    bool Start();
    void Stop();
    
    // Submit work
    void SubmitMigration(MigrationTask task);
    void SubmitPrefetch(uint64_t virtAddr, size_t size);
    void SubmitEviction(uint64_t virtAddr);
    
    // Priority management
    void SetPriority(uint64_t virtAddr, SchedulePriority priority);
    
    // Get queue depths
    size_t GetPendingMigrations() const;
    size_t GetPendingPrefetches() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// =============================================================================
// Memory Fabric (Main API)
// =============================================================================

class MemoryFabric {
public:
    static MemoryFabric& Instance();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Memory allocation
    MemoryRegion* Allocate(size_t size, MemoryTier preferredTier = MemoryTier::SYSTEM_RAM);
    void Free(MemoryRegion* region);
    
    // Unified allocation (auto-tier selection)
    MemoryRegion* AllocateUnified(size_t size, SchedulePriority priority = SchedulePriority::NORMAL);
    
    // Memory mapping
    MemoryRegion* MapFile(const char* path, size_t offset, size_t size);
    void UnmapFile(MemoryRegion* region);
    
    // Explicit tier management
    bool MigrateToTier(MemoryRegion* region, MemoryTier targetTier);
    bool Prefetch(MemoryRegion* region);
    bool Evict(MemoryRegion* region);
    bool Pin(MemoryRegion* region);
    bool Unpin(MemoryRegion* region);
    
    // Access notification (for prediction)
    void NotifyAccess(MemoryRegion* region, size_t offset, size_t size);
    
    // Statistics
    const FabricStats& GetStats() const { return stats_; }
    void PrintStats() const;
    
    // Configuration
    void SetPrefetchWindow(size_t bytes);
    void SetEvictionThreshold(uint8_t percent);
    void EnableCompression(bool enable);
    void EnablePrediction(bool enable);
    
private:
    MemoryFabric();
    ~MemoryFabric();
    MemoryFabric(const MemoryFabric&) = delete;
    MemoryFabric& operator=(const MemoryFabric&) = delete;
    
    bool initialized_;
    FabricStats stats_;
    
    std::unique_ptr<TierManager> tierManager_;
    std::unique_ptr<PredictiveEngine> predictor_;
    std::unique_ptr<Scheduler> scheduler_;
    
    // Region tracking
    std::unordered_map<uint64_t, std::unique_ptr<MemoryRegion>> regions_;
    std::mutex regionsMutex_;
    
    // Virtual address space
    uint64_t nextVirtAddr_;
    std::mutex virtAddrMutex_;
};

// =============================================================================
// C API (for interoperability)
// =============================================================================

extern "C" {
    // Initialization
    bool RawRamXD_Initialize();
    void RawRamXD_Shutdown();
    
    // Allocation
    void* RawRamXD_Allocate(size_t size, uint32_t tier);
    void* RawRamXD_AllocateUnified(size_t size, uint32_t priority);
    void RawRamXD_Free(void* ptr);
    
    // Tier management
    bool RawRamXD_MigrateToTier(void* ptr, uint32_t tier);
    bool RawRamXD_Prefetch(void* ptr);
    bool RawRamXD_Evict(void* ptr);
    bool RawRamXD_Pin(void* ptr);
    bool RawRamXD_Unpin(void* ptr);
    
    // File mapping
    void* RawRamXD_MapFile(const char* path, size_t offset, size_t size);
    void RawRamXD_UnmapFile(void* ptr);
    
    // Statistics
    void RawRamXD_GetStats(char* buffer, size_t bufferSize);
    void RawRamXD_PrintStats();
}

} // namespace RawRamXD

#endif // RAWRAMXD_HPP