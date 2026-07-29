// ============================================================================
// MemoryAperture.hpp - Memory Aperture Monitor & Heap-free Allocator
// Zero-overhead memory management for the Sovereign runtime
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>

namespace Sovereign {

// Memory aperture configuration
struct ApertureConfig {
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    uint32_t pageSize = 4096;
    bool useHugePages = true;
    bool reserveContiguous = true;
    bool enableOvercommit = false;
    uint32_t numaNode = 0;
    uint32_t protection = PAGE_READWRITE;
};

// Memory aperture statistics
struct ApertureStats {
    uint64_t totalSize;
    uint64_t usedSize;
    uint64_t peakSize;
    uint64_t pageFaults;
    uint64_t tlbMisses;
    uint64_t allocations;
    uint64_t deallocations;
    uint64_t hugePagesUsed;
    uint64_t numaRemoteAccesses;
    double fragmentationRatio;
};

// Memory region descriptor
struct MemoryRegion {
    uint64_t address;
    uint64_t size;
    uint32_t protection;
    bool isFree;
    bool isHugePage;
    uint32_t numaNode;
    std::string tag;
};

// Memory aperture monitor
class MemoryApertureMonitor {
public:
    MemoryApertureMonitor();
    ~MemoryApertureMonitor();

    // Initialize
    bool Initialize(const ApertureConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Aperture management
    bool Reserve(uint64_t size);
    bool Commit(uint64_t address, uint64_t size);
    bool Decommit(uint64_t address, uint64_t size);
    bool Release(uint64_t address, uint64_t size);

    // Allocation
    void* Allocate(uint64_t size, uint32_t alignment = 16);
    void Free(void* ptr);
    void* Reallocate(void* ptr, uint64_t newSize);

    // Page management
    bool LockPages(uint64_t address, uint64_t size);
    bool UnlockPages(uint64_t address, uint64_t size);
    bool PrefetchPages(uint64_t address, uint64_t size);

    // NUMA
    void SetNUMANode(uint32_t node);
    uint32_t GetNUMANode(uint64_t address) const;
    uint64_t GetNUMARemoteAccesses() const { return stats_.numaRemoteAccesses; }

    // Huge pages
    bool EnableHugePages(bool enabled);
    bool IsHugePageSupported() const;
    uint64_t GetHugePageSize() const;

    // Monitoring
    ApertureStats GetStats() const;
    std::vector<MemoryRegion> GetRegions() const;
    void ResetStats();

    // Callbacks
    void SetPageFaultCallback(std::function<void(uint64_t)> callback);
    void SetAllocationCallback(std::function<void(uint64_t, uint64_t)> callback);

    // Defragmentation
    bool Defragment();
    double GetFragmentationRatio() const { return stats_.fragmentationRatio; }

private:
    bool initialized_ = false;
    ApertureConfig config_;
    ApertureStats stats_;
    mutable std::mutex mutex_;
    
    // Allocated regions
    std::vector<MemoryRegion> regions_;
    
    // Free list
    struct FreeBlock {
        uint64_t address;
        uint64_t size;
    };
    std::vector<FreeBlock> freeList_;
    
    // Callbacks
    std::function<void(uint64_t)> pageFaultCallback_;
    std::function<void(uint64_t, uint64_t)> allocationCallback_;
    
    // Internal
    uint64_t AllocatePages(uint64_t size);
    void FreePages(uint64_t address, uint64_t size);
    bool IsPageAligned(uint64_t address) const;
    uint64_t AlignUp(uint64_t value, uint64_t alignment) const;
};

// Heap-free allocator (pool-based, no malloc/free)
class HeapFreeAllocator {
public:
    HeapFreeAllocator();
    ~HeapFreeAllocator();

    // Initialize with a pre-allocated memory pool
    bool Initialize(void* pool, uint64_t poolSize);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Allocation (O(1), no heap)
    void* Allocate(uint64_t size);
    void Free(void* ptr);
    void* Reallocate(void* ptr, uint64_t newSize);

    // Pool management
    uint64_t GetUsedSize() const { return used_; }
    uint64_t GetFreeSize() const { return poolSize_ - used_; }
    uint64_t GetPoolSize() const { return poolSize_; }
    double GetUtilization() const { return poolSize_ > 0 ? (double)used_ / poolSize_ : 0.0; }

    // Reset
    void Reset();
    void Compact();

    // Statistics
    struct AllocStats {
        uint64_t allocations;
        uint64_t deallocations;
        uint64_t peakUsage;
        uint64_t currentUsage;
        uint64_t totalWaste;
    };
    AllocStats GetStats() const { return stats_; }

private:
    bool initialized_ = false;
    uint8_t* pool_ = nullptr;
    uint64_t poolSize_ = 0;
    uint64_t used_ = 0;
    uint64_t offset_ = 0;
    AllocStats stats_;
    mutable std::mutex mutex_;
    
    // Free list for freed blocks
    struct FreeEntry {
        void* ptr;
        uint64_t size;
    };
    std::vector<FreeEntry> freeEntries_;
};

} // namespace Sovereign
