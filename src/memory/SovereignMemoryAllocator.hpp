//=============================================================================
// RawrXD Sovereign Memory Allocator
// Phase 3A: NUMA-Aware Large Page Memory Management
// 
// Provides hardware-aligned memory allocation with:
// - NUMA node-local allocation (VirtualAlloc2)
// - 1GB large page support (reduces TLB misses)
// - Memory tier abstraction
// - Real-time residency telemetry
// - RAII-based memory handles
//
// This is the foundation for the FabricJukeboxStreamer KV-cache residency.
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <windows.h>

// For VirtualAlloc2 and MEM_EXTENDED_PARAMETER
#include <memoryapi.h>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Forward Declarations
//=============================================================================
class SovereignMemoryAllocator;
class MemoryResidencyHandle;

//=============================================================================
// Memory Tier Enumeration
// Abstracts the physical backing of memory
//=============================================================================
enum class MemoryTier {
    L1_PINNED = 0,        // CPU L1-pinned (if supported)
    LARGE_PAGE_DRAM,      // 1GB huge pages
    STANDARD_DRAM,        // 4KB pages
    GPU_VRAM,             // GPU memory (future)
    MAPPED_FILE,          // Memory-mapped file
    TIER_COUNT
};

//=============================================================================
// Memory Allocation Flags
//=============================================================================
enum class AllocFlags : uint32_t {
    NONE = 0,
    NUMA_AFFINITY = 1 << 0,      // Bind to specific NUMA node
    LARGE_PAGES = 1 << 1,        // Request 1GB pages
    PREFETCH = 1 << 2,           // Prefault pages
    LOCKED = 1 << 3,             // Prevent swapping
    ZERO_INIT = 1 << 4,          // Zero-initialize memory
};

inline AllocFlags operator|(AllocFlags a, AllocFlags b) {
    return static_cast<AllocFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline bool HasFlag(AllocFlags flags, AllocFlags check) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(check)) != 0;
}

//=============================================================================
// NUMA Topology Information
//=============================================================================
struct NumaTopology {
    uint32_t numNodes;
    uint32_t numProcessors;
    uint32_t processorsPerNode;
    uint64_t totalPhysicalMemory;
    std::vector<uint64_t> nodeMemory;  // Memory per node
    
    static NumaTopology Detect();
    bool IsValid() const { return numNodes > 0; }
};

//=============================================================================
// Memory Statistics
// Real-time telemetry for residency monitoring
//=============================================================================
struct MemoryStats {
    // Allocation counters
    std::atomic<uint64_t> totalAllocations{0};
    std::atomic<uint64_t> totalDeallocations{0};
    std::atomic<uint64_t> activeAllocations{0};
    std::atomic<uint64_t> bytesAllocated{0};
    std::atomic<uint64_t> bytesCommitted{0};
    
    // Tier-specific stats
    std::atomic<uint64_t> largePageAllocations{0};
    std::atomic<uint64_t> standardPageAllocations{0};
    std::atomic<uint64_t> numaLocalAllocations{0};
    std::atomic<uint64_t> numaRemoteAllocations{0};
    
    // Performance metrics
    std::atomic<uint64_t> allocationTimeUs{0};  // Cumulative allocation time
    std::atomic<uint64_t> allocationCount{0};     // Number of allocation calls
    
    // TLB metrics (estimated)
    std::atomic<uint64_t> tlbMisses{0};
    std::atomic<uint64_t> pageFaults{0};
    
    double GetAverageAllocationTimeUs() const {
        uint64_t count = allocationCount.load();
        return count > 0 ? static_cast<double>(allocationTimeUs.load()) / count : 0.0;
    }
    
    void Reset();
};

//=============================================================================
// Memory Residency Handle
// RAII wrapper for allocated memory blocks
//=============================================================================
class MemoryResidencyHandle {
public:
    MemoryResidencyHandle() = default;
    MemoryResidencyHandle(void* ptr, size_t size, MemoryTier tier, 
                          uint32_t numaNode, SovereignMemoryAllocator* allocator);
    ~MemoryResidencyHandle();
    
    // Disable copy
    MemoryResidencyHandle(const MemoryResidencyHandle&) = delete;
    MemoryResidencyHandle& operator=(const MemoryResidencyHandle&) = delete;
    
    // Enable move
    MemoryResidencyHandle(MemoryResidencyHandle&& other) noexcept;
    MemoryResidencyHandle& operator=(MemoryResidencyHandle&& other) noexcept;
    
    // Accessors
    void* GetPtr() const { return ptr_; }
    size_t GetSize() const { return size_; }
    MemoryTier GetTier() const { return tier_; }
    uint32_t GetNumaNode() const { return numaNode_; }
    bool IsValid() const { return ptr_ != nullptr; }
    
    // Release ownership (caller becomes responsible for deallocation)
    void* Release();
    
    // Prefault pages into memory
    void Prefault();
    
    // Lock pages in memory (prevent swapping)
    bool Lock();
    void Unlock();
    
private:
    void* ptr_ = nullptr;
    size_t size_ = 0;
    MemoryTier tier_ = MemoryTier::STANDARD_DRAM;
    uint32_t numaNode_ = 0;
    SovereignMemoryAllocator* allocator_ = nullptr;
    bool locked_ = false;
    
    void Reset();
};

//=============================================================================
// Per-NUMA-Node Memory Pool
// Lock-free free list for fast allocation
//=============================================================================
class NumaMemoryPool {
public:
    struct Block {
        Block* next;
        size_t size;
        uint64_t allocationId;
    };
    
    NumaMemoryPool(uint32_t numaNode, size_t blockSize);
    ~NumaMemoryPool();
    
    // Initialize with pre-allocated memory
    bool Initialize(size_t poolSize, bool useLargePages);
    void Shutdown();
    
    // Allocate/deallocate blocks
    void* Allocate(size_t size);
    void Free(void* ptr, size_t size);
    
    // Get pool statistics
    size_t GetFreeBlocks() const;
    size_t GetUsedBlocks() const;
    uint32_t GetNumaNode() const { return numaNode_; }
    
private:
    uint32_t numaNode_;
    size_t blockSize_;
    
    // Lock-free free list
    alignas(64) std::atomic<Block*> freeList_{nullptr};
    
    // Pool memory
    void* poolBase_ = nullptr;
    size_t poolSize_ = 0;
    
    // Statistics
    alignas(64) std::atomic<size_t> allocatedBlocks_{0};
    alignas(64) std::atomic<size_t> freeBlockCount_{0};
    
    // Push/pop from free list
    void PushFreeBlock(Block* block);
    Block* PopFreeBlock();
};

//=============================================================================
// Sovereign Memory Allocator
// Main allocation interface with NUMA and large page support
//=============================================================================
class SovereignMemoryAllocator {
public:
    SovereignMemoryAllocator();
    ~SovereignMemoryAllocator();
    
    // Disable copy/move
    SovereignMemoryAllocator(const SovereignMemoryAllocator&) = delete;
    SovereignMemoryAllocator& operator=(const SovereignMemoryAllocator&) = delete;
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Core allocation API
    MemoryResidencyHandle Allocate(
        size_t bytes,
        MemoryTier tier = MemoryTier::STANDARD_DRAM,
        uint32_t numaNode = UINT32_MAX,  // UINT32_MAX = any node
        AllocFlags flags = AllocFlags::NONE
    );
    
    // Raw allocation (returns pointer only)
    void* AllocateRaw(
        size_t bytes,
        MemoryTier tier = MemoryTier::STANDARD_DRAM,
        uint32_t numaNode = UINT32_MAX,
        AllocFlags flags = AllocFlags::NONE
    );
    
    // Deallocation
    void Free(void* ptr, size_t size, MemoryTier tier, uint32_t numaNode);
    
    // NUMA-aware allocation helper
    uint32_t GetCurrentNumaNode() const;
    uint32_t GetPreferredNumaNode() const;
    bool BindThreadToNumaNode(uint32_t node);
    
    // Large page support
    bool AreLargePagesAvailable() const { return largePagesAvailable_; }
    size_t GetLargePageSize() const { return largePageSize_; }
    bool EnableLargePagePrivilege();
    
    // Memory tier queries
    size_t GetTierPageSize(MemoryTier tier) const;
    bool IsTierAvailable(MemoryTier tier) const;
    
    // Statistics and telemetry
    const MemoryStats& GetStats() const { return stats_; }
    MemoryStats GetSnapshot() const;
    std::string GetResidencyReport() const;
    
    // NUMA topology
    const NumaTopology& GetTopology() const { return topology_; }
    
    // Pool management
    bool CreateNumaPool(uint32_t numaNode, size_t poolSize, bool useLargePages);
    void DestroyNumaPool(uint32_t numaNode);
    
private:
    bool initialized_ = false;
    NumaTopology topology_;
    MemoryStats stats_;
    
    // Large page support
    bool largePagesAvailable_ = false;
    size_t largePageSize_ = 0;
    HANDLE largePageToken_ = nullptr;
    
    // NUMA pools (one per node)
    std::vector<std::unique_ptr<NumaMemoryPool>> numaPools_;
    std::mutex poolsMutex_;
    
    // Internal allocation methods
    void* AllocateStandardPages(size_t size, uint32_t numaNode, AllocFlags flags);
    void* AllocateLargePages(size_t size, uint32_t numaNode, AllocFlags flags);
    void* AllocateWithVirtualAlloc2(size_t size, uint32_t numaNode, DWORD allocType, DWORD protect);
    
    void FreeStandardPages(void* ptr, size_t size);
    void FreeLargePages(void* ptr, size_t size);
    
    // Utility
    size_t AlignUp(size_t size, size_t alignment) const;
    uint32_t SanitizeNumaNode(uint32_t node) const;
    
    // Telemetry
    void RecordAllocation(size_t size, MemoryTier tier, uint32_t numaNode, uint64_t timeUs);
    void RecordDeallocation(size_t size, MemoryTier tier, uint32_t numaNode);
};

//=============================================================================
// Global Allocator Access
// Singleton pattern for application-wide allocator
//=============================================================================
SovereignMemoryAllocator& GetGlobalAllocator();
bool InitializeGlobalAllocator();
void ShutdownGlobalAllocator();

//=============================================================================
// Convenience Functions
//=============================================================================
// Allocate NUMA-local memory for current thread
inline MemoryResidencyHandle AllocateNumaLocal(
    size_t bytes, 
    MemoryTier tier = MemoryTier::STANDARD_DRAM
) {
    auto& alloc = GetGlobalAllocator();
    return alloc.Allocate(bytes, tier, alloc.GetCurrentNumaNode());
}

// Allocate with large pages if available
inline MemoryResidencyHandle AllocateLarge(
    size_t bytes,
    uint32_t numaNode = UINT32_MAX
) {
    auto& alloc = GetGlobalAllocator();
    MemoryTier tier = alloc.AreLargePagesAvailable() 
        ? MemoryTier::LARGE_PAGE_DRAM 
        : MemoryTier::STANDARD_DRAM;
    return alloc.Allocate(bytes, tier, numaNode, AllocFlags::LARGE_PAGES);
}

} // namespace Memory
} // namespace RawrXD
