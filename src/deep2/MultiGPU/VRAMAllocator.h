// ============================================================================
// VRAMAllocator.h - Phase 2: Multi-GPU Scheduler
// VRAM allocation and memory management
// ============================================================================

#ifndef VRAM_ALLOCATOR_H
#define VRAM_ALLOCATOR_H

#include "GPUDeviceRegistry.h"
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <functional>

namespace Deep2 {
namespace MultiGPU {

// ============================================================================
// Memory Allocation Types
// ============================================================================
enum class AllocationType {
    TENSOR,           // Model weights
    KV_CACHE,         // Attention KV cache
    ACTIVATION,       // Layer activations
    WORKSPACE,        // Temporary computation
    EMBEDDING,        // Token embeddings
    SPECULATIVE       // Speculative decoding
};

// ============================================================================
// Memory Allocation
// ============================================================================
struct Allocation {
    uint64_t id = 0;
    int deviceIndex = -1;
    uint64_t offset = 0;
    uint64_t size = 0;
    AllocationType type = AllocationType::TENSOR;
    std::string tag;
    bool resident = false;
    void* hostPtr = nullptr;
    void* devicePtr = nullptr;
    
    bool IsValid() const { return id != 0 && deviceIndex >= 0; }
};

// ============================================================================
// Memory Pool
// ============================================================================
struct MemoryPool {
    int deviceIndex;
    uint64_t totalSize;
    uint64_t usedSize;
    uint64_t peakUsedSize;
    std::vector<Allocation> allocations;
    
    uint64_t GetFreeSize() const { return totalSize - usedSize; }
    float GetUtilization() const { 
        return totalSize > 0 ? 100.0f * usedSize / totalSize : 0.0f; 
    }
};

// ============================================================================
// Allocation Strategy
// ============================================================================
enum class AllocationStrategy {
    FIRST_FIT,        // First device with enough space
    BEST_FIT,         // Device with least wasted space
    ROUND_ROBIN,      // Distribute across devices
    ROLE_BASED,       // Use device roles (primary/secondary)
    PINNED            // Specific device required
};

// ============================================================================
// VRAM Allocator
// Manages memory allocation across multiple GPUs
// ============================================================================
class VRAMAllocator {
public:
    VRAMAllocator();
    ~VRAMAllocator();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Allocation
    Allocation Allocate(uint64_t size, AllocationType type,
                        AllocationStrategy strategy = AllocationStrategy::ROLE_BASED,
                        const std::string& tag = "");
    Allocation AllocateOnDevice(uint64_t size, int deviceIndex, AllocationType type,
                                const std::string& tag = "");
    
    // Deallocation
    void Free(Allocation& allocation);
    void FreeAllOnDevice(int deviceIndex);
    void FreeAllOfType(AllocationType type);
    
    // Migration
    bool Migrate(Allocation& allocation, int targetDevice);
    bool EvictToHost(Allocation& allocation);
    bool PromoteToDevice(Allocation& allocation, int deviceIndex);
    
    // Query
    uint64_t GetFreeVRAM(int deviceIndex) const;
    uint64_t GetUsedVRAM(int deviceIndex) const;
    uint64_t GetTotalVRAM() const;
    size_t GetAllocationCount(int deviceIndex = -1) const;
    
    // Pool management
    MemoryPool GetPoolInfo(int deviceIndex) const;
    std::vector<MemoryPool> GetAllPools() const;
    
    // Defragmentation
    bool Defragment(int deviceIndex);
    bool CompactMemory();
    
    // Strategy
    void SetDefaultStrategy(AllocationStrategy strategy);
    AllocationStrategy GetDefaultStrategy() const;
    
    // Events
    using AllocationCallback = std::function<void(const Allocation&)>;
    using DeallocationCallback = std::function<void(const Allocation&)>;
    using OOMCallback = std::function<bool(uint64_t requestedSize, int deviceIndex)>;
    
    void SetAllocationCallback(AllocationCallback cb);
    void SetDeallocationCallback(DeallocationCallback cb);
    void SetOOMCallback(OOMCallback cb);
    
    // Statistics
    struct Stats {
        uint64_t totalAllocated = 0;
        uint64_t totalFreed = 0;
        uint64_t peakUsage = 0;
        uint64_t migrationCount = 0;
        uint64_t evictionCount = 0;
        uint64_t oomCount = 0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    bool initialized_ = false;
    std::atomic<uint64_t> nextAllocationId_{1};
    AllocationStrategy defaultStrategy_ = AllocationStrategy::ROLE_BASED;
    
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, Allocation> allocations_;
    std::unordered_map<int, MemoryPool> pools_;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    AllocationCallback onAllocated_;
    DeallocationCallback onFreed_;
    OOMCallback onOOM_;
    
    // Internal allocation
    Allocation TryAllocate(uint64_t size, int deviceIndex, AllocationType type,
                           const std::string& tag);
    int SelectDevice(uint64_t size, AllocationStrategy strategy, AllocationType type);
    
    // Memory management
    void UpdatePoolUsage(int deviceIndex);
    bool CanAllocate(uint64_t size, int deviceIndex) const;
    
    // Strategy implementations
    int SelectDeviceFirstFit(uint64_t size);
    int SelectDeviceBestFit(uint64_t size);
    int SelectDeviceRoundRobin(uint64_t size);
    int SelectDeviceRoleBased(uint64_t size, AllocationType type);
};

// ============================================================================
// Scoped Allocation - RAII wrapper
// ============================================================================
class ScopedAllocation {
public:
    ScopedAllocation(VRAMAllocator& allocator, uint64_t size, AllocationType type,
                     AllocationStrategy strategy = AllocationStrategy::ROLE_BASED,
                     const std::string& tag = "");
    ~ScopedAllocation();
    
    // Disable copy
    ScopedAllocation(const ScopedAllocation&) = delete;
    ScopedAllocation& operator=(const ScopedAllocation&) = delete;
    
    // Enable move
    ScopedAllocation(ScopedAllocation&& other) noexcept;
    ScopedAllocation& operator=(ScopedAllocation&& other) noexcept;
    
    bool IsValid() const { return allocation_.IsValid(); }
    const Allocation& GetAllocation() const { return allocation_; }
    uint64_t GetSize() const { return allocation_.size; }
    int GetDeviceIndex() const { return allocation_.deviceIndex; }
    void* GetDevicePtr() const { return allocation_.devicePtr; }
    
    // Release ownership (caller must free)
    Allocation Release();

private:
    VRAMAllocator* allocator_;
    Allocation allocation_;
    bool ownsAllocation_;
};

// ============================================================================
// C API
// ============================================================================
extern "C" {

__declspec(dllexport) void* VRAMAllocator_Create();
__declspec(dllexport) void VRAMAllocator_Destroy(void* allocator);
__declspec(dllexport) bool VRAMAllocator_Initialize(void* allocator);
__declspec(dllexport) uint64_t VRAMAllocator_Allocate(void* allocator, uint64_t size, int deviceIndex);
__declspec(dllexport) void VRAMAllocator_Free(void* allocator, uint64_t allocationId);
__declspec(dllexport) uint64_t VRAMAllocator_GetFreeVRAM(void* allocator, int deviceIndex);
__declspec(dllexport) uint64_t VRAMAllocator_GetTotalVRAM(void* allocator);

} // extern "C"

} // namespace MultiGPU
} // namespace Deep2

#endif // VRAM_ALLOCATOR_H
