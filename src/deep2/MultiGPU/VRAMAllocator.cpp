// ============================================================================
// VRAMAllocator.cpp - Phase 2: Multi-GPU Scheduler
// VRAM allocation and memory management implementation
// ============================================================================

#include "VRAMAllocator.h"
#include <algorithm>
#include <cstring>

namespace Deep2 {
namespace MultiGPU {

// ============================================================================
// Constructor / Destructor
// ============================================================================
VRAMAllocator::VRAMAllocator() = default;

VRAMAllocator::~VRAMAllocator() {
    if (initialized_) {
        Shutdown();
    }
}

// ============================================================================
// Initialization
// ============================================================================
bool VRAMAllocator::Initialize() {
    if (initialized_) {
        return true;
    }

    printf("[VRAMAllocator] Initializing...\n");

    // Get device info from registry
    auto& registry = GPUDeviceRegistry::Instance();
    auto devices = registry.GetAllDevices();

    for (const auto& device : devices) {
        MemoryPool pool;
        pool.deviceIndex = device.index;
        pool.totalSize = device.totalVRAMBytes;
        pool.usedSize = device.usedVRAMBytes;
        pool.peakUsedSize = device.usedVRAMBytes;

        pools_[device.index] = pool;

        printf("[VRAMAllocator] Pool %d: %.2f GB total\n",
               device.index, device.totalVRAMBytes / (1024.0 * 1024.0 * 1024.0));
    }

    initialized_ = !pools_.empty();
    return initialized_;
}

void VRAMAllocator::Shutdown() {
    printf("[VRAMAllocator] Shutting down...\n");

    // Free all allocations
    for (auto& [id, alloc] : allocations_) {
        if (onFreed_) {
            onFreed_(alloc);
        }
    }
    allocations_.clear();
    pools_.clear();

    initialized_ = false;
}

// ============================================================================
// Allocation
// ============================================================================
Allocation VRAMAllocator::Allocate(uint64_t size, AllocationType type,
                                    AllocationStrategy strategy,
                                    const std::string& tag) {
    if (!initialized_) {
        return Allocation{};
    }

    int deviceIndex = SelectDevice(size, strategy, type);
    if (deviceIndex < 0) {
        // OOM - try to handle
        if (onOOM_) {
            bool handled = onOOM_(size, -1);
            if (handled) {
                // Retry after OOM handler
                deviceIndex = SelectDevice(size, strategy, type);
            }
        }

        if (deviceIndex < 0) {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.oomCount++;
            printf("[VRAMAllocator] OOM: Cannot allocate %zu bytes\n", size);
            return Allocation{};
        }
    }

    return TryAllocate(size, deviceIndex, type, tag);
}

Allocation VRAMAllocator::AllocateOnDevice(uint64_t size, int deviceIndex,
                                            AllocationType type,
                                            const std::string& tag) {
    if (!initialized_ || deviceIndex < 0) {
        return Allocation{};
    }

    return TryAllocate(size, deviceIndex, type, tag);
}

Allocation VRAMAllocator::TryAllocate(uint64_t size, int deviceIndex,
                                       AllocationType type,
                                       const std::string& tag) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto poolIt = pools_.find(deviceIndex);
    if (poolIt == pools_.end()) {
        return Allocation{};
    }

    auto& pool = poolIt->second;
    if (pool.GetFreeSize() < size) {
        return Allocation{};
    }

    // Create allocation
    Allocation alloc;
    alloc.id = nextAllocationId_++;
    alloc.deviceIndex = deviceIndex;
    alloc.size = size;
    alloc.type = type;
    alloc.tag = tag;
    alloc.resident = true;

    // Calculate offset (simplified - no fragmentation handling)
    alloc.offset = pool.usedSize;

    // Update pool
    pool.usedSize += size;
    pool.peakUsedSize = std::max(pool.peakUsedSize, pool.usedSize);
    pool.allocations.push_back(alloc);

    // Store allocation
    allocations_[alloc.id] = alloc;

    // Update stats
    {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.totalAllocated += size;
        stats_.peakUsage = std::max(stats_.peakUsage, pool.usedSize);
    }

    // Notify
    if (onAllocated_) {
        onAllocated_(alloc);
    }

    // Update registry
    GPUDeviceRegistry::Instance().UpdateMemoryUsage(deviceIndex, pool.usedSize);

    printf("[VRAMAllocator] Allocated %zu bytes on device %d (%s)\n",
           size, deviceIndex, tag.c_str());

    return alloc;
}

// ============================================================================
// Deallocation
// ============================================================================
void VRAMAllocator::Free(Allocation& allocation) {
    if (!allocation.IsValid()) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(allocation.id);
    if (it == allocations_.end()) {
        return;
    }

    auto poolIt = pools_.find(allocation.deviceIndex);
    if (poolIt != pools_.end()) {
        auto& pool = poolIt->second;

        // Remove from pool's allocation list
        auto& allocs = pool.allocations;
        allocs.erase(
            std::remove_if(allocs.begin(), allocs.end(),
                [&allocation](const Allocation& a) { return a.id == allocation.id; }),
            allocs.end()
        );

        // Recalculate used size (simplified - no coalescing)
        pool.usedSize = 0;
        for (const auto& a : allocs) {
            pool.usedSize = std::max(pool.usedSize, a.offset + a.size);
        }

        // Update registry
        GPUDeviceRegistry::Instance().UpdateMemoryUsage(allocation.deviceIndex, pool.usedSize);
    }

    // Update stats
    {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.totalFreed += allocation.size;
    }

    // Notify
    if (onFreed_) {
        onFreed_(allocation);
    }

    printf("[VRAMAllocator] Freed %zu bytes from device %d\n",
           allocation.size, allocation.deviceIndex);

    // Invalidate allocation
    allocations_.erase(it);
    allocation.id = 0;
}

void VRAMAllocator::FreeAllOnDevice(int deviceIndex) {
    std::vector<uint64_t> toFree;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, alloc] : allocations_) {
            if (alloc.deviceIndex == deviceIndex) {
                toFree.push_back(id);
            }
        }
    }

    for (uint64_t id : toFree) {
        auto it = allocations_.find(id);
        if (it != allocations_.end()) {
            Allocation alloc = it->second;
            Free(alloc);
        }
    }
}

void VRAMAllocator::FreeAllOfType(AllocationType type) {
    std::vector<uint64_t> toFree;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, alloc] : allocations_) {
            if (alloc.type == type) {
                toFree.push_back(id);
            }
        }
    }

    for (uint64_t id : toFree) {
        auto it = allocations_.find(id);
        if (it != allocations_.end()) {
            Allocation alloc = it->second;
            Free(alloc);
        }
    }
}

// ============================================================================
// Device Selection Strategies
// ============================================================================
int VRAMAllocator::SelectDevice(uint64_t size, AllocationStrategy strategy, AllocationType type) {
    switch (strategy) {
        case AllocationStrategy::FIRST_FIT:
            return SelectDeviceFirstFit(size);
        case AllocationStrategy::BEST_FIT:
            return SelectDeviceBestFit(size);
        case AllocationStrategy::ROUND_ROBIN:
            return SelectDeviceRoundRobin(size);
        case AllocationStrategy::ROLE_BASED:
            return SelectDeviceRoleBased(size, type);
        case AllocationStrategy::PINNED:
        default:
            return -1;
    }
}

int VRAMAllocator::SelectDeviceFirstFit(uint64_t size) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [index, pool] : pools_) {
        if (pool.GetFreeSize() >= size) {
            return index;
        }
    }
    return -1;
}

int VRAMAllocator::SelectDeviceBestFit(uint64_t size) {
    std::lock_guard<std::mutex> lock(mutex_);

    int bestDevice = -1;
    uint64_t bestWaste = UINT64_MAX;

    for (auto& [index, pool] : pools_) {
        if (pool.GetFreeSize() >= size) {
            uint64_t waste = pool.GetFreeSize() - size;
            if (waste < bestWaste) {
                bestWaste = waste;
                bestDevice = index;
            }
        }
    }
    return bestDevice;
}

int VRAMAllocator::SelectDeviceRoundRobin(uint64_t size) {
    static std::atomic<int> nextDevice{0};

    std::lock_guard<std::mutex> lock(mutex_);

    int numDevices = (int)pools_.size();
    if (numDevices == 0) return -1;

    for (int i = 0; i < numDevices; i++) {
        int deviceIndex = (nextDevice++ + i) % numDevices;
        auto it = pools_.find(deviceIndex);
        if (it != pools_.end() && it->second.GetFreeSize() >= size) {
            return deviceIndex;
        }
    }
    return -1;
}

int VRAMAllocator::SelectDeviceRoleBased(uint64_t size, AllocationType type) {
    auto& registry = GPUDeviceRegistry::Instance();

    // Primary device for transformer execution
    if (type == AllocationType::TENSOR ||
        type == AllocationType::ACTIVATION) {
        auto primary = registry.GetPrimaryDevice();
        if (primary && GetFreeVRAM(primary->index) >= size) {
            return primary->index;
        }
    }

    // Secondary device for KV cache
    if (type == AllocationType::KV_CACHE) {
        auto secondary = registry.GetSecondaryDevice();
        if (secondary && GetFreeVRAM(secondary->index) >= size) {
            return secondary->index;
        }
    }

    // Fallback to first fit
    return SelectDeviceFirstFit(size);
}

// ============================================================================
// Query Methods
// ============================================================================
uint64_t VRAMAllocator::GetFreeVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pools_.find(deviceIndex);
    if (it != pools_.end()) {
        return it->second.GetFreeSize();
    }
    return 0;
}

uint64_t VRAMAllocator::GetUsedVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pools_.find(deviceIndex);
    if (it != pools_.end()) {
        return it->second.usedSize;
    }
    return 0;
}

uint64_t VRAMAllocator::GetTotalVRAM() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& [index, pool] : pools_) {
        total += pool.totalSize;
    }
    return total;
}

size_t VRAMAllocator::GetAllocationCount(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (deviceIndex < 0) {
        return allocations_.size();
    }

    size_t count = 0;
    for (const auto& [id, alloc] : allocations_) {
        if (alloc.deviceIndex == deviceIndex) {
            count++;
        }
    }
    return count;
}

// ============================================================================
// Pool Management
// ============================================================================
MemoryPool VRAMAllocator::GetPoolInfo(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pools_.find(deviceIndex);
    if (it != pools_.end()) {
        return it->second;
    }
    return MemoryPool{};
}

std::vector<MemoryPool> VRAMAllocator::GetAllPools() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<MemoryPool> result;
    for (const auto& [index, pool] : pools_) {
        result.push_back(pool);
    }
    return result;
}

// ============================================================================
// Statistics
// ============================================================================
VRAMAllocator::Stats VRAMAllocator::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void VRAMAllocator::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

// ============================================================================
// Event Callbacks
// ============================================================================
void VRAMAllocator::SetAllocationCallback(AllocationCallback cb) {
    onAllocated_ = cb;
}

void VRAMAllocator::SetDeallocationCallback(DeallocationCallback cb) {
    onFreed_ = cb;
}

void VRAMAllocator::SetOOMCallback(OOMCallback cb) {
    onOOM_ = cb;
}

// ============================================================================
// ScopedAllocation Implementation
// ============================================================================
ScopedAllocation::ScopedAllocation(VRAMAllocator& allocator, uint64_t size,
                                    AllocationType type, AllocationStrategy strategy,
                                    const std::string& tag)
    : allocator_(&allocator), ownsAllocation_(true) {
    allocation_ = allocator.Allocate(size, type, strategy, tag);
}

ScopedAllocation::~ScopedAllocation() {
    if (ownsAllocation_ && allocation_.IsValid()) {
        allocator_->Free(allocation_);
    }
}

ScopedAllocation::ScopedAllocation(ScopedAllocation&& other) noexcept
    : allocator_(other.allocator_),
      allocation_(other.allocation_),
      ownsAllocation_(other.ownsAllocation_) {
    other.ownsAllocation_ = false;
    other.allocation_ = Allocation{};
}

ScopedAllocation& ScopedAllocation::operator=(ScopedAllocation&& other) noexcept {
    if (this != &other) {
        if (ownsAllocation_ && allocation_.IsValid()) {
            allocator_->Free(allocation_);
        }

        allocator_ = other.allocator_;
        allocation_ = other.allocation_;
        ownsAllocation_ = other.ownsAllocation_;

        other.ownsAllocation_ = false;
        other.allocation_ = Allocation{};
    }
    return *this;
}

Allocation ScopedAllocation::Release() {
    ownsAllocation_ = false;
    return allocation_;
}

} // namespace MultiGPU
} // namespace Deep2
