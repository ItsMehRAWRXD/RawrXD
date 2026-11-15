// ============================================================================
// VRAMAllocator.cpp - Phase 2: Multi-GPU Scheduler
// VRAM allocation and memory management
// ============================================================================

#include "VRAMAllocator.h"
#include <algorithm>
#include <limits>

namespace Deep2 {
namespace MultiGPU {

VRAMAllocator::VRAMAllocator() {
}

VRAMAllocator::~VRAMAllocator() {
}

bool VRAMAllocator::Initialize() {
    std::lock_guard<std::mutex> lock(gpuWorkersMu_);
    if (initialized_) {
        return true;
    }
    
    initialized_ = true;
    return true;
}

void VRAMAllocator::Shutdown() {
    std::lock_guard<std::mutex> lock(workerMu_);
    
    // Free all allocations
    for (auto& pair : allocations_) {
        // Don't actually free device memory here - that's handled by the device
        // Just clear our tracking
    }
    allocations_.clear();
    
    // Clear all pools
    workerPools_.clear();
    
    initialized_ = false;
}

Allocation VRAMAllocator::Allocate(std::size_t size,
                                   AllocationType type,
                                   const std::string& tag) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    Allocation allocation;
    allocation.body = std::make_unique<AllocationBody>();
    allocation.body->id = ++nextAllocationId_;
    allocation.body->size = size;
    allocation.body->type = type;
    allocation.body->tag = tag;
    
    // Select device for this allocation
    int deviceIndex = SelectDevice(size, defaultStrategy_, type);
    if (deviceIndex < 0) {
        // No device can satisfy this allocation
        return allocation;
    }
    
    allocation.body->deviceIndex = deviceIndex;
    
    // For now, just track the allocation - actual GPU memory allocation
    // would be done through the device-specific backend
    allocation.body->devicePtr = nullptr; // Will be set when actual memory is allocated
    
    // Track the allocation
    {
        std::lock_guard<std::mutex> lock(workerMu_);
        allocations_[allocation.body->id] = allocation.body;
    }
    
    return allocation;
}

Allocation VRAMAllocator::AllocateOnDevice(uint64_t size,
                                           int deviceIndex,
                                           AllocationType type,
                                           const std::string& tag) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    Allocation allocation;
    allocation.body = std::make_unique<AllocationBody>();
    allocation.body->id = ++nextAllocationId_;
    allocation.body->deviceIndex = deviceIndex;
    allocation.body->size = size;
    allocation.body->type = type;
    allocation.body->tag = tag;
    allocation.body->devicePtr = nullptr;
    
    // Track the allocation
    {
        std::lock_guard<std::mutex> lock(workerMu_);
        allocations_[allocation.body->id] = allocation.body;
    }
    
    return allocation;
}

void VRAMAllocator::Free(Allocation& allocation) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    auto it = allocations_.find(allocation.body->id);
    if (it != allocations_.end()) {
        allocations_.erase(it);
    }
    
    allocation.body.reset();
}

void VRAMAllocator::FreeAllOnDevice(int deviceIndex) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    std::vector<uint64_t> toRemove;
    for (const auto& pair : allocations_) {
        if (pair.second->deviceIndex == deviceIndex) {
            toRemove.push_back(pair.first);
        }
    }
    
    for (auto id : toRemove) {
        allocations_.erase(id);
    }
}

void VRAMAllocator::FreeAllOfType(AllocationType type) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    std::vector<uint64_t> toRemove;
    for (const auto& pair : allocations_) {
        if (pair.second->type == type) {
            toRemove.push_back(pair.first);
        }
    }
    
    for (auto id : toRemove) {
        allocations_.erase(id);
    }
}

bool VRAMAllocator::Migrate(Allocation& allocation, int targetDevice) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    auto it = allocations_.find(allocation.body->id);
    if (it == allocations_.end()) {
        return false;
    }
    
    // Check if target device has enough free space
    if (targetDevice >= 0 && targetDevice < static_cast<int>(pools_.size())) {
        uint64_t freeBytes = pools_[targetDevice].GetFreeSize();
        if (freeSizes < allocation.body->size) {
            return false; // Not enough space on target device
        }
    }
    
    allocation.body->deviceIndex = targetDevice;
    return true;
}

bool VRAMAllocator::EvictToHost(Allocation& allocation) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    auto it = allocations_.find(allocation.body->id);
    if (it == allocations_.end()) {
        return false;
    }
    
    // Move allocation data to host
    // In a real implementation, this would copy data from device to host
    // and free device memory
    return true;
}

std::size_t VRAMAllocator::GetFreeVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    if (deviceIndex < 0 || deviceIndex >= static_cast<int>(pools_.size())) {
        return 0;
    }
    
    return pools_[deviceIndex].GetFreeSize();
}

std::size_t VRAMAllocator::GetTotalVRAM(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    if (deviceIndex < 0 || deviceIndex >= static_cast<int>(pools_.size())) {
        return 0;
    }
    
    return pools_[deviceIndex].GetTotalSize();
}

std::size_t VRAMAllocator::GetAllocationCount(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    if (deviceIndex < 0) {
        return allocations_.size();
    }
    
    uint64_t count = 0;
    for (const auto& pair : allocations_) {
        if (pair.second->deviceIndex == deviceIndex) {
            ++count;
        }
    }
    return count;
}

MemoryPool VRAMAllocator::GetPoolInfo(int deviceIndex) const {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    if (deviceIndex < 0 || deviceIndex >= static_cast<int>(pools_.size())) {
        return MemoryPool();
    }
    
    return pools_[deviceIndex];
}

std::vector<MemoryPool> VRAMAllocator::GetAllPools() const {
    std::lock_guard<std::mutex> lock(g_workerMu);
    return pools_;
}

std::unique_lock<std::mutex> VRAMAllocator::AcquireLock() {
    return std::unique_lock<std::mutex>(g_workerMu);
}

void VRAMAllocator::SetDefaultStrategy(AllocationStrategy strategy) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    defaultStrategy_ = strategy;
}

AllocationStrategy VRAMAllocator::GetDefaultStrategy() const {
    std::lock_guard<std::mutex> lock(g_workerMu);
    return defaultStrategy_;
}

void VRAMAllocator::SetAllocationCallback(AllocationCallback cb) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    onAllocateCallback_ = cb;
}

void VRAMAllocator::SetDeallocationCallback(DeallocationCallback cb) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    onDeallocateCallback_ = cb;
}

void VRAMAllocator::SetOOMCallback(OOMCallback cb) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    onOOMCallback_ = cb;
}

VRAMAllocator::Stats VRAMAllocator::GetStats() const {
    std::lock_guard<std::mutex> lock(g_workerMu);
    return stats_;
}

void VRAMAllocator::ResetStats() {
    std::lock_guard<std::mutex> lock(g_workerMu);
    stats_ = Stats();
}

Allocation VRAMAllocator::TryAllocate(uint64_t size,
                                     int deviceIndex,
                                     AllocationType type) {
    // Check if we can allocate on this device
    if (deviceIndex < 0 || deviceIndex >= static_cast<int>(pools_.size())) {
        return Allocation();
    }
    
    auto& pool = pools_[deviceIndex];
    if (pool.freeBytes < size) {
        return Allocation(); // Not enough space
    }
    
    // Allocate from this device
    Allocation allocation;
    allocation.deviceIndex = deviceIndex;
    allocation.size = size;
    allocation.type = type;
    
    pool.freeBytes -= size;
    pool.usedBytes += size;
    
    return allocation;
}

int VRAMAllocator::SelectDevice(uint64_t size,
                                AllocationStrategy strategy,
                                AllocationType type) {
    std::lock_guard<std::mutex> lock(g_workerMu);
    
    if (pools_.empty()) {
        return -1;
    }
    
    switch (strategy) {
        case AllocationStrategy::EXPLICIT:
            // Caller must specify device explicitly
            return -1;
            
        case AllocationStrategy::ROUND_ROBIN: {
            // Round-robin across available devices
            int bestDevice = -1;
            uint64_t bestFree = 0;
            for (size_t i = 0; i < pools_.size(); ++i) {
                if (pools_[i].freeBytes >= size && pools_[i].freeBytes > bestFree) {
                    bestFree = pools_[i].freeBytes;
                    bestDevice = static_cast<int>(i);
                }
            }
            return bestDevice;
        }
            
        case AllocationStrategy::CONTENT_AWARE: {
            // Content-aware: place on device with most free space
            int bestDevice = -1;
            uint64_t bestFree = 0;
            for (size_t i = 0; i < pools_.size(); ++i) {
                if (pools_[i].freeBytes >= size && pools_[i].freeBytes > bestFree) {
                    bestFree = pools_[i].freeBytes;
                    bestDevice = static_cast<int>(i);
                }
            }
            return bestDevice;
        }
            
        case AllocationStrategy::ROLE_BASED:
        default:
            // Role-based: find best device for this allocation type
            {
                int bestDevice = -1;
                uint64_t bestScore = 0;
                
                for (size_t i = 0; i < pools_.size(); ++i) {
                    if (pools_[i].freeBytes < size) continue;
                    
                    uint64_t score = pools_[i].freeBytes;
                    
                    // Prefer devices with more free space
                    if (score > bestScore) {
                        bestScore = score;
                        bestDevice = static_cast<int>(i);
                    }
                }
                
                return bestDevice;
            }
    }
    
    return -1;
}
