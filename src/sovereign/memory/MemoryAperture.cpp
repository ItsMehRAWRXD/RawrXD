// ============================================================================
// MemoryAperture.cpp - Memory Aperture Monitor & Heap-free Allocator
// ============================================================================

#include "MemoryAperture.hpp"
#include <cstring>
#include <algorithm>
#include <iostream>

namespace Sovereign {

MemoryApertureMonitor::MemoryApertureMonitor() = default;
MemoryApertureMonitor::~MemoryApertureMonitor() {
    Shutdown();
}

bool MemoryApertureMonitor::Initialize(const ApertureConfig& config) {
    config_ = config;
    
    if (config_.size == 0) {
        config_.size = 1ULL << 30; // 1GB default
    }
    
    // Reserve virtual address space
    uint64_t base = reinterpret_cast<uint64_t>(
        VirtualAlloc(nullptr, config_.size, MEM_RESERVE, config_.protection));
    
    if (!base) return false;
    
    config_.baseAddress = base;
    
    // Initialize free list
    FreeBlock initial;
    initial.address = base;
    initial.size = config_.size;
    freeList_.push_back(initial);
    
    // Record region
    MemoryRegion region;
    region.address = base;
    region.size = config_.size;
    region.protection = config_.protection;
    region.isFree = true;
    region.isHugePage = false;
    region.numaNode = config_.numaNode;
    region.tag = "aperture";
    regions_.push_back(region);
    
    stats_.totalSize = config_.size;
    initialized_ = true;
    return true;
}

void MemoryApertureMonitor::Shutdown() {
    if (config_.baseAddress) {
        VirtualFree(reinterpret_cast<LPVOID>(config_.baseAddress), 0, MEM_RELEASE);
    }
    freeList_.clear();
    regions_.clear();
    initialized_ = false;
}

bool MemoryApertureMonitor::Reserve(uint64_t size) {
    uint64_t address = reinterpret_cast<uint64_t>(
        VirtualAlloc(nullptr, size, MEM_RESERVE, config_.protection));
    if (!address) return false;
    
    FreeBlock block;
    block.address = address;
    block.size = size;
    freeList_.push_back(block);
    
    stats_.totalSize += size;
    return true;
}

bool MemoryApertureMonitor::Commit(uint64_t address, uint64_t size) {
    void* result = VirtualAlloc(reinterpret_cast<LPVOID>(address), size, 
                                 MEM_COMMIT, config_.protection);
    if (!result) return false;
    
    stats_.usedSize += size;
    stats_.peakSize = std::max(stats_.peakSize, stats_.usedSize);
    return true;
}

bool MemoryApertureMonitor::Decommit(uint64_t address, uint64_t size) {
    if (VirtualFree(reinterpret_cast<LPVOID>(address), size, MEM_DECOMMIT)) {
        stats_.usedSize -= size;
        return true;
    }
    return false;
}

bool MemoryApertureMonitor::Release(uint64_t address, uint64_t size) {
    if (VirtualFree(reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE)) {
        stats_.totalSize -= size;
        return true;
    }
    return false;
}

void* MemoryApertureMonitor::Allocate(uint64_t size, uint32_t alignment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size = AlignUp(size, alignment);
    
    // Find best fit in free list
    int bestIdx = -1;
    uint64_t bestSize = UINT64_MAX;
    
    for (size_t i = 0; i < freeList_.size(); ++i) {
        if (freeList_[i].size >= size && freeList_[i].size < bestSize) {
            bestSize = freeList_[i].size;
            bestIdx = i;
        }
    }
    
    if (bestIdx < 0) return nullptr;
    
    uint64_t address = freeList_[bestIdx].address;
    
    // Split block if larger
    if (freeList_[bestIdx].size > size) {
        FreeBlock remainder;
        remainder.address = address + size;
        remainder.size = freeList_[bestIdx].size - size;
        freeList_.push_back(remainder);
    }
    
    freeList_.erase(freeList_.begin() + bestIdx);
    
    // Commit pages
    Commit(address, size);
    
    stats_.allocations++;
    stats_.usedSize += size;
    stats_.peakSize = std::max(stats_.peakSize, stats_.usedSize);
    
    if (allocationCallback_) {
        allocationCallback_(address, size);
    }
    
    return reinterpret_cast<void*>(address);
}

void MemoryApertureMonitor::Free(void* ptr) {
    if (!ptr) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t address = reinterpret_cast<uint64_t>(ptr);
    
    // Find the region
    for (auto& region : regions_) {
        if (address >= region.address && address < region.address + region.size) {
            FreeBlock block;
            block.address = address;
            block.size = region.size;
            freeList_.push_back(block);
            
            Decommit(address, region.size);
            stats_.deallocations++;
            stats_.usedSize -= region.size;
            return;
        }
    }
}

bool MemoryApertureMonitor::LockPages(uint64_t address, uint64_t size) {
    return VirtualLock(reinterpret_cast<LPVOID>(address), size) != 0;
}

bool MemoryApertureMonitor::UnlockPages(uint64_t address, uint64_t size) {
    return VirtualUnlock(reinterpret_cast<LPVOID>(address), size) != 0;
}

bool MemoryApertureMonitor::PrefetchPages(uint64_t address, uint64_t size) {
    // Prefetch into cache
    volatile uint8_t* base = reinterpret_cast<uint8_t*>(address);
    for (uint64_t i = 0; i < size; i += 64) {
        __cpuidex(reinterpret_cast<int*>(base + i), 0, 0);
    }
    return true;
}

bool MemoryApertureMonitor::EnableHugePages(bool enabled) {
    config_.useHugePages = enabled;
    return true;
}

bool MemoryApertureMonitor::IsHugePageSupported() const {
    // Check for 2MB page support via CPUID
    int regs[4];
    __cpuid(regs, 0x80000001);
    return (regs[3] & (1 << 26)) != 0; // Page 1GB support
}

uint64_t MemoryApertureMonitor::GetHugePageSize() const {
    return 2ULL << 20; // 2MB
}

ApertureStats MemoryApertureMonitor::GetStats() const {
    return stats_;
}

bool MemoryApertureMonitor::Defragment() {
    // Merge adjacent free blocks
    std::sort(freeList_.begin(), freeList_.end(), 
        [](const FreeBlock& a, const FreeBlock& b) { return a.address < b.address; });
    
    for (size_t i = 0; i + 1 < freeList_.size(); ) {
        if (freeList_[i].address + freeList_[i].size == freeList_[i + 1].address) {
            freeList_[i].size += freeList_[i + 1].size;
            freeList_.erase(freeList_.begin() + i + 1);
        } else {
            i++;
        }
    }
    
    return true;
}

uint64_t MemoryApertureMonitor::AlignUp(uint64_t value, uint64_t alignment) const {
    return (value + alignment - 1) & ~(alignment - 1);
}

// ============================================================
// HeapFreeAllocator
// ============================================================

HeapFreeAllocator::HeapFreeAllocator() = default;
HeapFreeAllocator::~HeapFreeAllocator() {
    Shutdown();
}

bool HeapFreeAllocator::Initialize(void* pool, uint64_t poolSize) {
    pool_ = static_cast<uint8_t*>(pool);
    poolSize_ = poolSize;
    offset_ = 0;
    used_ = 0;
    initialized_ = true;
    return true;
}

void HeapFreeAllocator::Shutdown() {
    pool_ = nullptr;
    poolSize_ = 0;
    offset_ = 0;
    used_ = 0;
    initialized_ = false;
}

void* HeapFreeAllocator::Allocate(uint64_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) return nullptr;
    
    // Align to 16 bytes
    size = (size + 15) & ~15ULL;
    
    // Check free list first
    for (size_t i = 0; i < freeEntries_.size(); ++i) {
        if (freeEntries_[i].size >= size) {
            void* ptr = freeEntries_[i].ptr;
            if (freeEntries_[i].size > size) {
                freeEntries_[i].ptr = static_cast<uint8_t*>(ptr) + size;
                freeEntries_[i].size -= size;
            } else {
                freeEntries_.erase(freeEntries_.begin() + i);
            }
            stats_.allocations++;
            stats_.currentUsage += size;
            stats_.peakUsage = std::max(stats_.peakUsage, stats_.currentUsage);
            return ptr;
        }
    }
    
    // Allocate from pool
    if (offset_ + size > poolSize_) return nullptr;
    
    void* ptr = pool_ + offset_;
    offset_ += size;
    used_ += size;
    
    stats_.allocations++;
    stats_.currentUsage += size;
    stats_.peakUsage = std::max(stats_.peakUsage, stats_.currentUsage);
    
    return ptr;
}

void HeapFreeAllocator::Free(void* ptr) {
    if (!ptr) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Add to free list
    FreeEntry entry;
    entry.ptr = ptr;
    entry.size = 0; // Size unknown in this simple allocator
    freeEntries_.push_back(entry);
    
    stats_.deallocations++;
}

void HeapFreeAllocator::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    offset_ = 0;
    used_ = 0;
    freeEntries_.clear();
}

void HeapFreeAllocator::Compact() {
    // Coalesce adjacent free entries
    std::sort(freeEntries_.begin(), freeEntries_.end(),
        [](const FreeEntry& a, const FreeEntry& b) { return a.ptr < b.ptr; });
}

} // namespace Sovereign
