// =============================================================================
// RawrXD-CoreRuntime: Memory Pool Implementation (Functional)
// =============================================================================
// Provides efficient memory allocation with pooling, alignment, and tracking

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/memory_pool.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <algorithm>
#include <Windows.h>

namespace RawrXD {
namespace Core {

// ============================================================================
// Memory Block Structure
// ============================================================================
struct MemoryBlock {
    static constexpr size_t ALIGNMENT = 64; // Cache line alignment
    
    void* basePtr = nullptr;      // Original allocation
    void* alignedPtr = nullptr;   // Aligned pointer
    size_t size = 0;              // Requested size
    size_t actualSize = 0;        // Actual allocated size
    bool inUse = false;           // Usage flag
    uint32_t allocationId = 0;      // Unique allocation ID
};

// ============================================================================
// Memory Pool Implementation
// ============================================================================
class MemoryPool::Impl {
public:
    // Pool configuration
    size_t blockSize = 64 * 1024;      // 64KB default block size
    size_t maxBlocks = 1024;             // Maximum number of blocks
    size_t alignment = 64;               // 64-byte alignment
    
    // Pool state
    std::vector<MemoryBlock> blocks;
    std::map<void*, size_t> allocationMap; // ptr -> block index
    size_t totalAllocated = 0;
    size_t totalCapacity = 0;
    uint32_t nextAllocationId = 1;
    
    // Thread safety
    std::mutex mutex;
    
    // Statistics
    size_t allocationCount = 0;
    size_t freeCount = 0;
    size_t peakAllocated = 0;
    
    Impl() = default;
    
    ~Impl() {
        Cleanup();
    }
    
    bool Initialize(size_t capacity) {
        std::lock_guard<std::mutex> lock(mutex);
        
        if (capacity == 0) {
            return false;
        }
        
        totalCapacity = capacity;
        
        // Pre-allocate blocks
        size_t numBlocks = std::min(capacity / blockSize, maxBlocks);
        blocks.reserve(numBlocks);
        
        for (size_t i = 0; i < numBlocks; ++i) {
            MemoryBlock block;
            block.actualSize = blockSize + alignment; // Extra space for alignment
            block.basePtr = VirtualAlloc(nullptr, block.actualSize, 
                                         MEM_COMMIT | MEM_RESERVE, 
                                         PAGE_READWRITE);
            if (!block.basePtr) {
                // Cleanup partial allocations
                Cleanup();
                return false;
            }
            
            // Align pointer
            uintptr_t addr = reinterpret_cast<uintptr_t>(block.basePtr);
            uintptr_t alignedAddr = (addr + alignment - 1) & ~(alignment - 1);
            block.alignedPtr = reinterpret_cast<void*>(alignedAddr);
            block.size = blockSize;
            block.inUse = false;
            
            blocks.push_back(std::move(block));
        }
        
        return true;
    }
    
    void* Allocate(size_t size) {
        if (size == 0) return nullptr;
        
        std::lock_guard<std::mutex> lock(mutex);
        
        // Round up to block size
        size_t blocksNeeded = (size + blockSize - 1) / blockSize;
        
        // Find contiguous free blocks
        for (size_t i = 0; i <= blocks.size() - blocksNeeded; ++i) {
            bool found = true;
            for (size_t j = 0; j < blocksNeeded; ++j) {
                if (i + j >= blocks.size() || blocks[i + j].inUse) {
                    found = false;
                    break;
                }
            }
            
            if (found) {
                // Mark blocks as used
                for (size_t j = 0; j < blocksNeeded; ++j) {
                    blocks[i + j].inUse = true;
                    blocks[i + j].allocationId = nextAllocationId;
                    if (j == 0) {
                        blocks[i].size = size; // Store actual requested size
                    }
                }
                
                void* ptr = blocks[i].alignedPtr;
                allocationMap[ptr] = i;
                totalAllocated += size;
                allocationCount++;
                
                if (totalAllocated > peakAllocated) {
                    peakAllocated = totalAllocated;
                }
                
                nextAllocationId++;
                
                // Zero memory
                std::memset(ptr, 0, size);
                
                return ptr;
            }
        }
        
        // No contiguous blocks available - allocate from system
        size_t allocSize = size + alignment;
        void* basePtr = VirtualAlloc(nullptr, allocSize, 
                                    MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_READWRITE);
        if (!basePtr) {
            return nullptr;
        }
        
        // Align
        uintptr_t addr = reinterpret_cast<uintptr_t>(basePtr);
        uintptr_t alignedAddr = (addr + alignment - 1) & ~(alignment - 1);
        void* alignedPtr = reinterpret_cast<void*>(alignedAddr);
        
        // Track system allocation
        MemoryBlock block;
        block.basePtr = basePtr;
        block.alignedPtr = alignedPtr;
        block.size = size;
        block.actualSize = allocSize;
        block.inUse = true;
        block.allocationId = nextAllocationId++;
        
        size_t blockIdx = blocks.size();
        blocks.push_back(std::move(block));
        allocationMap[alignedPtr] = blockIdx;
        
        totalAllocated += size;
        allocationCount++;
        
        if (totalAllocated > peakAllocated) {
            peakAllocated = totalAllocated;
        }
        
        std::memset(alignedPtr, 0, size);
        
        return alignedPtr;
    }
    
    void Free(void* ptr, size_t size) {
        if (!ptr) return;
        
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = allocationMap.find(ptr);
        if (it == allocationMap.end()) {
            // Unknown pointer - ignore or log
            return;
        }
        
        size_t blockIdx = it->second;
        if (blockIdx >= blocks.size()) {
            return;
        }
        
        MemoryBlock& block = blocks[blockIdx];
        
        // Calculate how many blocks to free
        size_t blocksToFree = (block.size + blockSize - 1) / blockSize;
        
        // Mark blocks as free
        for (size_t i = 0; i < blocksToFree && (blockIdx + i) < blocks.size(); ++i) {
            blocks[blockIdx + i].inUse = false;
            blocks[blockIdx + i].allocationId = 0;
        }
        
        totalAllocated -= std::min(size, totalAllocated);
        freeCount++;
        
        allocationMap.erase(it);
    }
    
    void* Reallocate(void* ptr, size_t oldSize, size_t newSize) {
        if (!ptr) {
            return Allocate(newSize);
        }
        
        if (newSize == 0) {
            Free(ptr, oldSize);
            return nullptr;
        }
        
        // Allocate new block
        void* newPtr = Allocate(newSize);
        if (!newPtr) {
            return nullptr;
        }
        
        // Copy old data
        size_t copySize = std::min(oldSize, newSize);
        std::memcpy(newPtr, ptr, copySize);
        
        // Free old block
        Free(ptr, oldSize);
        
        return newPtr;
    }
    
    size_t GetAllocated() const {
        std::lock_guard<std::mutex> lock(mutex);
        return totalAllocated;
    }
    
    size_t GetCapacity() const {
        std::lock_guard<std::mutex> lock(mutex);
        return totalCapacity;
    }
    
    size_t GetBlockSize() const {
        return blockSize;
    }
    
    size_t GetFreeBlocks() const {
        std::lock_guard<std::mutex> lock(mutex);
        size_t free = 0;
        for (const auto& block : blocks) {
            if (!block.inUse) free++;
        }
        return free;
    }
    
    void GetStats(MemoryPoolStats& stats) const {
        std::lock_guard<std::mutex> lock(mutex);
        stats.totalAllocated = totalAllocated;
        stats.totalCapacity = totalCapacity;
        stats.allocationCount = allocationCount;
        stats.freeCount = freeCount;
        stats.peakAllocated = peakAllocated;
        stats.blockCount = blocks.size();
        stats.freeBlockCount = GetFreeBlocks();
    }
    
    void Cleanup() {
        for (auto& block : blocks) {
            if (block.basePtr) {
                VirtualFree(block.basePtr, 0, MEM_RELEASE);
                block.basePtr = nullptr;
                block.alignedPtr = nullptr;
            }
        }
        blocks.clear();
        allocationMap.clear();
        totalAllocated = 0;
        totalCapacity = 0;
    }
};

// ============================================================================
// MemoryPool Public Interface
// ============================================================================
MemoryPool::MemoryPool() : pImpl(new Impl()) {}
MemoryPool::~MemoryPool() = default;
MemoryPool::MemoryPool(MemoryPool&&) noexcept = default;
MemoryPool& MemoryPool::operator=(MemoryPool&&) noexcept = default;

bool MemoryPool::Initialize(size_t capacity) {
    return pImpl->Initialize(capacity);
}

void* MemoryPool::Allocate(size_t size) {
    return pImpl->Allocate(size);
}

void MemoryPool::Free(void* ptr, size_t size) {
    pImpl->Free(ptr, size);
}

void* MemoryPool::Reallocate(void* ptr, size_t oldSize, size_t newSize) {
    return pImpl->Reallocate(ptr, oldSize, newSize);
}

size_t MemoryPool::GetAllocated() const {
    return pImpl->GetAllocated();
}

size_t MemoryPool::GetCapacity() const {
    return pImpl->GetCapacity();
}

size_t MemoryPool::GetBlockSize() const {
    return pImpl->GetBlockSize();
}

size_t MemoryPool::GetFreeBlocks() const {
    return pImpl->GetFreeBlocks();
}

void MemoryPool::GetStats(MemoryPoolStats& stats) const {
    pImpl->GetStats(stats);
}

// ============================================================================
// C API for external linking
// ============================================================================
extern "C" {
    void* MemoryPool_Create() {
        return new MemoryPool();
    }
    
    void MemoryPool_Destroy(void* pool) {
        delete static_cast<MemoryPool*>(pool);
    }
    
    int MemoryPool_Initialize(void* pool, size_t capacity) {
        if (!pool) return -1;
        return static_cast<MemoryPool*>(pool)->Initialize(capacity) ? 0 : -1;
    }
    
    void* MemoryPool_Allocate(void* pool, size_t size) {
        if (!pool) return nullptr;
        return static_cast<MemoryPool*>(pool)->Allocate(size);
    }
    
    void MemoryPool_Free(void* pool, void* ptr, size_t size) {
        if (!pool) return;
        static_cast<MemoryPool*>(pool)->Free(ptr, size);
    }
    
    size_t MemoryPool_GetAllocated(void* pool) {
        if (!pool) return 0;
        return static_cast<MemoryPool*>(pool)->GetAllocated();
    }
    
    size_t MemoryPool_GetCapacity(void* pool) {
        if (!pool) return 0;
        return static_cast<MemoryPool*>(pool)->GetCapacity();
    }
}

} // namespace Core
} // namespace RawrXD
