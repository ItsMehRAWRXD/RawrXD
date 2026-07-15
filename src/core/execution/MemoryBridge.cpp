//==============================================================================
// MemoryBridge.cpp
// Memory management implementation
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <string>
#include <windows.h>
#include "MemoryBridge.hpp"

namespace Sovereign {

//==============================================================================
// MemoryBuffer Implementation
//==============================================================================
void MemoryBuffer::Release() {
    if (data && owned) {
        MemoryBridge::AlignedFree(data);
        data = nullptr;
    }
    size = 0;
    capacity = 0;
}

bool MemoryBuffer::Allocate(size_t sz, BufferType t, uint32_t align) {
    Release();
    
    data = MemoryBridge::AlignedAlloc(sz, align);
    if (!data) return false;
    
    size = sz;
    capacity = sz;
    type = t;
    alignment = align;
    owned = true;
    
    return true;
}

bool MemoryBuffer::Resize(size_t newSize) {
    if (newSize <= capacity) {
        size = newSize;
        return true;
    }
    
    // Need to reallocate
    void* newData = MemoryBridge::AlignedAlloc(newSize, alignment);
    if (!newData) return false;
    
    // Copy existing data
    if (data) {
        memcpy(newData, data, size);
        MemoryBridge::AlignedFree(data);
    }
    
    data = newData;
    size = newSize;
    capacity = newSize;
    return true;
}

void MemoryBuffer::Zero() {
    if (data && size > 0) {
        memset(data, 0, size);
    }
}

MemoryBuffer::MemoryBuffer(MemoryBuffer&& other) noexcept
    : data(other.data)
    , size(other.size)
    , capacity(other.capacity)
    , type(other.type)
    , alignment(other.alignment)
    , owned(other.owned)
{
    other.data = nullptr;
    other.size = 0;
    other.capacity = 0;
    other.owned = false;
}

MemoryBuffer& MemoryBuffer::operator=(MemoryBuffer&& other) noexcept {
    if (this != &other) {
        Release();
        data = other.data;
        size = other.size;
        capacity = other.capacity;
        type = other.type;
        alignment = other.alignment;
        owned = other.owned;
        
        other.data = nullptr;
        other.size = 0;
        other.capacity = 0;
        other.owned = false;
    }
    return *this;
}

//==============================================================================
// MemoryPool Implementation
//==============================================================================
MemoryPool::MemoryPool() : poolBase_(nullptr), totalSize_(0) {}

MemoryPool::~MemoryPool() {
    if (poolBase_) {
        VirtualFree(poolBase_, 0, MEM_RELEASE);
    }
}

bool MemoryPool::Initialize(size_t totalSize) {
    totalSize_ = totalSize;
    
    // Allocate large page-aligned memory
    poolBase_ = VirtualAlloc(nullptr, totalSize, 
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!poolBase_) {
        // Fallback to regular allocation
        poolBase_ = _aligned_malloc(totalSize, MEMORY_ALIGNMENT_DEFAULT);
        if (!poolBase_) return false;
    }
    
    // Initialize with one free block
    blocks_.clear();
    Block initialBlock;
    initialBlock.ptr = poolBase_;
    initialBlock.size = totalSize;
    initialBlock.used = false;
    blocks_.push_back(initialBlock);
    
    return true;
}

void* MemoryPool::Allocate(size_t size, uint32_t alignment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Align size
    size = (size + alignment - 1) & ~(alignment - 1);
    
    // Find first fit
    for (auto& block : blocks_) {
        if (!block.used && block.size >= size) {
            // Align pointer
            void* alignedPtr = reinterpret_cast<void*>(
                (reinterpret_cast<uintptr_t>(block.ptr) + alignment - 1) & ~(alignment - 1)
            );
            
            block.used = true;
            block.ptr = alignedPtr;
            return alignedPtr;
        }
    }
    
    return nullptr; // Out of memory
}

void MemoryPool::Free(void* ptr) {
    if (!ptr) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& block : blocks_) {
        if (block.ptr == ptr) {
            block.used = false;
            // TODO: Coalesce adjacent free blocks
            return;
        }
    }
}

size_t MemoryPool::GetUsedSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t used = 0;
    for (const auto& block : blocks_) {
        if (block.used) used += block.size;
    }
    return used;
}

void MemoryPool::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& block : blocks_) {
        block.used = false;
    }
}

bool MemoryPool::Contains(void* ptr) const {
    if (!ptr || !poolBase_) return false;
    return ptr >= poolBase_ && 
           reinterpret_cast<char*>(ptr) < reinterpret_cast<char*>(poolBase_) + totalSize_;
}

//==============================================================================
// MemoryBridge Implementation
//==============================================================================
MemoryBridge::MemoryBridge() : totalAllocated_(0) {}

MemoryBridge::~MemoryBridge() {}

bool MemoryBridge::Initialize(size_t poolSize) {
    return pool_.Initialize(poolSize);
}

void* MemoryBridge::AlignedAlloc(size_t size, uint32_t alignment) {
    void* ptr = _aligned_malloc(size, alignment);
    if (ptr) {
        // Track allocation
        GetInstance().totalAllocated_ += size;
    }
    return ptr;
}

void MemoryBridge::AlignedFree(void* ptr) {
    _aligned_free(ptr);
}

std::shared_ptr<MemoryBuffer> MemoryBridge::CreateBuffer(size_t size, 
                                                           BufferType type,
                                                           uint32_t alignment) {
    auto buffer = std::make_shared<MemoryBuffer>();
    if (!buffer->Allocate(size, type, alignment)) {
        return nullptr;
    }
    return buffer;
}

std::shared_ptr<MemoryBuffer> MemoryBridge::GetOrCreateBuffer(const std::string& name,
                                                               size_t size,
                                                               BufferType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = namedBuffers_.find(name);
    if (it != namedBuffers_.end()) {
        // Check if existing buffer is large enough
        if (it->second->capacity >= size) {
            it->second->size = size;
            return it->second;
        }
        // Need larger buffer
        namedBuffers_.erase(it);
    }
    
    // Create new buffer
    auto buffer = CreateBuffer(size, type);
    if (buffer) {
        namedBuffers_[name] = buffer;
    }
    return buffer;
}

void MemoryBridge::ReleaseBuffer(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    namedBuffers_.erase(name);
}

MemoryBridge::Stats MemoryBridge::GetStats() const {
    Stats stats;
    stats.totalAllocated = totalAllocated_;
    stats.totalUsed = 0; // Would need tracking
    stats.poolSize = pool_.GetTotalSize();
    stats.poolUsed = pool_.GetUsedSize();
    stats.bufferCount = namedBuffers_.size();
    return stats;
}

void MemoryBridge::PrintStats() const {
    auto stats = GetStats();
    printf("=== Memory Bridge Stats ===\n");
    printf("Total Allocated: %zu MB\n", stats.totalAllocated / (1024 * 1024));
    printf("Pool Size: %zu MB\n", stats.poolSize / (1024 * 1024));
    printf("Pool Used: %zu MB\n", stats.poolUsed / (1024 * 1024));
    printf("Named Buffers: %zu\n", stats.bufferCount);
}

MemoryBridge& MemoryBridge::GetInstance() {
    static MemoryBridge instance;
    return instance;
}

} // namespace Sovereign
