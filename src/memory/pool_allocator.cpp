// Real implementation for pool_allocator.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/pool_allocator.h"

#include <cstdlib>
#include <cstring>
#include <vector>
#include <mutex>

namespace RawrXD { namespace Core {

struct PoolBlock {
    void* memory = nullptr;
    bool inUse = false;
};

class PoolAllocator::Impl {
public:
    std::vector<PoolBlock> blocks;
    std::mutex mutex;
    size_t blockSize = 4096;  // 4KB default
    size_t poolCapacity = 256;  // Max blocks in pool
};

PoolAllocator::PoolAllocator() : pImpl(new Impl()) {}
PoolAllocator::~PoolAllocator() = default;
PoolAllocator::PoolAllocator(PoolAllocator&&) noexcept = default;
PoolAllocator& PoolAllocator::operator=(PoolAllocator&&) noexcept = default;

bool PoolAllocator::Initialize(size_t blockSize, size_t capacity) {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    pImpl->blockSize = blockSize;
    pImpl->poolCapacity = capacity;

    // Pre-allocate all blocks
    pImpl->blocks.reserve(capacity);
    for (size_t i = 0; i < capacity; ++i) {
        PoolBlock block;
        block.memory = std::aligned_alloc(64, blockSize);
        if (!block.memory) return false;
        block.inUse = false;
        pImpl->blocks.push_back(block);
    }
    return true;
}

void* PoolAllocator::Allocate() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);

    for (auto& block : pImpl->blocks) {
        if (!block.inUse) {
            block.inUse = true;
            return block.memory;
        }
    }

    // Pool exhausted — allocate overflow block
    void* ptr = std::aligned_alloc(64, pImpl->blockSize);
    if (ptr) {
        PoolBlock block;
        block.memory = ptr;
        block.inUse = true;
        pImpl->blocks.push_back(block);
    }
    return ptr;
}

void PoolAllocator::Free(void* ptr) {
    if (!ptr) return;

    std::lock_guard<std::mutex> lock(pImpl->mutex);

    for (auto& block : pImpl->blocks) {
        if (block.memory == ptr) {
            block.inUse = false;
            return;
        }
    }

    // Not from pool — free directly
    std::free(ptr);
}

void PoolAllocator::Reset() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    for (auto& block : pImpl->blocks) {
        block.inUse = false;
    }
}

void PoolAllocator::Release() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    for (auto& block : pImpl->blocks) {
        if (block.memory) {
            std::free(block.memory);
        }
    }
    pImpl->blocks.clear();
}

size_t PoolAllocator::GetFreeCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    size_t count = 0;
    for (const auto& block : pImpl->blocks) {
        if (!block.inUse) ++count;
    }
    return count;
}

size_t PoolAllocator::GetTotalCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return pImpl->blocks.size();
}

}} // namespace RawrXD::Core
