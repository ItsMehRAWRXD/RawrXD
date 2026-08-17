// Real implementation for arena_allocator.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/arena_allocator.h"

#include <cstdlib>
#include <cstring>
#include <vector>
#include <mutex>

namespace RawrXD { namespace Core {

struct ArenaBlock {
    void* memory = nullptr;
    size_t size = 0;
    size_t used = 0;
};

class ArenaAllocator::Impl {
public:
    std::vector<ArenaBlock> blocks;
    std::mutex mutex;
    size_t blockSize = 64 * 1024;  // 64KB default block size

    void* AllocateFromBlock(ArenaBlock& block, size_t size) {
        if (block.used + size > block.size) {
            return nullptr;
        }
        void* ptr = static_cast<char*>(block.memory) + block.used;
        block.used += size;
        return ptr;
    }

    ArenaBlock AllocateNewBlock(size_t minSize) {
        ArenaBlock block;
        block.size = std::max(blockSize, minSize);
        block.memory = std::aligned_alloc(64, block.size);  // 64-byte aligned for SIMD
        block.used = 0;
        return block;
    }
};

ArenaAllocator::ArenaAllocator() : pImpl(new Impl()) {}
ArenaAllocator::~ArenaAllocator() = default;
ArenaAllocator::ArenaAllocator(ArenaAllocator&&) noexcept = default;
ArenaAllocator& ArenaAllocator::operator=(ArenaAllocator&&) noexcept = default;

void* ArenaAllocator::Allocate(size_t size) {
    if (size == 0) return nullptr;

    std::lock_guard<std::mutex> lock(pImpl->mutex);

    // Try to allocate from existing blocks
    for (auto& block : pImpl->blocks) {
        void* ptr = pImpl->AllocateFromBlock(block, size);
        if (ptr) return ptr;
    }

    // Need a new block
    ArenaBlock newBlock = pImpl->AllocateNewBlock(size);
    if (!newBlock.memory) return nullptr;

    void* ptr = pImpl->AllocateFromBlock(newBlock, size);
    pImpl->blocks.push_back(std::move(newBlock));
    return ptr;
}

void ArenaAllocator::Reset() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    for (auto& block : pImpl->blocks) {
        block.used = 0;
    }
}

void ArenaAllocator::Release() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    for (auto& block : pImpl->blocks) {
        if (block.memory) {
            std::free(block.memory);
        }
    }
    pImpl->blocks.clear();
}

size_t ArenaAllocator::GetTotalAllocated() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    size_t total = 0;
    for (const auto& block : pImpl->blocks) {
        total += block.used;
    }
    return total;
}

size_t ArenaAllocator::GetTotalReserved() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    size_t total = 0;
    for (const auto& block : pImpl->blocks) {
        total += block.size;
    }
    return total;
}

}} // namespace RawrXD::Core
