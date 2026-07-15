// =============================================================================
// RawrXD-CoreRuntime: Memory Pool Implementation (Stub)
// =============================================================================

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/memory_pool.h"
#include <cstddef>
#include <cstdint>

namespace RawrXD {
namespace Core {

class MemoryPool::Impl {
public:
    size_t allocated = 0;
    size_t capacity = 0;
};

MemoryPool::MemoryPool() : pImpl(new Impl()) {}
MemoryPool::~MemoryPool() = default;
MemoryPool::MemoryPool(MemoryPool&&) noexcept = default;
MemoryPool& MemoryPool::operator=(MemoryPool&&) noexcept = default;

bool MemoryPool::Initialize(size_t capacity) {
    pImpl->capacity = capacity;
    return true;
}

void* MemoryPool::Allocate(size_t size) {
    if (pImpl->allocated + size > pImpl->capacity) {
        return nullptr;
    }
    pImpl->allocated += size;
    return new uint8_t[size];
}

void MemoryPool::Free(void* ptr, size_t size) {
    delete[] static_cast<uint8_t*>(ptr);
    pImpl->allocated -= size;
}

size_t MemoryPool::GetAllocated() const {
    return pImpl->allocated;
}

size_t MemoryPool::GetCapacity() const {
    return pImpl->capacity;
}

} // namespace Core
} // namespace RawrXD
