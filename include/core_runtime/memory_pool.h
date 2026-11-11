// =============================================================================
// RawrXD-CoreRuntime Public API: Memory Pool
// =============================================================================

#ifndef RAWRXD_CORE_MEMORY_POOL_H
#define RAWRXD_CORE_MEMORY_POOL_H

#include "core_export.h"
#include <memory>
#include <cstddef>
#include <cstdint>

namespace RawrXD {
namespace Core {

class RAWRXD_CORE_EXPORT MemoryPool {
public:
    MemoryPool();
    ~MemoryPool();

    // Non-copyable
    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;

    // Movable
    MemoryPool(MemoryPool&&) noexcept;
    MemoryPool& operator=(MemoryPool&&) noexcept;

    // Initialize with capacity
    bool Initialize(size_t capacity);

    // Allocate memory
    void* Allocate(size_t size);

    // Free memory
    void Free(void* ptr, size_t size);

    // Get current allocation
    size_t GetAllocated() const;

    // Get total capacity
    size_t GetCapacity() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Core
} // namespace RawrXD

#endif // RAWRXD_CORE_MEMORY_POOL_H
