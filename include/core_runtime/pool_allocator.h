#ifndef RAWRXD_CORE_POOL_ALLOCATOR_H
#define RAWRXD_CORE_POOL_ALLOCATOR_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT PoolAllocator {
public:
    PoolAllocator();
    ~PoolAllocator();
    PoolAllocator(const PoolAllocator&) = delete;
    PoolAllocator& operator=(const PoolAllocator&) = delete;
    PoolAllocator(PoolAllocator&&) noexcept;
    PoolAllocator& operator=(PoolAllocator&&) noexcept;
    void* Allocate();
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_POOL_ALLOCATOR_H
