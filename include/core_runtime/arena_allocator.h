#ifndef RAWRXD_CORE_ARENA_ALLOCATOR_H
#define RAWRXD_CORE_ARENA_ALLOCATOR_H
#include "core_export.h"
#include <memory>
#include <cstddef>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT ArenaAllocator {
public:
    ArenaAllocator();
    ~ArenaAllocator();
    ArenaAllocator(const ArenaAllocator&) = delete;
    ArenaAllocator& operator=(const ArenaAllocator&) = delete;
    ArenaAllocator(ArenaAllocator&&) noexcept;
    ArenaAllocator& operator=(ArenaAllocator&&) noexcept;
    void* Allocate(size_t size);
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_ARENA_ALLOCATOR_H
