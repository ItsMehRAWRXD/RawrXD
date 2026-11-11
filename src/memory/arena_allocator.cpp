// Stub implementation for arena_allocator.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/arena_allocator.h"
namespace RawrXD { namespace Core {
class ArenaAllocator::Impl {};
ArenaAllocator::ArenaAllocator() : pImpl(new Impl()) {}
ArenaAllocator::~ArenaAllocator() = default;
ArenaAllocator::ArenaAllocator(ArenaAllocator&&) noexcept = default;
ArenaAllocator& ArenaAllocator::operator=(ArenaAllocator&&) noexcept = default;
void* ArenaAllocator::Allocate(size_t) { return nullptr; }
}} // namespace RawrXD::Core
