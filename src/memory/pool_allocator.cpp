// Stub implementation for pool_allocator.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/pool_allocator.h"
namespace RawrXD { namespace Core {
class PoolAllocator::Impl {};
PoolAllocator::PoolAllocator() : pImpl(new Impl()) {}
PoolAllocator::~PoolAllocator() = default;
PoolAllocator::PoolAllocator(PoolAllocator&&) noexcept = default;
PoolAllocator& PoolAllocator::operator=(PoolAllocator&&) noexcept = default;
void* PoolAllocator::Allocate() { return nullptr; }
}} // namespace RawrXD::Core
