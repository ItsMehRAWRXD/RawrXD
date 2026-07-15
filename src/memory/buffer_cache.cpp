// Stub implementation for buffer_cache.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/buffer_cache.h"
namespace RawrXD { namespace Core {
class BufferCache::Impl {};
BufferCache::BufferCache() : pImpl(new Impl()) {}
BufferCache::~BufferCache() = default;
BufferCache::BufferCache(BufferCache&&) noexcept = default;
BufferCache& BufferCache::operator=(BufferCache&&) noexcept = default;
void* BufferCache::GetBuffer(size_t) { return nullptr; }
}} // namespace RawrXD::Core
