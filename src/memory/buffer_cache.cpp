// Real implementation for buffer_cache.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/buffer_cache.h"

#include <cstdlib>
#include <cstring>
#include <vector>
#include <mutex>
#include <algorithm>

namespace RawrXD { namespace Core {

struct CachedBuffer {
    void* memory = nullptr;
    size_t size = 0;
    bool inUse = false;
};

class BufferCache::Impl {
public:
    std::vector<CachedBuffer> buffers;
    std::mutex mutex;
    size_t maxCacheSize = 16;  // Max cached buffers
    size_t totalCachedBytes = 0;
};

BufferCache::BufferCache() : pImpl(new Impl()) {}
BufferCache::~BufferCache() = default;
BufferCache::BufferCache(BufferCache&&) noexcept = default;
BufferCache& BufferCache::operator=(BufferCache&&) noexcept = default;

void* BufferCache::GetBuffer(size_t size) {
    if (size == 0) return nullptr;

    std::lock_guard<std::mutex> lock(pImpl->mutex);

    // Try to find a free buffer of sufficient size
    for (auto& buf : pImpl->buffers) {
        if (!buf.inUse && buf.size >= size) {
            buf.inUse = true;
            return buf.memory;
        }
    }

    // Allocate new buffer
    void* ptr = std::aligned_alloc(64, size);
    if (!ptr) return nullptr;

    CachedBuffer buf;
    buf.memory = ptr;
    buf.size = size;
    buf.inUse = true;
    pImpl->buffers.push_back(buf);
    pImpl->totalCachedBytes += size;

    // Trim cache if too large
    if (pImpl->buffers.size() > pImpl->maxCacheSize) {
        TrimCache();
    }

    return ptr;
}

void BufferCache::ReleaseBuffer(void* buffer) {
    if (!buffer) return;

    std::lock_guard<std::mutex> lock(pImpl->mutex);

    for (auto& buf : pImpl->buffers) {
        if (buf.memory == buffer) {
            buf.inUse = false;
            return;
        }
    }

    // Not in cache — free directly
    std::free(buffer);
}

void BufferCache::TrimCache() {
    // Remove oldest unused buffers
    auto it = pImpl->buffers.begin();
    while (it != pImpl->buffers.end() && pImpl->buffers.size() > pImpl->maxCacheSize) {
        if (!it->inUse) {
            std::free(it->memory);
            pImpl->totalCachedBytes -= it->size;
            it = pImpl->buffers.erase(it);
        } else {
            ++it;
        }
    }
}

void BufferCache::Clear() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    for (auto& buf : pImpl->buffers) {
        if (buf.memory) {
            std::free(buf.memory);
        }
    }
    pImpl->buffers.clear();
    pImpl->totalCachedBytes = 0;
}

size_t BufferCache::GetCachedBytes() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return pImpl->totalCachedBytes;
}

}} // namespace RawrXD::Core
