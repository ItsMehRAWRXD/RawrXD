// rawrxd_linestrip_cache.h - Line strip cache for Win32IDE presentation
// Stub header for build compatibility

#pragma once

#ifndef RAWRXD_LINESTRIP_CACHE_H
#define RAWRXD_LINESTRIP_CACHE_H

#include <cstdint>

namespace RawrXD {
namespace LineStrip {

// Stub structures for build compatibility
struct LineStripCacheEntry {
    uint32_t line_id;
    uint32_t strip_offset;
    uint32_t strip_length;
};

struct LineStripCache {
    LineStripCacheEntry* entries;
    uint32_t count;
    uint32_t capacity;
};

// Stub functions
inline void InitLineStripCache(LineStripCache* cache) {
    cache->entries = nullptr;
    cache->count = 0;
    cache->capacity = 0;
}

inline void FreeLineStripCache(LineStripCache* cache) {
    // No-op stub
}

} // namespace LineStrip
} // namespace RawrXD

#endif // RAWRXD_LINESTRIP_CACHE_H