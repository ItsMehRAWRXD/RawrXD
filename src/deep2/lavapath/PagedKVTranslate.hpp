#pragma once
/* PagedKVTranslate — token→physical offset + LRU reclaim tip. ≤99. */
#include "PagedKVManager.hpp"

namespace Deep2 {
namespace scoreboard {

constexpr uint32_t kKvBlockTokens = 16;

struct PagedKVGeo {
    uint32_t heads = 0;
    uint32_t headDim = 0;
    uint32_t elemBytes = 2;
};

inline uint64_t KvPageBytes(const PagedKVGeo& g) {
    return 2ull * kKvBlockTokens * g.heads * g.headDim * g.elemBytes;
}

/* Returns 1 and sets byteOff into page pool linear space; 0 on miss. */
inline int translateKv(PagedKVManager& kv, const PagedKVGeo& g, uint64_t seq,
                       uint32_t token, uint32_t head, int isValue,
                       uint64_t& byteOff) {
    if (!g.heads || !g.headDim || head >= g.heads)
        return 0;
    const uint32_t vb = token / kKvBlockTokens;
    const uint32_t tokIn = token % kKvBlockTokens;
    uint32_t page = 0;
    if (!kv.mapBlock(seq, vb, page) || page >= PagedKVManager::kVram)
        return 0;
    const uint64_t pageBytes = KvPageBytes(g);
    const uint64_t kvStride =
        (uint64_t)kKvBlockTokens * g.heads * g.headDim * g.elemBytes;
    const uint64_t tokStride = (uint64_t)g.heads * g.headDim * g.elemBytes;
    const uint64_t headStride = (uint64_t)g.headDim * g.elemBytes;
    const uint64_t base = isValue ? kvStride : 0;
    byteOff = (uint64_t)page * pageBytes + base + tokIn * tokStride +
              head * headStride;
    return 1;
}

/* Evict oldest VRAM page to free stack; returns page id or 0xffffffff. */
inline uint32_t evictLruVram(PagedKVManager& kv) {
    uint32_t victim = 0xffffffffu;
    uint64_t oldest = ~0ull;
    for (uint32_t i = 0; i < PagedKVManager::kVram; ++i) {
        if (kv.vram[i].free)
            continue;
        if (kv.vram[i].tick < oldest) {
            oldest = kv.vram[i].tick;
            victim = i;
        }
    }
    if (victim == 0xffffffffu)
        return victim;
    kv.vram[victim].free = 1;
    kv.vram[victim].seq = 0;
    kv.vram[victim].vblock = 0;
    kv.freeV[kv.nFreeV++] = victim;
    return victim;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
