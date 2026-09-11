#pragma once
/* PagedKvAcquire — physical pin/release on PagedKvController. LIVE=0. ≤99. */
#include "PagedKvController.hpp"

namespace Deep2 {
namespace scoreboard {

template <uint32_t P, uint32_t V>
inline uint32_t KvAcquirePhysical(PagedKvController<P, V>& kv, uint64_t logical,
                                  uint32_t token) noexcept {
    if (!kKvPagePoolFixed)
        return kKvInvalidPage;
    KvVirtualPage* v = kv.lookup(logical);
    if (!v)
        return kKvInvalidPage;
    if (v->physicalPage != kKvInvalidPage) {
        kv.physical[v->physicalPage].lastUseToken = token;
        return v->physicalPage;
    }
    uint32_t slot = kv.findFree();
    if (slot == kKvInvalidPage)
        slot = kv.selectVictim(token);
    if (slot == kKvInvalidPage)
        return kKvInvalidPage;
    kv.evict(slot);
    kv.physical[slot].owner = logical;
    kv.physical[slot].busy = 1;
    kv.physical[slot].lastUseToken = token;
    v->physicalPage = slot;
    v->lastUseToken = token;
    v->tier = KvTier::Ram;
    return slot;
}

template <uint32_t P, uint32_t V>
inline void KvMarkGpuResident(PagedKvController<P, V>& kv,
                              uint64_t logical) noexcept {
    if (KvVirtualPage* v = kv.lookup(logical))
        v->tier = KvTier::LocalGpu;
}

template <uint32_t P, uint32_t V>
inline void KvRelease(PagedKvController<P, V>& kv, uint64_t logical) noexcept {
    KvVirtualPage* v = kv.lookup(logical);
    if (!v || v->physicalPage == kKvInvalidPage)
        return;
    kv.physical[v->physicalPage].busy = 0;
    v->physicalPage = kKvInvalidPage;
    v->tier = KvTier::Backing;
}

using ProductKv = PagedKvController<>;

} /* namespace scoreboard */
} /* namespace Deep2 */
