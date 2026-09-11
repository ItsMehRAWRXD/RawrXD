#pragma once
/* PagedKvController — map/lookup + fixed physical pool core. LIVE=0. ≤99.
   GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 ELASTIC_RESIDENCY_REQUIRED=0 */
#include "PagedKvTypes.hpp"
#include "ScoreboardInvariants.hpp"

namespace Deep2 {
namespace scoreboard {

template <uint32_t PhysicalPages = kKvPhysicalPagesDefault,
          uint32_t VirtualMapEntries = kKvVirtualMapDefault>
struct PagedKvController {
    KvPhysicalPage physical[PhysicalPages]{};
    KvVirtualPage virtualMap[VirtualMapEntries]{};
    uint32_t mapped = 0;

    PagedKvController() noexcept {
        for (uint32_t i = 0; i < PhysicalPages; ++i)
            physical[i].id = i;
    }

    KvVirtualPage* lookup(uint64_t logical) noexcept {
        for (uint32_t i = 0; i < mapped; ++i)
            if (virtualMap[i].valid && virtualMap[i].logicalPage == logical)
                return &virtualMap[i];
        return nullptr;
    }

    KvVirtualPage* map(uint64_t logical, uint64_t backingOffset,
                       uint32_t token) noexcept {
        if (KvVirtualPage* e = lookup(logical)) {
            e->lastUseToken = token;
            return e;
        }
        if (mapped >= VirtualMapEntries)
            return nullptr;
        KvVirtualPage& v = virtualMap[mapped++];
        v.logicalPage = logical;
        v.backingOff = backingOffset;
        v.lastUseToken = token;
        v.valid = 1;
        v.tier = KvTier::Backing;
        v.physicalPage = kKvInvalidPage;
        return &v;
    }

    uint32_t findFree() const noexcept {
        for (uint32_t i = 0; i < PhysicalPages; ++i)
            if (!physical[i].busy)
                return i;
        return kKvInvalidPage;
    }

    uint32_t selectVictim(uint32_t now) const noexcept {
        uint32_t best = kKvInvalidPage, oldest = 0;
        for (uint32_t i = 0; i < PhysicalPages; ++i) {
            if (!physical[i].busy)
                return i;
            const uint32_t age = now - physical[i].lastUseToken;
            if (best == kKvInvalidPage || age > oldest) {
                oldest = age;
                best = i;
            }
        }
        return best;
    }

    void evict(uint32_t slot) noexcept {
        KvPhysicalPage& p = physical[slot];
        if (p.owner != ~0ull) {
            if (KvVirtualPage* v = lookup(p.owner)) {
                v->physicalPage = kKvInvalidPage;
                v->tier = KvTier::Backing;
            }
        }
        p.owner = ~0ull;
        p.busy = 0;
    }

    constexpr uint64_t physicalCapacityBytes(uint64_t pageBytes) const noexcept {
        return uint64_t(PhysicalPages) * pageBytes;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
