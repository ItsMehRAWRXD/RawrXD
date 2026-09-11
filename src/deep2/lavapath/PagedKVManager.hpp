#pragma once
/* PagedKVManager — bounded page pool + virtual block map tip.
   GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 P4. LIVE=0. ≤99. */
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

enum class KvLoc : uint8_t { Vram = 0, Host = 1 };

struct KvPage {
    uint32_t id = 0;
    KvLoc loc = KvLoc::Vram;
    void* ptr = nullptr;
    uint32_t free = 1;
    uint64_t seq = 0;
    uint32_t vblock = 0;
    uint64_t tick = 0;
};

struct PagedKVManager {
    static constexpr uint32_t kVram = 64, kHost = 128, kMap = 2048;
    uint64_t pageBytes = 0, clock = 0;
    KvPage vram[kVram]{}, host[kHost]{};
    uint32_t freeV[kVram]{}, freeH[kHost]{}, nFreeV = 0, nFreeH = 0;
    uint64_t mapKey[kMap]{};
    uint32_t mapPage[kMap]{};

    int init(uint64_t bytesPerPage) {
        pageBytes = bytesPerPage ? bytesPerPage : (1ull << 16);
        nFreeV = kVram;
        nFreeH = kHost;
        for (uint32_t i = 0; i < kVram; ++i) {
            vram[i] = KvPage{i, KvLoc::Vram, nullptr, 1, 0, 0, 0};
            freeV[i] = i;
        }
        for (uint32_t i = 0; i < kHost; ++i) {
            host[i] = KvPage{i, KvLoc::Host, nullptr, 1, 0, 0, 0};
            freeH[i] = i;
        }
        for (uint32_t i = 0; i < kMap; ++i) {
            mapKey[i] = ~0ull;
            mapPage[i] = 0xffffffffu;
        }
        return 1;
    }

    static uint32_t hash(uint64_t k) {
        return (uint32_t)((k * 0x9e3779b97f4a7c15ull) >> 32) % kMap;
    }

    int upsert(uint64_t key, uint32_t page) {
        uint32_t i = hash(key);
        for (uint32_t n = 0; n < kMap; ++n, i = (i + 1u) % kMap) {
            if (mapKey[i] == ~0ull || mapKey[i] == key) {
                mapKey[i] = key;
                mapPage[i] = page;
                return 1;
            }
        }
        return 0;
    }

    int lookup(uint64_t key, uint32_t& pageOut) const {
        uint32_t i = hash(key);
        for (uint32_t n = 0; n < kMap; ++n, i = (i + 1u) % kMap) {
            if (mapKey[i] == ~0ull)
                return 0;
            if (mapKey[i] == key) {
                pageOut = mapPage[i];
                return 1;
            }
        }
        return 0;
    }

    int mapBlock(uint64_t seq, uint32_t vb, uint32_t& pageOut) {
        const uint64_t key = (seq << 32) | vb;
        if (lookup(key, pageOut)) {
            if (pageOut < kVram)
                vram[pageOut].tick = ++clock;
            return 1;
        }
        if (!nFreeV)
            return 0;
        const uint32_t p = freeV[--nFreeV];
        vram[p].free = 0;
        vram[p].seq = seq;
        vram[p].vblock = vb;
        vram[p].tick = ++clock;
        if (!upsert(key, p))
            return 0;
        pageOut = p;
        return 1;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
