/* FreeTokenMicroZone.cpp — VirtualAlloc zones; N-way sticks; WAW overwrite. */
#include "FreeTokenMicroZone.hpp"
#include "FutureConsumerSpace.hpp"
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace freetoken {

ZonePool& Pool() {
    static ZonePool p;
    return p;
}

static void* ZoneAlloc(size_t n) {
#ifdef _WIN32
    /* Sector/page aligned for optional DirectIO into same addresses. */
    return VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    return std::malloc(n);
#endif
}

static void ZoneFree(void* p) {
#ifdef _WIN32
    if (p) VirtualFree(p, 0, MEM_RELEASE);
#else
    std::free(p);
#endif
}

bool Init(size_t zoneBytes, uint32_t sticks) {
    ZonePool& p = Pool();
    std::lock_guard<std::mutex> lock(p.mu);
    if (p.live) return true;
    p.zoneBytes = zoneBytes ? zoneBytes : FREETOKEN_ZONE_BYTES;
    /* Default 4-way: dual GPU × (compute|help) — eats >2-way freak. */
    if (!sticks) sticks = 4;
    if (sticks > 4) sticks = 4;
    p.stickCount = sticks;
    for (int i = 0; i < FREETOKEN_ZONE_COUNT; ++i) {
        MicroZone& z = p.zones[i];
        z.capacity = p.zoneBytes;
        z.base = static_cast<uint8_t*>(ZoneAlloc(z.capacity));
        if (!z.base) {
            for (int j = 0; j < i; ++j) {
                ZoneFree(p.zones[j].base);
                p.zones[j].base = nullptr;
            }
            return false;
        }
        std::memset(z.base, 0, z.capacity);
        z.cosign = {};
        z.cosign.stick = static_cast<uint8_t>(i % p.stickCount);
    }
    p.live = true;
    p.allocsAfterInit = 0;
    p.stickRpm[0] = p.stickRpm[1] = 0;
    return true;
}

void Shutdown() {
    ZonePool& p = Pool();
    std::lock_guard<std::mutex> lock(p.mu);
    if (!p.live) return;
    for (int i = 0; i < FREETOKEN_ZONE_COUNT; ++i) {
        ZoneFree(p.zones[i].base);
        p.zones[i].base = nullptr;
        p.zones[i].cosign = {};
    }
    p.live = false;
}

uint8_t* Overwrite(uint32_t zoneIdx, const void* src, size_t n,
                   uint64_t fileOffset, uint32_t layer, uint32_t expert) {
    ZonePool& p = Pool();
    if (!p.live || zoneIdx >= FREETOKEN_ZONE_COUNT || !src || !n)
        return nullptr;
    MicroZone& z = p.zones[zoneIdx];
    if (n > z.capacity) n = z.capacity;
    std::lock_guard<std::mutex> lock(p.mu);
    z.cosign.ready = 0;
    std::memcpy(z.base, src, n);
    z.cosign.generation++;
    z.cosign.fileOffset = fileOffset;
    z.cosign.addressKey = fileOffset ? OffsetKey(fileOffset)
                                     : ExpertIdKey(layer, expert);
    z.cosign.layer = layer;
    z.cosign.expert = expert;
    z.cosign.byteLen = static_cast<uint32_t>(n);
    z.cosign.stick = static_cast<uint8_t>(zoneIdx % p.stickCount);
    z.cosign.ready = 1;
    p.overwrites++;
    p.stickRpm[z.cosign.stick & 1u]++;
    /* PAST → FUTURE before bytes are considered retired→rebinding. */
    if (future::ConsumerCount() > 0) {
        future::AdvanceOwnership(zoneIdx, 0);
        future::NotePhysicalOverwrite(zoneIdx);
    }
    return z.base;
}

} // namespace freetoken
} // namespace Deep2
