#pragma once
/* FreeToken Micro-Zone — fixed overwrite slots; model size ≠ residency.
 * WAW-safe: ready=0 before memcpy, ready=1 after (AMD transfer-queue class). */
#include "FreeTokenAddressKey.hpp"
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <mutex>

#ifndef FREETOKEN_ZONE_COUNT
#define FREETOKEN_ZONE_COUNT 8
#endif
#ifndef FREETOKEN_ZONE_BYTES
#define FREETOKEN_ZONE_BYTES (64ull * 1024ull * 1024ull)
#endif

namespace Deep2 {
namespace freetoken {

struct CosignState {
    uint64_t generation = 0;
    uint64_t fileOffset = 0;
    uint64_t addressKey = 0; /* ExpertIdKey or OffsetKey */
    uint32_t layer = ~0u;
    uint32_t expert = ~0u;
    uint32_t byteLen = 0;
    uint8_t  ready = 0;  /* 0=writing (WAW lock), 1=compute-safe */
    uint8_t  stick = 0;
};

struct MicroZone {
    uint8_t*    base = nullptr;
    size_t      capacity = 0;
    CosignState cosign{};
};

struct ZonePool {
    MicroZone zones[FREETOKEN_ZONE_COUNT]{};
    size_t    zoneBytes = FREETOKEN_ZONE_BYTES;
    uint32_t  stickCount = 2;
    uint64_t  overwrites = 0;
    uint64_t  hits = 0;
    uint64_t  misses = 0;
    uint64_t  stickRpm[2]{}; /* overwrite counts per stick */
    uint64_t  allocsAfterInit = 0;
    bool      live = false;
    std::mutex mu;
};

ZonePool& Pool();
bool Init(size_t zoneBytes = FREETOKEN_ZONE_BYTES, uint32_t sticks = 2);
void Shutdown();
uint8_t* Overwrite(uint32_t zoneIdx, const void* src, size_t n,
                   uint64_t fileOffset, uint32_t layer, uint32_t expert);
int FindHot(uint32_t layer, uint32_t expert);
int FindHotByKey(uint64_t addressKey);
uint32_t PickZone(uint32_t stick);
double HitRatePct();
uint32_t ActiveZoneCount();
void EmitWitness(FILE* f);

} // namespace freetoken
} // namespace Deep2
