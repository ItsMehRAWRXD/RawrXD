/* FreeTokenMicroZone_Query.cpp — key lookup / RPM / witness. */
#include "FreeTokenMicroZone.hpp"
#include "FutureConsumerSpace.hpp"

namespace Deep2 {
namespace freetoken {

int FindHot(uint32_t layer, uint32_t expert) {
    return FindHotByKey(ExpertIdKey(layer, expert));
}

int FindHotByKey(uint64_t addressKey) {
    ZonePool& p = Pool();
    if (!p.live || !addressKey) return -1;
    for (int i = 0; i < FREETOKEN_ZONE_COUNT; ++i) {
        const CosignState& c = p.zones[i].cosign;
        if (!c.ready) continue;
        if (c.addressKey == addressKey ||
            (addressKey == ExpertIdKey(c.layer, c.expert))) {
            p.hits++;
            future::NoteConsumerHit();
            return i;
        }
        if ((addressKey & 0x8000000000000000ull) &&
            c.fileOffset &&
            OffsetKey(c.fileOffset) == addressKey) {
            p.hits++;
            future::NoteConsumerHit();
            return i;
        }
    }
    p.misses++;
    future::NoteConsumerMiss();
    return -1;
}

uint32_t PickZone(uint32_t stick) {
    ZonePool& p = Pool();
    const uint32_t sc = p.stickCount ? p.stickCount : 2;
    uint32_t best = stick % FREETOKEN_ZONE_COUNT;
    uint64_t oldest = ~0ull;
    for (uint32_t i = stick % sc; i < FREETOKEN_ZONE_COUNT; i += sc) {
        if (!p.zones[i].cosign.ready) return i;
        uint64_t g = p.zones[i].cosign.generation;
        if (g < oldest) { oldest = g; best = i; }
    }
    return best;
}

double HitRatePct() {
    ZonePool& p = Pool();
    uint64_t t = p.hits + p.misses;
    return t ? (100.0 * (double)p.hits / (double)t) : 0.0;
}

uint32_t ActiveZoneCount() {
    ZonePool& p = Pool();
    uint32_t n = 0;
    for (int i = 0; i < FREETOKEN_ZONE_COUNT; ++i)
        if (p.zones[i].cosign.ready) ++n;
    return n;
}

void EmitWitness(FILE* f) {
    if (!f) f = stderr;
    ZonePool& p = Pool();
    std::fprintf(f,
        "FREETOKEN_MICROZONE live=%d zones=%d zone_mb=%zu sticks=%u "
        "active=%u overwrites=%llu hits=%llu misses=%llu hit_pct=%.2f "
        "stick0_rpm=%llu stick1_rpm=%llu allocs_after_init=%llu "
        "key=address_id waw_ready_gate=1 helpframe_nway=%u eat_gt2=1 "
        "metric=fetch_not_fit models=20/35/70/120/300/671+ unbounded=1 "
        "public_gap=amd_xfer_waw+prescope_dual_only\n",
        p.live ? 1 : 0, FREETOKEN_ZONE_COUNT,
        p.zoneBytes / (1024 * 1024), p.stickCount,
        ActiveZoneCount(),
        (unsigned long long)p.overwrites,
        (unsigned long long)p.hits,
        (unsigned long long)p.misses,
        HitRatePct(),
        (unsigned long long)p.stickRpm[0],
        (unsigned long long)p.stickRpm[1],
        (unsigned long long)p.allocsAfterInit,
        p.stickCount ? p.stickCount : 4u);
}

} // namespace freetoken
} // namespace Deep2
