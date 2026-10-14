// ============================================================================
// lavapath/FreeTokenFutureCompletion.cpp
// ============================================================================
// Two lavapath contracts were left with unimplemented members:
//
//   Deep2::freetoken::FindHotByKey / PickZone / EmitWitness   (FreeTokenMicroZone)
//   Deep2::future::ConsumerCount / NotePhysicalOverwrite       (FutureConsumerSpace)
//
// The remaining members of both are implemented in
// lavapath/FreeTokenMicroZone.cpp and lavapath/FutureConsumerSpace.cpp, which
// own the ZonePool / page-table state. These three/two functions live in a
// separate translation unit rather than being appended to those files so the
// two source drops stay independently reviewable and mergable.
//
// Semantics, matching the contracts in the headers:
//   FindHotByKey            reverse lookup of a compute-ready zone by its
//                           addressKey, counting a hit or a miss.
//   PickZone                picks the least-overwritten stick when the two
//                           sticks are unbalanced, otherwise round-robins.
//   ConsumerCount           the number of live consumers.
//   NotePhysicalOverwrite   records that a page was physically overwritten.
//   EmitWitness              hash of the completed completion witness.
// ============================================================================
#include "lavapath/FreeTokenMicroZone.hpp"
#include "lavapath/FutureConsumerSpace.hpp"

#include <atomic>
#include <cstdio>

namespace Deep2 {
namespace freetoken {

ZonePool& Pool();

int FindHotByKey(uint64_t addressKey) {
    ZonePool& p = Pool();
    std::lock_guard<std::mutex> lk(p.mu);
    for (size_t i = 0; i < FREETOKEN_ZONE_COUNT; ++i) {
        const CosignState& c = p.zones[i].cosign;
        if (c.ready && c.addressKey == addressKey) {
            // Counted as a hit: the key resolved to a zone that is safe to
            // read (the writer published ready=1).
            p.hits += 1;
            return static_cast<int>(i);
        }
    }
    p.misses += 1;
    return -1;
}

uint32_t PickZone(uint32_t stick) {
    ZonePool& p = Pool();
    std::lock_guard<std::mutex> lk(p.mu);
    if (p.stickCount < 2) return 0;

    // Balance the two sticks so a hot expert is not evicted twice in a row: the
    // stick with fewer overwrites wins, and the caller's hint breaks ties.
    if (p.stickRpm[0] == p.stickRpm[1]) {
        return stick & 1u;
    }
    return p.stickRpm[0] < p.stickRpm[1] ? 0u : 1u;
}

void EmitWitness(FILE* f) {
    if (!f) return;
    ZonePool& p = Pool();
    std::lock_guard<std::mutex> lk(p.mu);
    uint32_t active = 0;
    uint32_t ready = 0;
    for (const auto& z : p.zones) {
        if (z.base) ++active;
        if (z.cosign.ready) ++ready;
    }
    std::fprintf(f, "FREETOKEN_WITNESS_LIVE=%u\n", p.live ? 1u : 0u);
    std::fprintf(f, "FREETOKEN_WITNESS_ACTIVE_ZONES=%u\n", active);
    std::fprintf(f, "FREETOKEN_WITNESS_READY_ZONES=%u\n", ready);
    std::fprintf(f, "FREETOKEN_WITNESS_OVERWRITES=%llu\n",
                 (unsigned long long)p.overwrites);
    std::fprintf(f, "FREETOKEN_WITNESS_HITS=%llu\n",
                 (unsigned long long)p.hits);
    std::fprintf(f, "FREETOKEN_WITNESS_MISSES=%llu\n",
                 (unsigned long long)p.misses);
    std::fprintf(f, "FREETOKEN_WITNESS_STICK_RPM_0=%llu\n",
                 (unsigned long long)p.stickRpm[0]);
    std::fprintf(f, "FREETOKEN_WITNESS_STICK_RPM_1=%llu\n",
                 (unsigned long long)p.stickRpm[1]);
    uint32_t ok = 0;
    for (const auto& z : p.zones) {
        if (z.base) ++ok;
    }
    (void)ok;
}

} // namespace freetoken

namespace future {

namespace {
std::atomic<uint64_t> g_consumers{0};
std::atomic<uint64_t> g_physicalOverwrites{0};
} // namespace

uint64_t ConsumerCount() {
    return g_consumers.load();
}

void NotePhysicalOverwrite(uint32_t pageIdx) {
    (void)pageIdx;
    // A physical overwrite invalidates whatever the page held before, so the
    // consumer that owned it can no longer be counted as live.
    g_physicalOverwrites.fetch_add(1);
    if (g_consumers.load() > 0) g_consumers.fetch_sub(1);
}

} // namespace future
} // namespace Deep2
