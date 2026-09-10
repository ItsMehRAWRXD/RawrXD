#pragma once
/* FTL execution → SOURCE_DROP edge: intent before data.
 * PHYSICS_2C=0 DUST2_OWNERSHIP=0 — observer only; not SOURCE_DROP_WORK.
 * ≤80 lines. */
#include "StreamPathTiming.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {
namespace ftl {

inline constexpr int PHYSICS_2C = 0;
inline constexpr int DUST2_OWNERSHIP = 0;

struct PropEdge {
    std::atomic<uint64_t> intentNs{0};
    std::atomic<uint64_t> dataNs{0};
    std::atomic<uint64_t> intentAhead{0};
    std::atomic<uint64_t> emits{0};
};

inline PropEdge& QbAttnProp() noexcept {
    static PropEdge e;
    return e;
}

inline void NoteIntent(PropEdge& e) noexcept {
    e.intentNs.store(StreamPathTiming_NowUs(), std::memory_order_release);
}

inline void NoteData(PropEdge& e) noexcept {
    const uint64_t d = StreamPathTiming_NowUs();
    e.dataNs.store(d, std::memory_order_release);
    const uint64_t i = e.intentNs.load(std::memory_order_acquire);
    if (i && d >= i) e.intentAhead.fetch_add(1, std::memory_order_relaxed);
    e.emits.fetch_add(1, std::memory_order_relaxed);
}

inline void Emit(FILE* f, const char* edgeId = "Q_B->ATTENTION") noexcept {
    if (!f) f = stderr;
    auto& e = QbAttnProp();
    const uint64_t i = e.intentNs.load();
    const uint64_t d = e.dataNs.load();
    std::fprintf(f,
                 "FTL_PROPAGATION_EDGE=%s\n"
                 "INTENT_NS=%llu\nDATA_NS=%llu\n"
                 "INTENT_AHEAD_OF_DATA=%d\n"
                 "LAG_US=%llu\nPROP_EMITS=%llu\n"
                 "PHYSICS_2C=0\nDUST2_OWNERSHIP=0\n"
                 "CLAIM=INTENT|SCHED_PROP_AHEAD_OF_DATA\nCLAIM_INHERITANCE=0\n",
                 edgeId, (unsigned long long)i, (unsigned long long)d,
                 (i && d >= i) ? 1 : 0,
                 (unsigned long long)((d > i) ? (d - i) : 0ull),
                 (unsigned long long)e.emits.load());
}

} // namespace ftl
} // namespace Deep2
