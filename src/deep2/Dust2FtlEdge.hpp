#pragma once
/* DUST2_FTL — observer only. DUST2 owns nothing. SOURCE_DROP owns manifestation.
 * Measures INTENT|SCHED_PROP_AHEAD_OF_DATA. PHYSICS_2C=0 DEPENDENCY_BYPASS=0.
 * Does not authorize consumption. Evidence = emit only. ≤95 lines. */
#include "StreamPathTiming.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace Deep2 {
namespace dust2 {

inline bool Armed() noexcept {
    const char* e = std::getenv("DUST2_FTL");
    if (e && e[0] == '0') return false;
    return true; /* default ON — observer emit only */
}

inline std::atomic<uint64_t>& IntentNs() noexcept {
    static std::atomic<uint64_t> v{0};
    return v;
}
inline std::atomic<uint64_t>& MaterializeNs() noexcept {
    static std::atomic<uint64_t> v{0};
    return v;
}
inline std::atomic<uint64_t>& SchedFtlHits() noexcept {
    static std::atomic<uint64_t> v{0};
    return v;
}
inline std::atomic<uint64_t>& IntentFtlHits() noexcept {
    static std::atomic<uint64_t> v{0};
    return v;
}

inline void Emit(FILE* f) noexcept {
    if (!f) f = stderr;
    if (!Armed()) {
        std::fprintf(f, "DUST2_FTL=0\n");
        return;
    }
    const uint64_t i = IntentNs().load(std::memory_order_acquire);
    const uint64_t m = MaterializeNs().load(std::memory_order_acquire);
    const uint64_t sf = SchedFtlHits().load(std::memory_order_relaxed);
    const uint64_t ift = IntentFtlHits().load(std::memory_order_relaxed);
    const uint64_t lead = (m > i && i) ? (m - i) : 0ull;
    const char* cls = (sf || ift) ? "DUST2_FTL_MANIFESTED" : "DUST2_FTL_UNOBSERVED";
    std::fprintf(f,
        "EDGE=DUST2_FTL\n"
        "OBSERVER_ONLY=1\n"
        "CLAIM=INTENT|SCHED_PROP_AHEAD_OF_DATA\n"
        "PHYSICS_2C=0\n"
        "PHYSICS_CLAIM=0\n"
        "VIOLATE_DEPENDENCIES=0\n"
        "DEPENDENCY_BYPASS=0\n"
        "AUTHORIZE_CONSUMPTION=0\n"
        "DUST2_OWNS_NOTHING=1\n"
        "SOURCE_DROP_OWNS_MANIFESTATION=1\n"
        "OWNER=dust2::NoteSchedFtl|NoteIntent|NoteMaterialize\n"
        "SCHED_FTL_HITS=%llu INTENT_FTL_HITS=%llu\n"
        "INTENT_NS=%llu MATERIALIZE_NS=%llu INTENT_LEAD_US=%llu\n"
        "CLAIM_INHERITANCE=0\n"
        "CLASS=%s\n",
        (unsigned long long)sf, (unsigned long long)ift,
        (unsigned long long)i, (unsigned long long)m,
        (unsigned long long)lead, cls);
}

inline void EmitOnce(FILE* f) noexcept {
    static std::atomic<int> once{0};
    if (once.exchange(1) == 0) Emit(f);
}

inline void NoteSchedFtl(bool tpsReady, bool progressed) noexcept {
    if (!Armed() || tpsReady || !progressed) return;
    const uint64_t n = SchedFtlHits().fetch_add(1, std::memory_order_relaxed);
    if (n == 0) Emit(stderr);
}

inline void NoteIntent(uint64_t issueNs) noexcept {
    if (!Armed()) return;
    IntentNs().store(issueNs, std::memory_order_release);
}

inline void NoteMaterialize(uint64_t completeNs) noexcept {
    if (!Armed()) return;
    MaterializeNs().store(completeNs, std::memory_order_release);
    const uint64_t i = IntentNs().load(std::memory_order_acquire);
    if (i && completeNs > i)
        IntentFtlHits().fetch_add(1, std::memory_order_relaxed);
    EmitOnce(stderr);
}

} // namespace dust2
} // namespace Deep2
