#pragma once
/* DepStamp — each edge owns readiness; no inheritance.
 * POLICY/OWNER/PROMOTE/HOT = NOT_A_SCHEDULER_BLOCK
 * DATA_DEPENDENCY = REQUIRED (FORCE_REVERSE only in audit canary)
 * ≤70 lines — execution evidence, not words. */
#include "Dust2FtlEdge.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct DepStamp {
    std::atomic<uint64_t> issued{0};
    std::atomic<uint64_t> complete{0};
};

inline bool DepValid(const DepStamp& d) noexcept {
    const uint64_t i = d.issued.load(std::memory_order_acquire);
    const uint64_t c = d.complete.load(std::memory_order_acquire);
    return c >= i && i > 0;
}

inline uint64_t DepIssue(DepStamp& d) noexcept {
    return d.issued.fetch_add(1, std::memory_order_acq_rel) + 1;
}

inline void DepComplete(DepStamp& d, uint64_t issue) noexcept {
    uint64_t cur = d.complete.load(std::memory_order_relaxed);
    while (issue > cur &&
           !d.complete.compare_exchange_weak(cur, issue,
                                             std::memory_order_release,
                                             std::memory_order_relaxed)) {
    }
}

inline void DepEmitViolation(FILE* f, const char* edge, uint64_t issued,
                             uint64_t complete) noexcept {
    if (!f) f = stderr;
    std::fprintf(f,
                 "EDGE=%s\nPRODUCER_ISSUE=%llu\nPRODUCER_COMPLETE=%llu\n"
                 "CORRUPTION_DEP=%d\nCLAIM_INHERITANCE=0\n",
                 edge ? edge : "?",
                 (unsigned long long)issued, (unsigned long long)complete,
                 (complete < issued) ? 1 : 0);
}

/* Q_B → ATTENTION — process-local stamp; no inheritance from other edges. */
inline DepStamp& QbDep() noexcept {
    static DepStamp s;
    return s;
}

inline uint64_t QbDepIssue() noexcept {
    const uint64_t n = DepIssue(QbDep());
    dust2::NoteIntent(StreamPathTiming_NowUs());
    return n;
}

inline void QbDepComplete() noexcept {
    DepComplete(QbDep(), QbDep().issued.load(std::memory_order_acquire));
    dust2::NoteMaterialize(StreamPathTiming_NowUs());
}

} // namespace Deep2
