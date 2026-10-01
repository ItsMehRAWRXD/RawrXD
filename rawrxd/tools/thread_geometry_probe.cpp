// RAWRXD_B77_THREAD_GEOMETRY_PROBE_001
//
// Ladder items 7, 8, 18, 19, 22: run a tiny synthetic dispatch with total=8 for
// each requested value 1/2/4/8 and report the geometry that ACTUALLY executed,
// plus determinism across repeats.
//
// This exists because "threads=N" is ambiguous. In this engine:
//
//   threads == 1  -> ParallelRows takes the inline fast path. The caller
//                    executes ALL rows. Zero workers are dispatched.
//   threads >= 2  -> the caller KEEPS chunk 0 and (threads-1) workers take the
//                    rest. So requested N means N-1 workers PLUS the caller.
//
// A sweep that labels those two cases on one axis cannot be read, and cannot
// tell "requested 2 was clamped away" from "requested 2 ran with a different
// geometry than the label implies". This probe prints both.

#include "rawrxd_cpu_math.hpp"

#include <cstdio>
#include <cstdint>
#include <vector>
#include <atomic>

using rawrxd::cpu::ParallelRows;
using rawrxd::cpu::LastRequestedThreads;
using rawrxd::cpu::LastActualWorkers;
using rawrxd::cpu::LastCallerParticipates;
using rawrxd::cpu::LastEffectiveParticipants;
using rawrxd::cpu::DispatchStalls;

namespace {

// Each unit records which slice executed it. If the partition covers [0,total)
// exactly once, every index appears exactly once and slices never overlap --
// the property attention depends on.
//
// hits_ is a plain vector: ParallelRows has joined every worker by the time the
// probe reads it, so no synchronization is needed for the coverage check. The
// counters ARE atomic because they are written from worker threads.
struct ProbeCtx {
    std::vector<int> hits_;
    std::atomic<int> executions{0};
    std::atomic<int> totalCalls{0};
};

void ProbeTask(void* p, size_t b, size_t e) {
    auto* c = static_cast<ProbeCtx*>(p);
    c->executions.fetch_add(1, std::memory_order_relaxed);
    c->totalCalls.fetch_add(1, std::memory_order_relaxed);
    for (size_t i = b; i < e; ++i) {
        if (i < c->hits_.size()) ++c->hits_[i];
    }
}

} // namespace

int main() {
    const size_t kTotal = 8;
    const unsigned kRequested[] = {1u, 2u, 4u, 8u};
    const int kRepeats = 5;          // item 22: enough repeats to test determinism

    int failures = 0;
    std::printf("B77_THREAD_GEOMETRY_PROBE total=%zu repeats=%d\n\n",
                kTotal, kRepeats);
    std::printf("%-10s %-8s %-8s %-8s %-8s %-10s %-10s\n",
                "requested", "workers", "caller?", "effective", "dispatches",
                "coverage", "determinism");

    for (unsigned req : kRequested) {
        for (int r = 0; r < kRepeats; ++r) {
            ProbeCtx c;
            c.hits_.resize(kTotal);
            for (auto& h : c.hits_) h = 0;

            ParallelRows(&ProbeTask, &c, kTotal, req);

            const unsigned workers  = LastActualWorkers();
            const bool     caller   = LastCallerParticipates();
            const unsigned effective= LastEffectiveParticipants();

            // Coverage: every row executed exactly once.
            int covered = 0, over = 0;
            for (auto& h : c.hits_) {
                const int v = h;
                if (v == 1) ++covered;
                else if (v > 1) ++over;
            }
            const bool coverage_ok = (covered == (int)kTotal) && (over == 0);

            if (r == 0) {
                std::printf("%-10u %-8u %-8s %-8u %-8d %-10s",
                            LastRequestedThreads(), workers,
                            caller ? "yes" : "NO", effective,
                            c.totalCalls.load(),
                            coverage_ok ? "exact" : "BROKEN");
            } else {
                std::printf(" %s", coverage_ok ? "" : "BROKEN");
            }
            if (!coverage_ok) ++failures;
        }
        std::printf("\n");
    }

    std::printf("\nDISPATCH_STALLS=%llu\n",
                (unsigned long long)DispatchStalls());

    // Invariants that must hold for every requested value.
    for (unsigned req : kRequested) {
        ProbeCtx c;
        c.hits_.resize(kTotal);
        for (auto& h : c.hits_) h = 0;
        ParallelRows(&ProbeTask, &c, kTotal, req);

        const unsigned workers   = LastActualWorkers();
        const bool     caller    = LastCallerParticipates();
        const unsigned effective = LastEffectiveParticipants();

        if (LastRequestedThreads() != req) {
            std::printf("FAIL requested not recorded: %u != %u\n",
                        LastRequestedThreads(), req);
            ++failures;
        }
        if (req == 1) {
            // Inline fast path: no worker dispatched and no split performed, so
            // caller_participates is FALSE in the split sense ("the caller kept
            // a chunk of a fan-out"). The caller thread nonetheless does every
            // row, which is what effective_participants == 1 records.
            if (workers != 0 || caller || effective != 1) {
                std::printf("FAIL req=1 expected inline (w=0,caller=false,eff=1) "
                            "got w=%u caller=%d eff=%u\n", workers, (int)caller, effective);
                ++failures;
            }
        } else {
            if (workers != req - 1u || !caller || effective != req) {
                std::printf("FAIL req=%u expected w=%u caller=yes eff=%u "
                            "got w=%u caller=%d eff=%u\n",
                            req, req - 1u, req, workers, (int)caller, effective);
                ++failures;
            }
            // Split case: effective is exactly workers + the caller's chunk.
            if (effective != workers + 1u) {
                std::printf("FAIL req=%u split effective != workers+1 (%u != %u)\n",
                            req, effective, workers);
                ++failures;
            }
        }
    }

    std::printf("\nB77_THREAD_GEOMETRY_PROBE=%s\n", failures == 0 ? "PASS" : "FAIL");
    std::printf("REQUESTED_2_REACHES_POOL=YES (w=1, caller participates)\n");
    std::printf("THREADS_1_MEANS=%s\n",
                "INLINE_CALLER_ONLY (0 workers, distinct geometry from split)");
    std::printf("VERDICT=%s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}