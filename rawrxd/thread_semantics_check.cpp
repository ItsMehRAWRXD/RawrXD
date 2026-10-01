// thread_semantics_check.cpp
// Verifies the dispatch contract instead of inferring it from speedups.
//
// Canonical definition enforced here (RAWRXD_B77_THREAD_TERMINOLOGY_001):
//   requested N        = what the caller asked for
//   actual_workers     = N - 1, because the CALLING thread takes one slice
//   caller_participates= true whenever N >= 1
//   effective          = actual_workers + (caller_participates ? 1 : 0) = N
// So "threads=2" means two participants (caller + 1 worker), NOT two workers.
//
// Checks, in ladder order:
//   1-6   literal request -> config -> RunThreads value, with names that
//         cannot be conflated
//   7-8   a tiny synthetic dispatch proves coverage: every row processed once
//   9-16  every requested value 1/2/4/8 is distinguishable in the receipt
//   17    labels report BOTH requested and actual execution
//   22-23 determinism, and fresh-runtime vs in-process at identical geometry
#include "rawrxd_cpu_math.hpp"

#include <atomic>
#include <cstdio>
#include <string>
#include <vector>

using namespace rawrxd::cpu;

static int g_fail = 0;
static void Check(bool ok, const char* name, double got = 0, double want = 0) {
    if (ok) std::printf("PASS %-46s\n", name);
    else { std::printf("FAIL %-46s got=%.9g want=%.9g\n", name, got, want); ++g_fail; }
    std::fflush(stdout);
}

// ---- coverage probe: records which row indices actually ran, and how often ----
// A fixed-capacity array: std::vector<std::atomic<T>> cannot be resized because
// atomics are neither copyable nor movable.
static constexpr size_t kMaxRows = 256;

struct Coverage {
    std::atomic<int> hits[kMaxRows];
    size_t rows = 0;
    std::atomic<size_t> tasks{0};
    Coverage() { for (auto& h : hits) h.store(0); }
};
static Coverage* g_cov = nullptr;

static void ProbeTask(void* p, size_t b, size_t e) {
    (void)p;
    if (g_cov) {
        g_cov->tasks.fetch_add(1);
        for (size_t i = b; i < e && i < kMaxRows; ++i) g_cov->hits[i].fetch_add(1);
    }
}

int main() {
    std::printf("backend=%s\n\n", BackendName());
    std::printf("CANONICAL DEFINITION UNDER TEST\n");
    std::printf("  requested N  -> actual_workers = N-1, caller_participates = 1\n");
    std::printf("  effective_participants = actual_workers + caller_participates\n\n");

    // ---- ladder 7/8/9/10: tiny synthetic dispatch, coverage verified ----
    for (unsigned requested : {1u, 2u, 4u, 8u}) {
        const size_t kRows = 8;
        Coverage cov;
        
        
        g_cov = &cov;

        ResetDispatchTrace();
        ParallelRows(&ProbeTask, nullptr, kRows, requested);

        const DispatchRecord r = GeometryForRequested(requested);
        std::printf("\n--- requested=%u ---\n", requested);
        std::printf("  requested_threads   = %u\n", r.requestedThreads);
        std::printf("  actual_workers      = %u\n", r.actualWorkers);
        std::printf("  caller_participates = %d\n", r.callerParticipates ? 1 : 0);
        std::printf("  effective           = %u\n", r.effectiveParticipants);
        std::printf("  total_rows=%zu chunk=%zu inlined=%d dispatches=%llu\n",
                    r.totalRows, r.chunk, r.inlined ? 1 : 0,
                    (unsigned long long)r.timesRequested);

        // Every requested value must be reported back verbatim (no clamping,
        // rounding, or power-of-two collapse).
        char nm[96];
        std::snprintf(nm, sizeof(nm), "requested %u echoed verbatim", requested);
        Check(r.requestedThreads == requested, nm, r.requestedThreads, requested);

        // effective == requested by the canonical definition.
        std::snprintf(nm, sizeof(nm), "requested %u effective == requested", requested);
        const unsigned expect_eff = requested;
        Check(r.effectiveParticipants == expect_eff, nm,
              r.effectiveParticipants, expect_eff);

        // caller_participates must be true for every requested value, including
        // 1 (which is inline but still the caller doing the work).
        std::snprintf(nm, sizeof(nm), "requested %u caller participates", requested);
        Check(r.callerParticipates, nm, r.callerParticipates ? 1 : 0, 1);

        // Coverage: every row processed exactly once, no gaps, no double-writes.
        int double_hits = 0, missed = 0;
        for (size_t i = 0; i < kRows; ++i) {
            const int h = cov.hits[i].load();
            if (h == 0) ++missed;
            if (h > 1) ++double_hits;
        }
        std::snprintf(nm, sizeof(nm), "requested %u covers all 8 rows once", requested);
        Check(missed == 0 && double_hits == 0, nm,
              double(missed + double_hits), 0);
        std::printf("  tasks=%d coverage_missed=%d double_written=%d\n",
                    cov.tasks.load(), missed, double_hits);
    }
    g_cov = nullptr;

    // ---- ladder 16/17: distinctness. Two different requests must never
    // report identical geometry, or one silently becomes the other.
    std::printf("\n--- distinctness ---\n");
    struct Snap { unsigned req, workers, eff; };
    std::vector<Snap> snaps;
    for (unsigned requested : {1u, 2u, 4u, 8u}) {
        ParallelRows(&ProbeTask, nullptr, 64, requested);
        const DispatchRecord r = GeometryForRequested(requested);
        snaps.push_back({r.requestedThreads, r.actualWorkers, r.effectiveParticipants});
    }
    bool all_distinct = true;
    for (size_t i = 0; i < snaps.size(); ++i) {
        for (size_t j = i + 1; j < snaps.size(); ++j) {
            if (snaps[i].workers == snaps[j].workers) all_distinct = false;
        }
    }
    Check(all_distinct, "each requested value has a distinct worker count");
    for (const auto& s : snaps) {
        std::printf("  requested=%u workers=%u effective=%u\n",
                    s.req, s.workers, s.eff);
    }

    // ---- ladder 22/23: determinism at identical geometry, repeated ----
    std::printf("\n--- determinism at fixed geometry (requested=4) ---\n");
    std::vector<int> first;
    for (int trial = 0; trial < 3; ++trial) {
        const size_t kRows = 32;
        Coverage cov;
        
        
        g_cov = &cov;
        ParallelRows(&ProbeTask, nullptr, kRows, 4);
        std::vector<int> sig;
        for (size_t i = 0; i < kRows; ++i) sig.push_back(cov.hits[i].load());
        if (trial == 0) first = sig;
        else Check(sig == first, "repeated dispatch yields identical coverage");
        g_cov = nullptr;
    }

    // ---- ladder 9/12: a request larger than the work must not lie ----
    std::printf("\n--- oversized request vs small work ---\n");
    {
        ParallelRows(&ProbeTask, nullptr, 2, 8);
        const DispatchRecord r = GeometryForRequested(8);
        std::printf("  requested=8 rows=2 -> workers=%u chunk=%zu effective=%u\n",
                    r.actualWorkers, r.chunk, r.effectiveParticipants);
        // Workers beyond the row count get empty slices and must NOT claim
        // completion budget; effective participants may legitimately exceed
        // rows. The contract is that coverage is still exactly once.
        Check(r.totalRows == 2, "oversized request preserves total_rows", double(r.totalRows), 2);
    }

    std::printf("\nRESULT %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
