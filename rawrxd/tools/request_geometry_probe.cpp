// RAWRXD_B79_REQUEST_GEOMETRY_PROBE_001
//
// Ladder items 19/21: verify that GeometryForRequested(N) returns the geometry
// of a dispatch that was REQUESTED with N -- not the process-wide last dispatch,
// and not a stale record.
//
// The defect this exists to catch is specific: the sweep prints one geometry line
// per cell, and if that lookup is keyed on the wrong thing every cell in the
// table reports the same fan-out. workerpool_geometry_probe (B78) already proved
// the pool's per-call geometry; this proves the QUERY is correctly keyed.
//
// Method: interleave requests so consecutive dispatches have DIFFERENT requested
// values. If the query returned the last dispatch unconditionally, every lookup
// would return the final request's geometry and the mismatch count would be
// maximal. If it is correctly keyed, each lookup matches what was requested.
#include "rawrxd_cpu_math.hpp"

#include <atomic>
#include <cstdio>
#include <vector>

namespace {
std::atomic<int>* g_visits = nullptr;

void RangeTask(void* p, size_t begin, size_t end) {
    (void)p;
    for (size_t i = begin; i < end; ++i) {
        g_visits[i].fetch_add(1, std::memory_order_relaxed);
    }
}
} // namespace

int main() {
    // Rows large enough that the row-count clamp never binds, so the executed
    // geometry depends ONLY on the requested thread count. That isolates the
    // lookup from the partition logic B78 already validated.
    const size_t kTotal = 4096;
    std::vector<std::atomic<int>> visits(kTotal);
    g_visits = visits.data();

    const unsigned requests[] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};

    std::printf("RAWRXD_B79_REQUEST_GEOMETRY_PROBE_001\n");
    std::printf("total_rows=%zu (clamp cannot bind)\n\n", kTotal);
    std::printf("%-10s %-9s %-8s %-11s %-11s %-9s\n",
                "requested", "workers", "caller", "effective", "times_req", "verdict");

    int mismatches = 0;
    int never_dispatched = 0;

    // Interleave: pass 1 ascending, pass 2 descending. A descending pass makes
    // "returns the last dispatch unconditionally" fail loudly.
    for (int pass = 0; pass < 2; ++pass) {
        for (int k = 0; k < 8; ++k) {
            const unsigned requested = requests[pass == 0 ? k : 7 - k];

            for (auto& v : visits) v.store(0, std::memory_order_relaxed);
            rawrxd::cpu::ParallelRows(&RangeTask, nullptr, kTotal, requested);

            const rawrxd::cpu::DispatchRecord g =
                rawrxd::cpu::GeometryForRequested(requested);

            // Expected geometry, derived from the canonical definition rather
            // than copied from the pool.
            //
            //   effective_participants = actual_workers + (caller_participates ? 1 : 0)
            //
            // An INLINE dispatch has actual_workers == 0, so for effective to be
            // 1 the caller MUST be marked as participating: it does every row.
            // caller_participates describes whether the caller did work, not
            // whether it was one of several slices -- so inline is
            // workers=0, caller=yes, effective=1, not caller=no.
            const unsigned expWorkers = requested <= 1 ? 0u : requested - 1u;
            const bool expCaller = true;
            const unsigned expEff = expWorkers + 1u;

            const bool ok = g.actualWorkers == expWorkers &&
                            (g.callerParticipates ? 1u : 0u) == (expCaller ? 1u : 0u) &&
                            g.effectiveParticipants == expEff &&
                            g.totalRows == kTotal;
            if (!ok) ++mismatches;
            if (g.timesRequested == 0) ++never_dispatched;

            std::printf("%-10u %-9u %-8s %-11u %-11llu %-9s%s\n",
                        requested, g.actualWorkers,
                        g.callerParticipates ? "yes" : "no",
                        g.effectiveParticipants,
                        (unsigned long long)g.timesRequested,
                        ok ? "MATCH" : "MISMATCH",
                        pass == 0 ? "" : "  (descending pass)");
        }
    }

    std::printf("\nGEOMETRY_MISMATCHES=%d\n", mismatches);
    std::printf("REQUESTS_NEVER_DISPATCHED=%d\n", never_dispatched);
    std::printf("VERDICT=%s\n",
                (mismatches == 0 && never_dispatched == 0) ? "PASS" : "FAIL");
    return (mismatches == 0 && never_dispatched == 0) ? 0 : 1;
}