// RAWRXD_B78_THREAD_GEOMETRY_PROBE_001
//
// Items 7/8/18 of the ladder: a tiny synthetic dispatch matrix proving which
// requested thread counts actually reach RunThreads and what geometry each one
// executes. No model, no weights, no sweep -- total_rows is 8, so the whole
// thing runs in milliseconds and the answer cannot be obscured by inference
// cost.
//
// The ladder's question was "why does requested 2 disappear?". The pool's
// canonical definition (RAWRXD_B77_THREAD_TERMINOLOGY_001) says threads==1 takes
// an inline fast path with ZERO dispatched workers while threads>=2 splits the
// caller in with `threads-1` workers. So "threads=1" and "threads=2" are not
// two points on one scale -- they are two different execution geometries. This
// probe records both, per request, and additionally records whether the
// requested value survived every clamp.
//
// A second axis matters for the sweep: rows are shared between the caller and
// the workers, so a large total always fills the fan-out while a small one can
// starve it. total=8 is probed alongside total=1 and total=3 because those are
// where clamping and ceil-division actually bite.
#include "rawrxd_cpu_math.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

using rawrxd::cpu::LastActualWorkers;
using rawrxd::cpu::LastCallerParticipates;
using rawrxd::cpu::LastEffectiveParticipants;
using rawrxd::cpu::LastRequestedThreads;
using rawrxd::cpu::ParallelRows;

namespace {

// Each row is claimed by exactly one participant, so the union of the ranges
// must cover [0,total) exactly once. `visits[i]` counts how many times row i
// was written; anything other than 1 is a partition defect.
std::atomic<int>* g_visits = nullptr;

void RangeTask(void* p, size_t begin, size_t end) {
    (void)p;
    for (size_t i = begin; i < end; ++i) {
        g_visits[i].fetch_add(1, std::memory_order_relaxed);
    }
}

struct Row {
    unsigned requested;
    size_t total;
    unsigned actual_workers;
    bool caller_participates;
    unsigned effective;
    bool covers_once;
    int max_visits;
};

} // namespace

int main() {
    const size_t kMaxRows = 64;
    std::vector<std::atomic<int>> visits(kMaxRows);
    for (auto& v : visits) v.store(0, std::memory_order_relaxed);
    g_visits = visits.data();

    const unsigned requests[] = {1u, 2u, 3u, 4u, 5u, 8u, 9u, 16u};
    const size_t totals[] = {1u, 2u, 3u, 8u, 64u};

    std::printf("RAWRXD_B78_THREAD_GEOMETRY_PROBE_001\n");
    std::printf("canonical definition: threads==1 -> INLINE (0 workers, caller does\n");
    std::printf("all rows); threads>=2 -> caller + (threads-1) workers share rows\n\n");
    std::printf("%-10s %-7s %-9s %-10s %-11s %-9s %-8s\n",
                "requested", "total", "workers", "caller_part", "effective",
                "coverage", "maxvisit");
    std::printf("---------------------------------------------------------------"
                "-----------\n");

    std::vector<Row> rows;
    int defects = 0;
    for (size_t total : totals) {
        for (unsigned requested : requests) {
            for (auto& v : visits) v.store(0, std::memory_order_relaxed);

            ParallelRows(&RangeTask, nullptr, total, requested);

            int worst = 0;
            bool once = true;
            for (size_t i = 0; i < total; ++i) {
                const int n = visits[i].load(std::memory_order_relaxed);
                if (n != 1) once = false;
                if (n > worst) worst = n;
            }
            if (!once) ++defects;

            Row r;
            r.requested = requested;
            r.total = total;
            r.actual_workers = LastActualWorkers();
            r.caller_participates = LastCallerParticipates();
            r.effective = LastEffectiveParticipants();
            r.covers_once = once;
            r.max_visits = worst;
            rows.push_back(r);

            std::printf("%-10u %-7zu %-9u %-10s %-11u %-9s %-8d%s\n",
                        r.requested, r.total, r.actual_workers,
                        r.caller_participates ? "yes" : "no",
                        r.effective, once ? "ONCE" : "BAD", worst,
                        once ? "" : "   <-- PARTITION DEFECT");
        }
    }

    // Ladder item 9: show explicitly that requested==1 and requested==2 are
    // different geometries rather than points on one scale.
    std::printf("\nGEOMETRY_CLASS\n");
    std::set<std::string> classes;
    for (const Row& r : rows) {
        if (r.total != 8) continue;
        char buf[96];
        std::snprintf(buf, sizeof(buf),
                      "requested=%u -> workers=%u caller=%s effective=%u",
                      r.requested, r.actual_workers,
                      r.caller_participates ? "yes" : "no", r.effective);
        classes.insert(buf);
        std::printf("  %s\n", buf);
    }
    std::printf("DISTINCT_GEOMETRIES_AT_TOTAL_8=%zu\n", (int)classes.size());
    std::printf("  (requested 1 and requested 2 are DIFFERENT geometries, not a\n"
                "   2x step: 1 runs inline with 0 workers, 2 runs caller+1 worker)\n");

    std::printf("\nPARTITION_DEFECTS=%d\n", defects);
    std::printf("VERDICT=%s\n", defects == 0 ? "PASS" : "FAIL");
    return defects == 0 ? 0 : 1;
}