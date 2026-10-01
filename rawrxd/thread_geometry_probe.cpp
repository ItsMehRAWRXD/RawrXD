// thread_geometry_probe.cpp
// RAWRXD_THREAD_GEOMETRY_PROBE_001
//
// Answers the question the sweep output could not: for a requested thread
// count, what geometry ACTUALLY executes?
//
// The sweep's "threads=N" label went through three transformations before any
// thread ran, and the report showed only the first one:
//
//   requested_threads     what the caller passed
//     -> threads<=1 ?      inline fast path, ZERO workers, caller does all rows
//     -> use = threads-1   the caller keeps a slice, so N threads => N-1 workers
//     -> use = min(use, total_rows-1)   and then a clamp for small row counts
//
// A single "threads" integer therefore cannot answer "did my 2 threads run?",
// and "requested 2 disappears" was unresolvable from sweep output alone. This
// probe dispatches a known, tiny row count and prints every field, so the
// mapping from request to execution is observed rather than inferred.
//
// It is deliberately tiny (total=8) because a small total exercises the clamp
// that a large total hides: at total=1376 every request has work to spare.

#include "rawrxd_cpu_math.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace rawrxd;

namespace {
// Counts which thread executed which row, so a correct partition is verifiable
// and not merely plausible. Every row must be visited exactly once.
struct Probe {
    std::vector<int> visits;   // visits[row] = number of times row was executed
    std::vector<int> owner;    // owner[row]  = thread ordinal that ran it
    std::atomic<int> next{0};
};
static std::atomic<int> g_threadOrdinal{0};

void ProbeRows(void* p, size_t begin, size_t end) {
    Probe* pr = static_cast<Probe*>(p);
    const int me = g_threadOrdinal.fetch_add(1, std::memory_order_relaxed) + 1;
    for (size_t i = begin; i < end; ++i) {
        pr->visits[i]++;
        pr->owner[i] = me;
    }
}
} // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);

    // RAWRXD_B77_THREAD_TERMINOLOGY_001: the canonical vocabulary. These are the
    // field names the probe prints, chosen so that none of them can be read as
    // another.
    std::printf("%-8s %-10s %-9s %-9s %-10s %-8s %-8s %-7s %-6s %s\n",
                "total", "requested", "reqWorker", "actWorker", "callerPart",
                "effective", "inlined", "chunk", "seq", "verdict");
    std::printf("-------- ---------- --------- ---------- ---------- "
                "-------- -------- ------- ------ -------\n");

    int failures = 0;
    for (size_t total : {8u, 2u, 3u, 16u, 1376u}) {
        for (unsigned requested : {1u, 2u, 3u, 4u, 8u, 16u}) {
            Probe pr;
            pr.visits.assign(total, 0);
            pr.owner.assign(total, 0);
            g_threadOrdinal.store(0, std::memory_order_relaxed);

            const size_t seqBefore = cpu::DispatchCount();
            cpu::ParallelRows(&ProbeRows, &pr, total, requested);
            const size_t seqAfter = cpu::DispatchCount();

            // Observed distinct threads that actually touched a row. This is a
            // MEASUREMENT of participation, independent of what the pool
            // recorded, so the two can be compared instead of trusted.
            std::vector<int> distinct;
            for (int o : pr.owner) {
                if (o == 0) continue;
                bool seen = false;
                for (int d : distinct) if (d == o) { seen = true; break; }
                if (!seen) distinct.push_back(o);
            }
            const unsigned observed = (unsigned)distinct.size();

            // Correctness: every row exactly once.
            bool allOnce = true;
            for (int v : pr.visits) if (v != 1) allOnce = false;

            const unsigned reqW = requested >= 1 ? requested - 1u : 0u;
            const unsigned effRec = cpu::LastEffectiveParticipants();
            const unsigned actRec = cpu::LastActualWorkers();
            const unsigned reqRec = cpu::LastRequestedThreads();

            // The claim being tested: the recorded geometry must match what the
            // request implies for THIS row count.
            unsigned expectWorkers;
            unsigned expectEff;
            if (requested <= 1) { expectWorkers = 0; expectEff = 1; }
            else {
                expectWorkers = reqW;
                if (expectWorkers > total - 1) expectWorkers = (unsigned)(total - 1);
                expectEff = expectWorkers + 1u;
            }
            const bool geoOk = (reqRec == requested) && (actRec == expectWorkers) &&
                               (effRec == expectEff);
            // observed participants must be <= effective and >= 1
            const bool obsOk = observed >= 1 && observed <= effRec;

            const bool ok = allOnce && geoOk && obsOk;
            if (!ok) ++failures;

            std::printf("%-8zu %-10u %-9u %-9u %-10s %-8u %-8s %-7zu %-6zu %s\n",
                        total, reqRec, reqW, actRec,
                        cpu::LastCallerParticipates() ? "yes" : "no",
                        effRec,
                        requested <= 1 ? "yes" : "no",
                        cpu::LastChunk(), seqAfter - seqBefore,
                        ok ? "OK" : "MISMATCH");
            if (!ok) {
                std::printf("    allOnce=%d expectedWorkers=%u expectedEff=%u "
                            "observedThreads=%u\n",
                            allOnce ? 1 : 0, expectWorkers, expectEff, observed);
            }
        }
    }

    std::printf("\nROW_ONCE_AND_GEOMETRY_MATCH=%s FAILURES=%d\n",
                failures == 0 ? "PASS" : "FAIL", failures);
    std::printf("VERDICT=%s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
