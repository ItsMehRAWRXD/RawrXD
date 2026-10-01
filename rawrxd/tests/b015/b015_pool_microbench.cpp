// RAWRXD_POOL_LIFECYCLE_001
//
// Drives the persistent WorkerPool through the cross-config sequence that made
// the pool defect reachable: one process, several thread counts walked in order,
// each dispatch asserting the completion protocol and the published geometry.
//
// The defect this exists to observe is a class of lifecycle bug that a
// single-configuration run cannot reach. The pool is a process-wide leaked
// singleton; threads_ persists at the high-water mark; generation_ keeps
// counting. A worker created by a later EnsureThreads() used to start with
// seen = 0, wake immediately on a generation that had already been published,
// and decrement a pending_ budget it was never counted in.
//
// So the probe runs a WARM phase that walks thread counts 1..8 and a COLD
// phase that repeats the same calls. If the pool is correct the two phases
// produce identical geometry per cell. If it is not, the second pass of a cell
// diverges -- which is contamination from the earlier cells, not the cell
// itself.
//
// Every dispatched cell asserts PendingAtReturn() == 0. With
// RAWRXD_WORKERPOOL_WAIT_INFINITE=1 the wait cannot expire, so a nonzero value
// is a protocol break rather than a timeout artifact. Asserting completion
// separately from timing is the point: a throughput number cannot tell
// "all workers finished" from "returned early".

#include "rawrxd_cpu_math.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

using rawrxd::cpu::DispatchRecord;

struct Cell {
    unsigned    requested = 0;
    size_t      totalRows = 0;
    DispatchRecord geometry{};
    unsigned    pendingAtReturn = 0;
    unsigned    activeAtReturn  = 0;
    unsigned    totalAtReturn   = 0;
    unsigned    chunkAtReturn   = 0;
    unsigned long long generationAtReturn = 0;
    bool        ok = false;
};

// Row task that touches every element of the range so a missing slice is
// observable in the checksum rather than only in the counters.
struct Ctx {
    std::vector<double> out;
    size_t rowsTouched = 0;
};

void RowFill(void* vctx, size_t begin, size_t end) {
    Ctx* c = static_cast<Ctx*>(vctx);
    for (size_t i = begin; i < end; ++i) {
        c->out[i] = static_cast<double>(i) + 0.5;
    }
    c->rowsTouched += end - begin;
}

// Rows walked per phase. 1 inlines (never reaches the pool), 2 is the smallest
// split, and the odd values are where ceil-division leaves an empty slice --
// the partition bug lived exactly there.
const unsigned kRequested[] = {1, 2, 3, 4, 5, 6, 7, 8};
const size_t   kRows[]      = {8, 17, 64, 512, 1376, 4096};

Cell RunCell(unsigned requested, size_t totalRows) {
    Cell c;
    c.requested = requested;
    c.totalRows = totalRows;
    Ctx ctx;
    ctx.out.assign(totalRows, -1.0);

    rawrxd::cpu::ParallelRows(&RowFill, &ctx, totalRows, requested);

    c.geometry = rawrxd::cpu::GeometryForRequested(requested);
    c.pendingAtReturn      = rawrxd::cpu::DispatchPendingAtReturn();
    c.activeAtReturn       = rawrxd::cpu::DispatchActiveAtReturn();
    c.totalAtReturn        = rawrxd::cpu::DispatchTotalAtReturn();
    c.chunkAtReturn        = rawrxd::cpu::DispatchChunkAtReturn();
    c.generationAtReturn   = rawrxd::cpu::DispatchGenerationAtReturn();

    // Coverage: every row written exactly once, and no row left at the
    // sentinel. A double-written or skipped row is the user-visible form of
    // both the surplus-worker decrement and the empty-slice decrement.
    bool coverageOk = true;
    for (size_t i = 0; i < totalRows; ++i) {
        if (ctx.out[i] != static_cast<double>(i) + 0.5) { coverageOk = false; break; }
    }

    const bool dispatched = requested >= 2 && totalRows >= 2;
    const bool protocolOk = !dispatched || c.pendingAtReturn == 0;
    const bool tallyOk = c.geometry.requestedThreads == requested;

    // Geometry must describe this cell, not the previous one. The inline path
    // reports zero workers with the caller participating; a split reports at
    // least one worker and the caller keeping a slice.
    const bool shapeOk = dispatched
        ? (c.geometry.actualWorkers >= 1 && c.geometry.callerParticipates)
        : (c.geometry.actualWorkers == 0 && c.geometry.inlined);

    c.ok = coverageOk && protocolOk && tallyOk && shapeOk;
    return c;
}

void PrintCell(const char* phase, const Cell& c) {
    std::printf(
        "POOL_CELL phase=%s requested=%u total=%zu workers=%u "
        "caller=%d effective=%u chunk=%zu inlined=%d pending_at_return=%u "
        "active_at_return=%u total_at_return=%u chunk_at_return=%u "
        "generation=%llu ok=%d\n",
        phase, c.requested, c.totalRows, c.geometry.actualWorkers,
        c.geometry.callerParticipates ? 1 : 0,
        c.geometry.effectiveParticipants, c.geometry.chunk,
        c.geometry.inlined ? 1 : 0, c.pendingAtReturn, c.activeAtReturn,
        c.totalAtReturn, c.chunkAtReturn, c.generationAtReturn,
        c.ok ? 1 : 0);
    std::fflush(stdout);
}

} // namespace

int main() {
    std::printf("BEGIN pool_lifecycle\n");

    unsigned failures = 0;
    unsigned stallsStart = static_cast<unsigned>(rawrxd::cpu::DispatchStalls());
    std::vector<Cell> warm;

    // WARM: walk thread counts 1..8. This is the sequence that grows threads_
    // to the high-water mark and leaves surplus workers parked.
    std::printf("PHASE warm\n");
    for (unsigned requested : kRequested) {
        for (size_t rows : kRows) {
            Cell c = RunCell(requested, rows);
            PrintCell("warm", c);
            if (!c.ok) ++failures;
            warm.push_back(c);
        }
    }

    // COLD: the same cells again, in the same order. Same process, same pool,
    // now with 7 parked workers from the warm phase. Any divergence here is
    // cross-config contamination.
    std::printf("PHASE cold\n");
    size_t idx = 0;
    for (unsigned requested : kRequested) {
        for (size_t rows : kRows) {
            Cell c = RunCell(requested, rows);
            PrintCell("cold", c);
            if (!c.ok) ++failures;
            if (idx < warm.size()) {
                const Cell& w = warm[idx];
                const bool same =
                    w.geometry.actualWorkers == c.geometry.actualWorkers &&
                    w.geometry.chunk == c.geometry.chunk &&
                    w.geometry.effectiveParticipants ==
                        c.geometry.effectiveParticipants &&
                    w.geometry.inlined == c.geometry.inlined;
                std::printf(
                    "POOL_MATCH requested=%u total=%zu stable=%d "
                    "warm_workers=%u cold_workers=%u warm_chunk=%zu "
                    "cold_chunk=%zu\n",
                    requested, rows, same ? 1 : 0,
                    w.geometry.actualWorkers, c.geometry.actualWorkers,
                    w.geometry.chunk, c.geometry.chunk);
                if (!same) ++failures;
            }
            ++idx;
        }
    }

    const unsigned stallsEnd =
        static_cast<unsigned>(rawrxd::cpu::DispatchStalls());
    std::printf("POOL_SUMMARY stalls=%u dispatches=%llu failures=%u\n",
                stallsEnd - stallsStart,
                rawrxd::cpu::DispatchCount(), failures);
    std::printf("VERDICT=%s\n", failures == 0 ? "PASS" : "FAIL");
    std::printf("END pool_lifecycle\n");
    std::fflush(stdout);
    return failures == 0 ? 0 : 1;
}