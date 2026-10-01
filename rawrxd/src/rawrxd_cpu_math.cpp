// rawrxd_cpu_math.cpp - AVX-512 / AVX2 / SSE2 inference kernels.
#include "rawrxd_cpu_math.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <immintrin.h>

#if defined(_WIN32)
#include <intrin.h>
#include <windows.h>
#endif

namespace rawrxd {
namespace cpu {

// ===========================================================================
// Capability detection
// ===========================================================================
namespace {

Caps DetectCaps() {
    Caps c;
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    c.logical_cpus = si.dwNumberOfProcessors;

    int r[4];
    __cpuid(r, 1);
    const int f1_ecx = r[2], f1_edx = r[3];
    c.sse2 = (f1_edx & (1 << 26)) != 0;
    c.fma  = (f1_ecx & (1 << 12)) != 0;
    c.avx  = (f1_ecx & (1 << 28)) != 0;
    c.f16c = (f1_ecx & (1 << 29)) != 0;

    __cpuidex(r, 7, 0);
    const int f7_ebx = r[1], f7_ecx = r[2];
    c.avx2        = (f7_ebx & (1 <<  5)) != 0;
    c.avx512f     = (f7_ebx & (1 << 16)) != 0;
    c.avx512dq    = (f7_ebx & (1 << 17)) != 0;
    c.avx512vl    = (f7_ebx & (1 << 31)) != 0;
    c.avx512bw    = (r[3]    & (1 << 30)) != 0;
    c.avx512vnni  = (f7_ecx  & (1 << 11)) != 0;
#else
    c.sse2 = true;
    c.logical_cpus = std::thread::hardware_concurrency();
#endif
    // OS support for the wide state is required even when the CPU reports it.
#if defined(_WIN32)
    if (c.avx512f && !c.avx512dq) { /* F alone is still usable */ }
    if (c.avx) {
        // XGETBV: bits 1 and 2 must be set for XMM+YMM state.
        unsigned long long xcr0 = _xgetbv(0);
        const bool os_ymm = (xcr0 & 0x6) == 0x6;
        const bool os_zmm = (xcr0 & 0xE6) == 0xE6;
        if (!os_ymm) { c.avx = false; c.avx2 = false; c.fma = false; c.avx512f = false; }
        if (!os_zmm) { c.avx512f = false; c.avx512dq = false;
                       c.avx512bw = false; c.avx512vl = false; c.avx512vnni = false; }
    }
#endif
    return c;
}

const Caps& CapsRef() {
    static const Caps c = DetectCaps();
    return c;
}

bool UseAvx512() {
    const Caps& c = CapsRef();
#if defined(__AVX512F__)
    return c.avx512f;
#else
    (void)c;
    return false;
#endif
}

bool UseAvx2() {
    const Caps& c = CapsRef();
#if defined(__AVX2__)
    return c.avx2 && !UseAvx512();
#else
    (void)c;
    return false;
#endif
}

// Threads to use for one matmul. Small problems are dominated by the barrier
// cost, so scale the count with the work actually available.
unsigned ThreadCountFor(size_t work_items) {
    const unsigned hw = CapsRef().logical_cpus;
    if (hw <= 1 || work_items < 2) return 1;
    unsigned t = static_cast<unsigned>(work_items);
    if (t > hw) t = hw;
    if (t > 16) t = 16;
    return t < 1 ? 1 : t;
}

// Threads only pay off when each thread gets enough rows to amortize the
// barrier. Below this, the fan-out costs more than the work.
constexpr size_t kMinRowsPerThread = 4;

unsigned MatMulThreadCount(size_t n) {
    // Threading is opt-out: measured on this Zen 4 host the pool cost more than
    // the work for decode-shaped matmuls, so the default is single-threaded.
    // Set RAWRXD_MATMUL_THREADS=N to force a thread count (0 or 1 = inline).
    static const int forced = [] {
#if defined(_MSC_VER)
        char* e = nullptr;
        size_t len = 0;
        if (_dupenv_s(&e, &len, "RAWRXD_MATMUL_THREADS") == 0 && e && len > 0) {
            const int v = std::atoi(e);
            std::free(e);
            return v;
        }
        std::free(e);
        return -1;
#else
        const char* e = std::getenv("RAWRXD_MATMUL_THREADS");
        return e ? std::atoi(e) : -1;
#endif
    }();
    if (forced >= 0) {
        if (forced <= 1) return 1;
        const unsigned cap = static_cast<unsigned>(forced);
        return ThreadCountFor(n < cap ? n : cap);
    }
    const size_t by_work = n / kMinRowsPerThread;
    if (by_work < 2) return 1;
    return 1;   // measured default: threading is a net loss at this granularity
}

} // namespace

const Caps& Detect() { return CapsRef(); }

const char* BackendName() {
    if (UseAvx512()) return "AVX-512F (+FMA)";
    if (UseAvx2())   return "AVX2+FMA";
    if (CapsRef().avx) return "AVX";
    return "scalar";
}

// ===========================================================================
// GEMM: y[i] = dot(W[i*k .. i*k+k-1], x[0..k))
//
// W is row-major with stride k. For each output row we walk k in 16-float
// lanes, accumulating a single ZMM/ymm register, then horizontally reduce.
// The horizontal reduce is the one real cost of this shape; it is why this is
// a dot-product formulation rather than the classic Nx16 accumulator tile.
// For large n the reduction amortizes and throughput approaches memory/ALU
// limits, which is the right trade for a GEMV-heavy decode workload.
// ===========================================================================
namespace {

#if defined(__AVX512F__)
inline float HorizontalSum(__m512 v) {
    return _mm512_reduce_add_ps(v);
}
// Compiled with /arch:AVX512; the dispatch guard on UseAvx512() keeps hosts
// without the extension from taking this path.
inline float DotRowAvx512(const float* __restrict w, const float* __restrict x, size_t k) {
    // Two independent accumulators so the 64-wide step does not serialize on a
    // single dependency chain; both are reduced at the end.
    __m512 acc0 = _mm512_setzero_ps();
    __m512 acc1 = _mm512_setzero_ps();
    size_t i = 0;
    for (; i + 32 <= k; i += 32) {
        acc0 = _mm512_fmadd_ps(_mm512_loadu_ps(w + i),      _mm512_loadu_ps(x + i),      acc0);
        acc1 = _mm512_fmadd_ps(_mm512_loadu_ps(w + i + 16), _mm512_loadu_ps(x + i + 16), acc1);
    }
    for (; i + 16 <= k; i += 16) {
        acc0 = _mm512_fmadd_ps(_mm512_loadu_ps(w + i), _mm512_loadu_ps(x + i), acc0);
    }
    if (i < k) {
        // Masked tail; k is a multiple of 16 for real models, so this is rare.
        const __mmask16 mask = static_cast<__mmask16>((1u << (k - i)) - 1u);
        acc0 = _mm512_fmadd_ps(_mm512_maskz_loadu_ps(mask, w + i),
                               _mm512_maskz_loadu_ps(mask, x + i), acc0);
    }
    return _mm512_reduce_add_ps(_mm512_add_ps(acc0, acc1));
}
#endif

#if defined(__AVX2__) && !defined(__AVX512F__)
inline float DotRowAvx2(const float* __restrict w, const float* __restrict x, size_t k) {
    __m256 acc = _mm256_setzero_ps();
    size_t i = 0;
    for (; i + 32 <= k; i += 32) {
        acc = _mm256_fmadd_ps(_mm256_loadu_ps(w + i),     _mm256_loadu_ps(x + i),     acc);
        acc = _mm256_fmadd_ps(_mm256_loadu_ps(w + i + 8),  _mm256_loadu_ps(x + i + 8),  acc);
        acc = _mm256_fmadd_ps(_mm256_loadu_ps(w + i + 16), _mm256_loadu_ps(x + i + 16), acc);
        acc = _mm256_fmadd_ps(_mm256_loadu_ps(w + i + 24), _mm256_loadu_ps(x + i + 24), acc);
    }
    for (; i + 8 <= k; i += 8) {
        acc = _mm256_fmadd_ps(_mm256_loadu_ps(w + i), _mm256_loadu_ps(x + i), acc);
    }
    __m128 lo = _mm256_castps256_ps128(acc);
    __m128 hi = _mm256_extractf128_ps(acc, 1);
    lo = _mm_add_ps(lo, hi);
    lo = _mm_hadd_ps(lo, lo);
    lo = _mm_hadd_ps(lo, lo);
    if (i < k) {
        float tail = 0.0f;
        for (size_t j = i; j < k; ++j) tail += w[j] * x[j];
        return _mm_cvtss_f32(lo) + tail;
    }
    return _mm_cvtss_f32(lo);
}
#endif

inline float DotRowScalar(const float* __restrict w, const float* __restrict x, size_t k) {
    // 4-way unroll; MSVC vectorizes this too, but the explicit form is stable
    // across compilers and avoids a dependency chain on the single accumulator.
    __m64 unused; (void)unused;
    float s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    size_t i = 0;
    for (; i + 4 <= k; i += 4) {
        s0 += w[i] * x[i];
        s1 += w[i + 1] * x[i + 1];
        s2 += w[i + 2] * x[i + 2];
        s3 += w[i + 3] * x[i + 3];
    }
    float s = s0 + s1 + s2 + s3;
    for (; i < k; ++i) s += w[i] * x[i];
    return s;
}

inline float DotRow(const float* w, const float* x, size_t k) {
#if defined(__AVX512F__)
    if (UseAvx512()) return DotRowAvx512(w, x, k);
#endif
#if defined(__AVX2__) && !defined(__AVX512F__)
    if (UseAvx2()) return DotRowAvx2(w, x, k);
#endif
    return DotRowScalar(w, x, k);
}

// ---------------------------------------------------------------------------
// Persistent worker pool.
//
// Matmul is called many thousands of times per token (every projection of every
// layer). Creating std::thread per call costs far more than the work it
// parallelizes -- measured at ~8x SLOWER than scalar single-threaded. So the
// workers are created once and parked on a condition variable.
// parallelizes -- measured at ~8x SLOWER than scalar single-threaded. So the
// workers are created once and parked on a condition variable.
//
// Cost is still not free (~10us per parallel call), so small matmuls stay on
// the calling thread; see MatMulThreadCount.
// ---------------------------------------------------------------------------
class WorkerPool {
public:
    static WorkerPool& Instance() {
        // Intentionally leaked. The pool owns threads that park on a condition
        // variable; destroying it at static-destruction time would race with
        // those threads and abort the process on exit.
        static WorkerPool* p = new WorkerPool();
        return *p;
    }

    void Run(void (*fn)(void*, size_t, size_t), void* ctx, size_t total_rows) {
        RunThreads(fn, ctx, total_rows, CapsRef().logical_cpus);
    }

    // Explicit thread count. `threads` is the TOTAL participating threads
    // (including the caller), so only threads-1 workers are dispatched.
    // RAWRXD_B76_WORKERPOOL_FAIL_CLOSED_001
    //
    // On a stall, Run() returns while dispatched workers may still be running
    // inside fn(ctx, ...). The caller's `ctx` is typically a stack object (the
    // AttnCtx in rawrxd_transformer.cpp), so those workers are writing into
    // memory the caller believes it has released. The next operation then
    // reuses or frees that storage underneath them.
    //
    // The 10s bound cannot simply be raised: a lost wakeup would then present as
    // the silent hang the bound was introduced to prevent. And returning early
    // is unsafe regardless of the threshold.
    //
    // Fix: FAIL CLOSED. A stall poisons the pool, and a poisoned pool runs
    // inline on the calling thread only. Inline execution cannot race with a
    // stale worker, so subsequent operations are correct even though they are
    // slower. The pool un-poisons when every outstanding worker from the
    // offending generation has retired, checked before the next dispatch.
    //
// This trades throughput for correctness after a stall, which is the correct
    // direction: a silently corrupted result is worse than a slow one.
    void RunThreads(void (*fn)(void*, size_t, size_t), void* ctx,
                    size_t total_rows, unsigned threads) {
        if (threads <= 1) {
            // RAWRXD_B77_THREAD_TERMINOLOGY_001: record the inline geometry
            // BEFORE returning. This path used to return without touching the
            // last_* fields, so a request for 1 thread left the PREVIOUS
            // dispatch's geometry on display -- a request for 1 could be
            // reported as 8, which is the same class of bug as a requested
            // configuration vanishing from a report.
            last_requested_threads_.store(threads, std::memory_order_release);
            last_actual_workers_.store(0, std::memory_order_release);
            last_caller_participates_.store(true, std::memory_order_release);
            last_effective_participants_.store(1, std::memory_order_release);
            last_total_rows_.store(total_rows, std::memory_order_relaxed);
            last_chunk_.store(total_rows, std::memory_order_relaxed);
            last_inlined_.store(true, std::memory_order_release);
            dispatches_.fetch_add(1, std::memory_order_relaxed);
            fn(ctx, 0, total_rows);
            return;
        }
        // RAWRXD_B76_WORKERPOOL_FAIL_CLOSED_001: un-poison only once the
        // offending generation has actually drained. If pending_ is still
        // non-zero a stale worker is still running and dispatching again is
        // exactly the unsafe case.
        if (poisoned_ &&
            pending_.load(std::memory_order_acquire) == 0) {
            poisoned_ = false;
            std::fprintf(stderr,
                "[WORKERPOOL] UNPOISONED: stalled generation retired; "
                "dispatch resumes\n");
            std::fflush(stderr);
        }
        if (poisoned_) {
            // Inline only: cannot race with a stale worker from the
            // generation that timed out.
            fn(ctx, 0, total_rows);
            return;
        }
        // RAWRXD_B77_THREAD_TERMINOLOGY_001
        // Canonical thread vocabulary, because the benchmark's "threads=N" label
        // conflates three different quantities and the sweep cannot be read
        // without them:
        //
        //   requested_threads    -- what the caller asked for
        //   actual_workers       -- threads-1 (the caller keeps a chunk)
        //   caller_participates  -- true when the caller kept a chunk (threads>=2)
        //   effective_participants= actual_workers + (caller_participates ? 1 : 0)
        //
        // NOTE the asymmetry: threads==1 takes the inline fast path ABOVE and
        // dispatches ZERO workers with the caller doing every row. So
        // effective_participants is 1 for threads=1 and threads for threads>=2.
        // Labelling the inline case "1 thread" and the split case "N threads"
        // hides that the two are structurally different execution geometries,
        // which is exactly the ambiguity that made "requested 2 disappeared"
        // unresolvable from sweep output alone.
        last_requested_threads_.store(threads, std::memory_order_release);
        last_actual_workers_.store(0, std::memory_order_release);
        last_caller_participates_.store(false, std::memory_order_release);
        last_effective_participants_.store(1, std::memory_order_release);

        // RAWRXD_WORKERPOOL_PARTITION_001
        // The row space is split into `use + 1` slices -- one for the caller,
        // one per dispatched worker -- and the completion budget is exactly the
        // number of dispatched workers.
        //
        // The previous shape derived `chunk_ = ceil(total_rows / use)` and gave
        // worker id the range [chunk_*(id+1), min(+chunk_, total_rows)). That
        // yields ceil(total_rows/chunk_) - 1 non-empty worker slices, which is
        // at most `use - 1`: the last slice is empty or partially consumed by
        // the ceiling. `pending_` was still set to `use`, so the budget could
        // never be met and every threads>=2 call waited out the 10s bound
        // (rs3.log: use=1 total=1376 chunk=1377). An earlier variant instead
        // charged empty slices to the budget, underflowing pending_ to
        // 0xFFFFFFFF and letting Run() return while workers still wrote into
        // the caller's buffer.
        //
        // Dividing by (use + 1) and clamping `use` to total_rows - 1 makes
        // every worker slice provably non-empty, so the budget and the work
        // agree by construction instead of by coincidence.
        unsigned use = threads - 1u;
        if (total_rows <= 1) { RecordGeometry(threads, 0, true, 1, total_rows, 0); fn(ctx, 0, total_rows); return; }
        if (use > total_rows - 1) use = static_cast<unsigned>(total_rows - 1);
        if (use == 0) { RecordGeometry(threads, 0, true, 1, total_rows, 0); fn(ctx, 0, total_rows); return; }
        // RAWRXD_B77_THREAD_TERMINOLOGY_001: `use` is the number of workers that
        // will actually be given a non-empty slice, AFTER the clamp above. The
        // caller takes the remaining slice, so effective participants is use+1.
        // This is the value a benchmark must report, not `threads`.
        RecordGeometry(threads, use, true, use + 1u, total_rows, 0);

        // RAWRXD_WORKERPOOL_STALE_GENERATION_001
        // Spawn first, then publish, and hand each new thread the CURRENT
        // generation so it cannot adopt work that is already in flight.
        //
        // The pool is a process-wide singleton and the benchmark runs several
        // model geometries through it in one process, so this is not
        // theoretical. A worker created by EnsureThreads() used to start with
        // seen = 0 and wait for `generation_ != 0`. Once a previous call had
        // already bumped generation_, a thread created during a later call woke
        // immediately, picked up that call's fn_/ctx_, and then decremented
        // pending_ a second time -- it was never counted in pending_ when the
        // work was published. pending_ is unsigned, so the extra decrement
        // underflowed it, the caller's `pending_ == 0` predicate stopped
        // matching, and Run() returned while worker threads were still writing
        // into the caller's output buffer. The next operation then reused or
        // freed that buffer underneath them.
        //
        // pending_ is also now guarded by done_m_ on both sides. It was written
        // under m_ and decremented under done_m_ -- two different mutexes for
        // one counter.
// P0_POOL_TRANSITION_001: boundaries bracket the publish so a dump pair shows
    // exactly what changed across one dispatch, including the geometry
    // (chunk_/total_/active_) and the pending_ lifecycle.
    static std::atomic<unsigned> g_configSeq{0};
    const unsigned seq = ++g_configSeq;
    DumpState("PRE", use, (unsigned)total_rows, seq);
    {
            std::lock_guard<std::mutex> lk(m_);
            while (threads_.size() < use) {
                const unsigned id = static_cast<unsigned>(threads_.size());
                const uint64_t born_at = generation_;
                // RAWRXD_POOL_STATE_DUMP_003: the watermark mirror must cover
                // every worker that exists. It was sized 8, so on a 16-logical
                // core host every worker with id >= 8 was excluded by the
                // `id < seenOf_.size()` guard in Worker() and never published a
                // watermark. Grown here, under m_, at the same moment the id is
                // assigned, so the index is always valid.
                if (id >= seenOf_.size()) seenOf_.resize(id + 1, 0);
                threads_.emplace_back([this, id, born_at] { Worker(id, born_at); });
            }
            fn_ = fn;
            ctx_ = ctx;
            // RAWRXD_WORKERPOOL_PARTITION_001
            // Split across ALL participants: the calling thread plus `use`
            // workers = use+1. Chunking by `use` instead gave the caller the
            // entire range whenever use==1, leaving the worker with an empty
            // slice that still had to signal completion -> guaranteed deadlock.
//
            // Ceil-division alone does not guarantee every slice is non-empty:
            // T=5 with use=3 gives parts=4, chunk=2, and the third worker range
            // [6,5) is empty. So the chunk is chosen first and the worker count
            // is then derived as the exact number of worker slices that exist,
            // ceil(total/chunk) - 1. `pending_` is set from that same value, so
            // budget and work agree by construction. Because
            // chunk >= total/(use+1), the derived count is always <= use, so
            // this can only shrink the fan-out, never exceed what was asked.
            // Clamping `use` by `total_rows - 1` alone does not reach this case.
            const size_t parts = static_cast<size_t>(use) + 1u;
            size_t chunk = (total_rows + parts - 1) / parts;
            if (chunk == 0) chunk = 1;
            const size_t populated = (total_rows + chunk - 1) / chunk - 1;
            if (populated == 0) { fn(ctx, 0, total_rows); return; }
            use = static_cast<unsigned>(populated);
            active_ = use;
            pending_ = use;
            last_actual_workers_.store(use, std::memory_order_release);
            last_caller_participates_.store(true, std::memory_order_release);
            last_effective_participants_.store(
                static_cast<unsigned>(use) + 1u, std::memory_order_release);
            // generation_ is a plain uint64_t guarded by m_, not an atomic, so
            // it cannot be .load()ed. The generation this dispatch belongs to is
            // the incremented value, and it must be published before pending_ is
            // observed as 0 or a worker could match the wrong generation.
            ++generation_;
            pending_gen_.store(generation_, std::memory_order_release);
            chunk_ = chunk;
            total_ = total_rows;
            // RAWRXD_THREAD_GEOMETRY_TRACE_001: re-record now that the
            // partition is known. The earlier record at entry passed chunk=0,
            // so every dispatched cell reported chunk=0 and a geometry report
            // could not state the slice size that actually executed.
            RecordGeometry(threads, use, true, use + 1u, total_rows, chunk);
            // RAWRXD_WORKERPOOL_ACTIVE_BOUND_001
            // active_ bounds who may consume this generation. The pool is a
            // process-wide singleton, so threads_ persists at the high-water
            // mark. Without this bound, a call asking for fewer threads than an
            // earlier call set pending_ = use, but EVERY parked thread still
            // satisfied `generation_ > seen`, woke, and decremented -- so
            // threads_.size() decrements hit a counter sized for `use` and
            // underflowed it again, letting Run() return while spare workers
            // were still writing into the caller's buffer.
            //
            // This is reachable precisely by a benchmark that walks thread
            // counts in one process: after an 8-thread call the next 2-thread
            // call had 6 surplus workers. It is equally reachable in production
            // whenever one layer has 8 rows of parallelism and the next has 2.
            //
// active_ / pending_ / chunk_ are assigned above from the same
            // narrowed `use`, so they are not repeated here. generation_ is
            // bumped together with pending_/pending_gen_ above, in one place.
        }
        cv_start_.notify_all();
        DumpState("PUBLISH", use, (unsigned)total_rows, seq);

        // The calling thread takes the first chunk, so only the remaining
        // chunks are handed to workers.
        fn(ctx, 0, chunk_ < total_rows ? chunk_ : total_rows);

        // RAWRXD_WORKERPOOL_BOUNDED_WAIT_001
        // This wait used to be unbounded. A lost wakeup therefore presented as
        // a silent hang: regime_sweep.exe sat at 3.5s of CPU indefinitely with
        // an empty output file, on its first use of the pool (MLP threads=2 at
        // depth 16, immediately after MLP threads=1, which runs inline and
        // never touches the pool). A hang with no diagnostic is strictly worse
        // than a slow call, so the wait is now bounded and a stall is counted
        // and reported on stderr. The timeout is far above any legitimate
        // dispatch time: the caller's own chunk has already run by this point.
        std::unique_lock<std::mutex> lk(done_m_);
        // B75A_TIMEOUT_ESCAPE_IMPOSSIBLE
        // With RAWRXD_WORKERPOOL_WAIT_INFINITE=1 the wait cannot expire, so
        // Run() can never return while a worker still holds fn_/ctx_. That
        // CLOSES the use-after-free window for a diagnostic run, rather than
        // merely raising the threshold and hoping the run stays under it.
        // The bounded wait below is the production default and is still a real
        // defect (RAWRXD_WORKERPOOL_TIMEOUT_ESCAPE_001); it is disabled here
        // only so the B75a experiment is unambiguous.
        bool finished;
        if (WaitInfinite()) {
            cv_done_.wait(lk, [this] {
                return pending_.load(std::memory_order_acquire) == 0 || stop_;
            });
            finished = true;
        } else {
            finished = cv_done_.wait_for(lk, std::chrono::seconds(10),
                [this] { return pending_.load(std::memory_order_acquire) == 0; });
        }
        // Capture the state AT RETURN so a harness can assert pending_ == 0
        // directly. A speedup number cannot distinguish "returned with all
        // workers finished" from "returned early"; this can.
        last_pending_at_return_.store(pending_.load(std::memory_order_acquire),
                                      std::memory_order_release);
        last_active_at_return_.store(active_, std::memory_order_release);
            last_total_at_return_.store((unsigned)total_, std::memory_order_release);
            last_chunk_at_return_.store((unsigned)chunk_, std::memory_order_release);
        last_generation_at_return_.store(generation_, std::memory_order_release);
        dispatches_.fetch_add(1, std::memory_order_relaxed);
        if (!finished) {
            const unsigned stuck = pending_.load(std::memory_order_acquire);
            std::fprintf(stderr,
                "[WORKERPOOL] STALL: use=%u active=%u parked=%zu pending=%u "
                "generation=%llu total=%zu chunk=%zu -- dispatched workers did "
                "not complete within 10s\n",
                use, active_, threads_.size(), stuck,
                (unsigned long long)generation_, total_, chunk_);
            std::fflush(stderr);
            ++stalls_;
            // RAWRXD_B76_WORKERPOOL_FAIL_CLOSED_001: the generation that
            // timed out may still be executing. Until its budget drains to
            // zero, no new dispatch may write into a caller buffer that a
            // stale worker could still be writing into.
            poisoned_ = true;
        }
        {
            std::lock_guard<std::mutex> lk2(m_);
            fn_ = nullptr;
            ctx_ = nullptr;
        }
        DumpState("POST", use, (unsigned)total_rows, seq);
    }

    unsigned long long stalls() const { return stalls_; }

    // B75A: state captured at the moment RunThreads returned. A diagnostic
    // harness reads these to assert the completion protocol rather than
    // inferring it from throughput.
    unsigned PendingAtReturn() const { return last_pending_at_return_.load(std::memory_order_acquire); }

  // RAWRXD_B77_INLINE_PATH_RECORDED_001: geometry for a dispatch that never
  // reaches the pool because ParallelRows short-circuited to inline.
  // RecordGeometry already publishes every field for this case; the inline
  // dispatch has zero workers, effective 1, and a single slice covering all
  // rows, so the extra store here only records the inlined flag.
    void RecordInline(unsigned requested, size_t total_rows) {
        // RAWRXD_B79_INLINE_CALLER_PARTICIPATES_001
        // callerParticipates must be TRUE here. The inline path does all the
        // work on the calling thread, so it is emphatically a participant;
        // recording false made a threads=1 cell report a geometry that looks
        // like "zero participants did anything", which is how requested=1 came
        // to look like a configuration that never ran.
        RecordGeometry(requested, 0, true, 1, total_rows, total_rows);
        last_inlined_.store(true, std::memory_order_release);
    }

  // RAWRXD_B77_THREAD_TERMINOLOGY_001: canonical geometry accessors.
  unsigned LastRequestedThreads() const { return last_requested_threads_.load(std::memory_order_acquire); }
  unsigned LastActualWorkers() const { return last_actual_workers_.load(std::memory_order_acquire); }
  bool LastCallerParticipates() const { return last_caller_participates_.load(std::memory_order_acquire); }
    unsigned LastEffectiveParticipants() const {
        return last_effective_participants_.load(std::memory_order_acquire);
    }
    size_t LastTotalRows() const { return last_total_rows_.load(std::memory_order_relaxed); }
    size_t LastChunk()     const { return last_chunk_.load(std::memory_order_relaxed); }
    bool   LastInlined()   const { return last_inlined_.load(std::memory_order_relaxed); }
    unsigned ActiveAtReturn() const { return last_active_at_return_.load(std::memory_order_acquire); }
    // P0_POOL_TRANSITION_001: total_rows of the dispatch that produced the
    // values above. One Forward() issues several dispatches (MLP gate/up with
    // total=I, MLP down with total=H, ATTN heads with total=nH), so a reader
    // must match on total_work_items to know which operator it is looking at.
    // Without this the reported geometry belongs to whichever dispatch ran last.
    unsigned TotalAtReturn() const { return last_total_at_return_.load(std::memory_order_acquire); }
    unsigned ChunkAtReturn() const { return last_chunk_at_return_.load(std::memory_order_acquire); }
    unsigned long long GenerationAtReturn() const { return last_generation_at_return_.load(std::memory_order_acquire); }
    unsigned long long Dispatches() const { return dispatches_.load(std::memory_order_acquire); }

    // RAWRXD_B78_INLINE_GEOMETRY_001
    // Records the geometry of a dispatch that ran entirely on the calling
    // thread. Zero workers, and the caller is the only participant -- which is
    // a DIFFERENT execution shape from a dispatched 2-way split, and was
    // previously indistinguishable because the inline path published nothing.
    void RecordInlineGeometry(size_t total_rows) {
        // Retained for source compatibility with callers that do not carry a
        // requested value. ParallelRows uses RecordInline(requested, ...) so the
        // per-requested tally in GeometryForRequested() is written; this overload
        // cannot key the tally, so it records against slot 1 only.
        RecordInline(1u, total_rows);
    }

private:
    static bool WaitInfinite() {
        static const bool v = [] {
#if defined(_MSC_VER)
            char* e = nullptr; size_t len = 0;
            if (_dupenv_s(&e, &len, "RAWRXD_WORKERPOOL_WAIT_INFINITE") == 0 && e && len > 0) {
                const int n = std::atoi(e);
                std::free(e);
                return n != 0;
            }
            std::free(e);
            return false;
#else
            const char* e = std::getenv("RAWRXD_WORKERPOOL_WAIT_INFINITE");
            return e && e[0] != '0';
#endif
        }();
        return v;
    }
    std::atomic<unsigned> last_pending_at_return_{0};
    std::atomic<unsigned> last_active_at_return_{0};
std::atomic<unsigned> last_total_at_return_{0};
std::atomic<unsigned> last_chunk_at_return_{0};
    std::atomic<unsigned long long> last_generation_at_return_{0};
    std::atomic<unsigned long long> dispatches_{0};
  // RAWRXD_B76_WORKERPOOL_FAIL_CLOSED_001: set when a dispatch times out with
  // workers possibly still running. While set, RunThreads executes inline only,
  // so no new dispatch writes into a buffer a stale worker may still touch.
  // Cleared once the offending generation's budget has drained to zero.
  std::atomic<bool> poisoned_{false};
  // RAWRXD_B77_THREAD_TERMINOLOGY_001: canonical geometry per dispatch, so a
  // benchmark can report what actually executed rather than what it requested.
    std::atomic<unsigned> last_requested_threads_{0};
    std::atomic<unsigned> last_actual_workers_{0};
    std::atomic<bool> last_caller_participates_{false};
    std::atomic<unsigned> last_effective_participants_{1};
    // RAWRXD_B77_THREAD_TERMINOLOGY_001: rows and chunk size, so a report can
    // state the geometry that executed rather than only the thread count. A
    // record without these cannot distinguish "8 threads over 8 rows" from
    // "8 threads over 1376 rows", which are different amounts of work.
    std::atomic<size_t> last_total_rows_{0};
    std::atomic<size_t> last_chunk_{0};
    std::atomic<bool> last_inlined_{false};
    // RAWRXD_THREAD_GEOMETRY_TRACE_001: per-requested-value geometry tally.
    // One forward pass issues hundreds of ParallelRows calls, so the
    // process-wide last-dispatch register cannot answer "what did MY requested
    // N do?". This can.
    DispatchRecord geom_[64]{};
    mutable std::mutex geom_m_{};   // mutable: GeometryForRequested() is const

    // P0_POOL_TRANSITION_001
    // Dumps the pool state that survives a config boundary, plus every parked
    // worker's identity and its `seen` watermark. The question is not what the
    // values are in isolation but whether a config run in a FRESH process
    // produces the same transition as the identical config run after sweep
    // cells that walked other thread counts in the same process. Anything that
    // differs there is cross-config contamination.
    //
    // Reads the same fields under the same m_ that publishes them, so the dump
    // cannot itself introduce the race it is meant to observe.
    void DumpState(const char* phase, unsigned threads, unsigned depth, unsigned seq) {
        static const bool on = [] {
            const char* e = std::getenv("RAWRXD_TRACE_POOL_STATE");
            return e && e[0] == '1';
        }();
        if (!on) return;
        std::lock_guard<std::mutex> lk(m_);
        std::fprintf(stderr,
            "POOL_STATE phase=%s config_seq=%u generation=%llu "
            "requested_threads=%u actual_workers=%u caller_participates=1 "
            "effective_participants=%u total_work_items=%zu chunk_size=%zu "
            "depth=%u active=%u pending=%u parked=%zu\n",
            phase, seq, (unsigned long long)generation_, threads,
            (unsigned)active_, (unsigned)active_ + 1u,
            total_, chunk_, depth, active_,
            pending_.load(std::memory_order_acquire), threads_.size());
        // Per-worker identity. `seen` is the watermark that decides which
        // generation a thread may consume; a stale one here is a candidate
        // root cause, but so is publishing a geometry while a worker still
        // observes another generation's geometry. The dump distinguishes them
        // rather than assuming.
        for (size_t w = 0; w < threads_.size(); ++w) {
            // Bounded read: threads_ can outgrow the mirror, and a diagnostic
            // that reads past its own buffer reports garbage as if it were pool
            // state. Out-of-range prints seen=NA rather than an out-of-bounds
            // load.
            bool mirrored = (w < seenOf_.size());
            unsigned long long seen = 0;
            if (mirrored) seen = (unsigned long long)seenOf_[w];
            if (mirrored) {
                std::fprintf(stderr,
                    "POOL_WORKER worker=%zu eligible=%d seen=%llu\n",
                    w, (active_ != 0 && w < active_) ? 1 : 0, seen);
            } else {
                std::fprintf(stderr,
                    "POOL_WORKER worker=%zu eligible=%d seen=NA\n",
                    w, (active_ != 0 && w < active_) ? 1 : 0);
            }
        }
        std::fflush(stderr);
    }

private:
    using TaskFn = void (*)(void*, size_t, size_t);

    // RAWRXD_B77_THREAD_TERMINOLOGY_001: one place that records the geometry, so
    // every exit path (inline, clamped, dispatched) publishes a record and none
    // of them can leave the previous dispatch's numbers on display.
    void RecordGeometry(unsigned requested, unsigned workers, bool caller,
                        unsigned effective, size_t total_rows, size_t chunk) {
        last_requested_threads_.store(requested, std::memory_order_release);
        last_actual_workers_.store(workers, std::memory_order_release);
        last_caller_participates_.store(caller, std::memory_order_release);
        last_effective_participants_.store(effective, std::memory_order_release);
        last_total_rows_.store(total_rows, std::memory_order_relaxed);
        last_chunk_.store(chunk, std::memory_order_relaxed);
        last_inlined_.store(false, std::memory_order_relaxed);
        dispatches_.fetch_add(1, std::memory_order_relaxed);
        // RAWRXD_THREAD_GEOMETRY_TRACE_001: tally by requested value as well.
        // The process-wide last-dispatch register cannot answer a
        // per-configuration question, because one forward pass issues hundreds
        // of dispatches and the register ends up describing the last inner op.
        const unsigned idx = requested < kGeomSlots ? requested : kGeomSlots - 1;
        // RAWRXD_B78_TALLY_LOCK_001: this tally is READ under geom_m_ by
        // GeometryForRequested() but was WRITTEN here without holding it. A
        // DispatchRecord is several scalar fields, so a concurrent reader could
        // observe a half-updated record -- new actual_workers beside an old
        // effective count -- which is exactly the contradictory geometry that
        // request_geometry_probe rejected. Written under the reader's lock.
        {
            std::lock_guard<std::mutex> glk(geom_m_);
            DispatchRecord& slot = geom_[idx];
            slot.seq             = dispatches_.load(std::memory_order_relaxed);
            slot.requestedThreads= requested;
            slot.requestedWorkers= requested >= 1u ? requested - 1u : 0u;
            slot.actualWorkers   = workers;
            slot.callerParticipates = caller;
            slot.effectiveParticipants = effective;
            slot.totalRows       = total_rows;
            slot.chunk           = chunk;
            slot.inlined         = (workers == 0);
            slot.timesRequested += 1;
        }
    }
public:
    // RAWRXD_THREAD_GEOMETRY_TRACE_001
    // Public accessors for the per-requested-value geometry tally. They must sit
    // after an explicit `public:` because this class has TWO private: markers and
    // these declarations land after both of them; without this the free-function
    // wrappers failed to compile with C2248.
    static constexpr unsigned kGeomSlots = 64;
    DispatchRecord GeometryForRequested(unsigned requested) const {
        if (requested >= kGeomSlots) return DispatchRecord{};
        std::lock_guard<std::mutex> lk(const_cast<std::mutex&>(geom_m_));
        return geom_[requested];
    }
    void ResetGeometryTrace() {
        std::lock_guard<std::mutex> lk(geom_m_);
        for (unsigned i = 0; i < kGeomSlots; ++i) geom_[i] = DispatchRecord{};
    }

    // born_at is the generation this thread was created in. A thread must never
    // consume a generation that was published before it existed, because it is
    // not counted in that generation's pending_ budget.
    void Worker(unsigned id, uint64_t born_at) {
        uint64_t seen = born_at;
        for (;;) {
            TaskFn fn = nullptr;
            void* ctx = nullptr;
            size_t begin = 0, end = 0;
            uint64_t gen = 0;
            {
                std::unique_lock<std::mutex> lk(m_);
                cv_start_.wait(lk, [this, seen] { return generation_ > seen || stop_; });
                if (stop_) return;
                seen = generation_;
                gen = seen;
                if (id < seenOf_.size()) seenOf_[id] = seen;
                // A surplus thread left over from a wider earlier call must NOT
                // consume this generation: it is not in the pending_ budget.
                // It records the generation as seen and goes back to waiting.
                if (id >= active_) continue;
                fn = fn_;
                ctx = ctx_;
                const size_t base = chunk_ * (id + 1);
                begin = base < total_ ? base : total_;
                const size_t stop = begin + chunk_;
                end = stop < total_ ? stop : total_;
                // A slice that is empty (begin == end) is NOT a participant.
                // Counting it would decrement the budget for work never done,
                // which is exactly how pending_ underflowed to 0xFFFFFFFF.
                if (begin >= end) continue;
            }
if (fn) {
                fn(ctx, begin, end);
                // RAWRXD_WORKERPOOL_STALE_DECREMENT_001: only the generation
                // this task was published under may debit its budget. If a
                // bounded wait timed out while this slice was still running, a
                // later dispatch has already re-armed pending_; decrementing now
                // would corrupt that budget and underflow the unsigned counter,
                // stalling every subsequent call.
                if (gen != pending_gen_.load(std::memory_order_acquire))
                    continue;
                if (pending_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                    std::lock_guard<std::mutex> lk(done_m_);
                    cv_done_.notify_one();
                }
            }
        }
    }

// RAWRXD_POOL_STATE_DUMP_001: DumpState() is a const observer that locks m_
// so its read of generation_/chunk_/total_/active_/pending_ is ordered against
// the publishing side rather than racing it. That requires m_ to be mutable.
mutable std::mutex m_;
mutable std::mutex done_m_;
std::condition_variable cv_start_;
std::condition_variable cv_done_;
    std::vector<std::thread> threads_;
    TaskFn fn_ = nullptr;
    void* ctx_ = nullptr;
    size_t chunk_ = 0;
    size_t total_ = 0;
    // RAWRXD_WORKERPOOL_STALE_GENERATION_001: pending_ is published under m_
    // and consumed under done_m_. It is atomic so the publish and the decrements
    // are ordered by a single modification order rather than by two unrelated
    // mutexes; the underflow this replaces is what let Run() return early with
    // workers still writing into the caller's buffer.
    std::atomic<unsigned> pending_{0};
    // Per-worker `seen` watermark, mirrored so DumpState can report it without
    // reaching into a worker that owns the authoritative copy. Index is the
    // worker id assigned at creation and never reused.
    //
    // RAWRXD_POOL_STATE_DUMP_002: this was brace-initialised, which selects
    // vector(initializer_list<uint64_t>) -- so `{8, 0}` built a TWO-element
    // vector holding {8, 0}, not eight zeros. Worker's `id < seenOf_.size()`
    // guard then excluded every worker with id >= 2, and DumpState read
    // seenOf_[w] for w < threads_.size() past the end of a two-element buffer.
    // The over-read is what produced the garbage watermarks
    // (27303570963497028, 9799848659912978135, ...) that looked like stale
    // generations. Parenthesised init: count-then-value, as intended.
    // `= std::vector<uint64_t>(8, 0)` rather than `seenOf_(8, 0)`: the bare
    // parenthesised form in a class body is parsed as a function declaration
    // by MSVC (C2059), which then makes every `seenOf_.` use a syntax error.
    std::vector<uint64_t> seenOf_ = std::vector<uint64_t>(8, 0);
    // RAWRXD_WORKERPOOL_STALE_DECREMENT_001: generation that pending_ is
    // currently armed for. A worker that is still running when the bounded wait
    // times out will finish its slice afterwards and decrement whatever budget
    // the NEXT call armed, which underflows the unsigned counter to 0xFFFFFFFF
    // and stalls every later dispatch. The decrement is therefore only valid if
    // the generation the task was published under is still the armed one.
    std::atomic<uint64_t> pending_gen_{0};
    // RAWRXD_WORKERPOOL_ACTIVE_BOUND_001: how many of the parked workers may
    // consume the current generation. Guards against surplus threads
    // decrementing a counter sized for fewer workers than exist.
    unsigned active_ = 0;
    uint64_t generation_ = 0;
    // RAWRXD_WORKERPOOL_BOUNDED_WAIT_001: dispatch completions that never
    // arrived. Readable through WorkerPool::Instance().stalls() so a benchmark
    // can refuse to admit a speedup that overlapped an unfinished dispatch.
    std::atomic<unsigned long long> stalls_{0};
    bool stop_ = false;
};

void MatMulRangeTask(void* ctx, size_t begin, size_t end) {
    struct Args { float* y; const float* x; const float* W; size_t k; size_t n; };
    Args* a = static_cast<Args*>(ctx);
    const size_t stride = a->k;
    for (size_t i = begin; i < end; ++i) {
        a->y[i] = DotRow(a->W + i * stride, a->x, a->k);
    }
}

} // namespace

void MatMulRowInto(float* y, const float* x, const float* W, size_t k, size_t n) {
    if (n == 0 || k == 0) return;
    const unsigned nt = MatMulThreadCount(n);
    if (nt <= 1) {
        for (size_t i = 0; i < n; ++i) y[i] = DotRow(W + i * k, x, k);
        return;
    }
    struct Args { float* y; const float* x; const float* W; size_t k; size_t n; } args{y, x, W, k, n};
    WorkerPool::Instance().Run(&MatMulRangeTask, &args, n);
}

void MatMulRow(std::vector<float>& y, const float* x, const float* W, size_t k, size_t n) {
    y.resize(n);
    MatMulRowInto(y.data(), x, W, k, n);
}

void MatMulRowsInto(float* y, size_t y_stride, const float* x, const float* W,
                    size_t w_count, size_t k, size_t n) {
    for (size_t j = 0; j < w_count; ++j) {
        MatMulRowInto(y + j * y_stride, x, W + j * n * k, k, n);
    }
}

// ===========================================================================
// RmsNorm: y = x / sqrt(mean(x^2) + eps) * weight
// ===========================================================================
void RmsNorm(float* out, const float* x, const float* weight, size_t n, float eps) {
    if (n == 0) return;
#if defined(__AVX512F__)
    if (UseAvx512()) {
        __m512 ss = _mm512_setzero_ps();
        size_t i = 0;
        for (; i + 16 <= n; i += 16) {
            __m512 v = _mm512_loadu_ps(x + i);
            ss = _mm512_fmadd_ps(v, v, ss);
        }
        float total = _mm512_reduce_add_ps(ss);
        for (; i < n; ++i) total += x[i] * x[i];
        const float inv = 1.0f / std::sqrt(total / static_cast<float>(n) + eps);
        const __m512 vinv = _mm512_set1_ps(inv);
        size_t j = 0;
        for (; j + 16 <= n; j += 16) {
            __m512 v = _mm512_mul_ps(_mm512_loadu_ps(x + j), vinv);
            _mm512_storeu_ps(out + j, _mm512_mul_ps(v, _mm512_loadu_ps(weight + j)));
        }
        for (; j < n; ++j) out[j] = x[j] * inv * weight[j];
        return;
    }
#endif
#if defined(__AVX2__) && !defined(__AVX512F__)
    if (UseAvx2()) {
        __m256 ss = _mm256_setzero_ps();
        size_t i = 0;
        for (; i + 8 <= n; i += 8) {
            __m256 v = _mm256_loadu_ps(x + i);
            ss = _mm256_fmadd_ps(v, v, ss);
        }
        __m128 lo = _mm256_castps256_ps128(ss), hi = _mm256_extractf128_ps(ss, 1);
        lo = _mm_add_ps(lo, hi); lo = _mm_hadd_ps(lo, lo); lo = _mm_hadd_ps(lo, lo);
        float total = _mm_cvtss_f32(lo);
        for (; i < n; ++i) total += x[i] * x[i];
        const float inv = 1.0f / std::sqrt(total / static_cast<float>(n) + eps);
        const __m256 vinv = _mm256_set1_ps(inv);
        size_t j = 0;
        for (; j + 8 <= n; j += 8) {
            __m256 v = _mm256_mul_ps(_mm256_loadu_ps(x + j), vinv);
            _mm256_storeu_ps(out + j, _mm256_mul_ps(v, _mm256_loadu_ps(weight + j)));
        }
        for (; j < n; ++j) out[j] = x[j] * inv * weight[j];
        return;
    }
#endif
    float ss = 0.0f;
    for (size_t i = 0; i < n; ++i) ss += x[i] * x[i];
    const float inv = 1.0f / std::sqrt(ss / static_cast<float>(n) + eps);
    for (size_t i = 0; i < n; ++i) out[i] = x[i] * inv * weight[i];
}

// ===========================================================================
// Attention primitives
// ===========================================================================
float Dot(const float* a, const float* b, size_t n) {
    return DotRow(a, b, n);
}

void WeightedSum(float* dst, const float* w, const float* V, size_t stride,
                 size_t width, size_t count, float* scratch) {
    if (count == 0 || width == 0) return;
    // `width` elements are written per row; consecutive rows sit `stride`
    // apart in V. They are equal for MHA, and width < stride under GQA.
    float* a = scratch;
    if (!a) {
        a = static_cast<float*>(_alloca(width * sizeof(float)));
    }
    std::memset(a, 0, width * sizeof(float));
    for (size_t p = 0; p < count; ++p) {
        const float wp = w[p];
        const float* v = V + p * stride;
#if defined(__AVX512F__)
        if (UseAvx512()) {
            const __m512 wv = _mm512_set1_ps(wp);
            size_t i = 0;
            for (; i + 16 <= width; i += 16) {
                _mm512_storeu_ps(a + i, _mm512_fmadd_ps(wv, _mm512_loadu_ps(v + i),
                                                        _mm512_loadu_ps(a + i)));
            }
            for (; i < width; ++i) a[i] += wp * v[i];
            continue;
        }
#endif
        for (size_t i = 0; i < width; ++i) a[i] += wp * v[i];
    }
#if defined(__AVX512F__)
    if (UseAvx512()) {
        size_t i = 0;
        for (; i + 16 <= width; i += 16) {
            _mm512_storeu_ps(dst + i, _mm512_add_ps(_mm512_loadu_ps(dst + i),
                                                    _mm512_loadu_ps(a + i)));
        }
        for (; i < width; ++i) dst[i] += a[i];
        return;
    }
#endif
    for (size_t i = 0; i < width; ++i) dst[i] += a[i];
}

// ===========================================================================
// Softmax (numerically stable, in place)
// ===========================================================================
void Softmax(float* x, size_t n) {
    if (n == 0) return;
    float mx = x[0];
    for (size_t i = 1; i < n; ++i) if (x[i] > mx) mx = x[i];
    float sum = 0.0f;
    for (size_t i = 0; i < n; ++i) { x[i] = std::exp(x[i] - mx); sum += x[i]; }
    if (sum > 0.0f) {
        const float inv = 1.0f / sum;
        for (size_t i = 0; i < n; ++i) x[i] *= inv;
    }
}

// ===========================================================================
// SiLU: x * sigmoid(x)
// ===========================================================================
void SiluInPlace(float* x, size_t n) {
#if defined(__AVX512F__)
    if (UseAvx512()) {
        size_t i = 0;
        for (; i + 16 <= n; i += 16) {
            __m512 v = _mm512_loadu_ps(x + i);
            // exp via the 256-bit intrinsic on each half keeps accuracy; the
            // approximation error is far below float32 relevance here.
            __m512 e = _mm512_exp_ps(_mm512_sub_ps(_mm512_setzero_ps(), v));
            _mm512_storeu_ps(x + i, _mm512_mul_ps(v, _mm512_div_ps(_mm512_set1_ps(1.0f),
                                                                   _mm512_add_ps(_mm512_set1_ps(1.0f), e))));
        }
        for (; i < n; ++i) x[i] = x[i] / (1.0f + std::exp(-x[i]));
        return;
    }
#endif
    for (size_t i = 0; i < n; ++i) x[i] = x[i] / (1.0f + std::exp(-x[i]));
}

// ===========================================================================
// Elementwise helpers
// ===========================================================================
void MulInPlace(float* a, const float* b, size_t n) {
#if defined(__AVX512F__)
    if (UseAvx512()) {
        size_t i = 0;
        for (; i + 16 <= n; i += 16)
            _mm512_storeu_ps(a + i, _mm512_mul_ps(_mm512_loadu_ps(a + i),
                                                  _mm512_loadu_ps(b + i)));
        for (; i < n; ++i) a[i] *= b[i];
        return;
    }
#endif
    for (size_t i = 0; i < n; ++i) a[i] *= b[i];
}

void AddInPlace(float* dst, const float* src, size_t n) {
#if defined(__AVX512F__)
    if (UseAvx512()) {
        size_t i = 0;
        for (; i + 16 <= n; i += 16)
            _mm512_storeu_ps(dst + i, _mm512_add_ps(_mm512_loadu_ps(dst + i),
                                                    _mm512_loadu_ps(src + i)));
        for (; i < n; ++i) dst[i] += src[i];
        return;
    }
#endif
    for (size_t i = 0; i < n; ++i) dst[i] += src[i];
}

// ===========================================================================
// RoPE. GGUF stores rotary weights with the real part in the first half and
// the imaginary part in the second (HuggingFace rotate_half convention).
//   v[i]        = x0*cos - x1*sin
//   v[i + half] = x0*sin + x1*cos
// ===========================================================================
void ApplyRope(float* v, size_t head_dim, float pos, const float* inv_freq) {
    const size_t half = head_dim / 2;
    for (size_t i = 0; i < half; ++i) {
        const float f = pos * inv_freq[i];
        const float c = std::cos(f);
        const float s = std::sin(f);
        const float x0 = v[i];
        const float x1 = v[i + half];
        v[i] = x0 * c - x1 * s;
        v[i + half] = x0 * s + x1 * c;
    }
}

int EnvThreads(const char* name) {
#if defined(_MSC_VER)
    char* e = nullptr;
    size_t len = 0;
    if (_dupenv_s(&e, &len, name) == 0 && e && len > 0) {
        const int v = std::atoi(e);
        std::free(e);
        return v;
    }
    std::free(e);
    return -1;
#else
    const char* e = std::getenv(name);
    return e ? std::atoi(e) : -1;
#endif
}

int EnvCtxThreshold() {
    static const int v = [] {
        const int f = EnvThreads("RAWRXD_CTX_THRESHOLD");
        return f > 0 ? f : 256;
    }();
    return v;
}

void ParallelRows(RowTask fn, void* ctx, size_t total_rows, unsigned threads) {
    if (!fn || total_rows == 0) return;
    // RAWRXD_B78_INLINE_GEOMETRY_001
    // The inline fast path below returns WITHOUT reaching RunThreads, so it
    // never published a geometry. The last-record fields then kept whatever the
    // PREVIOUS dispatch left behind, and a receipt read after a threads=1 cell
    // reported that earlier cell's fan-out instead of its own.
    //
    // workerpool_geometry_probe measured exactly this: at total=8,
    // requested=1 reported workers=2 effective=3, which is the stale record
    // from the preceding total=3/requested=16 dispatch. A threads=1 cell
    // therefore looked like a 3-way fan-out.
    //
    // Recording the inline geometry here makes every dispatch -- inline or
    // dispatched -- leave a record that describes itself.
    if (threads <= 1 || total_rows < 2) {
        // RAWRXD_B79_INLINE_TALLY_001
        // Must be RecordInline(requested, ...) so the per-requested tally in
        // GeometryForRequested() is written. Calling the tally-free
        // RecordInlineGeometry(size_t) left slot `requested` empty, so
        // GeometryForRequested(1) returned a zeroed record and requested=1
        // vanished from every receipt.
        WorkerPool::Instance().RecordInline(threads, total_rows);
        fn(ctx, 0, total_rows);
        return;
    }
    WorkerPool::Instance().RunThreads(fn, ctx, total_rows, threads);
}

// RAWRXD_WORKERPOOL_BOUNDED_WAIT_001
unsigned long long DispatchStalls() {
    return WorkerPool::Instance().stalls();
}

// RAWRXD_THREAD_GEOMETRY_TRACE_001: process-wide dispatch count. The pool
// member exists but the free function did not, so anything that counted
// dispatches (thread_geometry_probe, regime_sweep's seq column) failed to link
// with LNK2019.
unsigned long long DispatchCount() {
    return WorkerPool::Instance().Dispatches();
}

// B75A: completion-protocol evidence. With RAWRXD_WORKERPOOL_WAIT_INFINITE=1 a
// dispatch cannot time out, so a nonzero pending count at return is a protocol
// break rather than noise. These three free functions were declared in the
// header but their definitions were lost during an edit, so regime_sweep failed
// to link with LNK2019.
unsigned DispatchPendingAtReturn() {
    return WorkerPool::Instance().PendingAtReturn();
}
unsigned DispatchActiveAtReturn() {
    return WorkerPool::Instance().ActiveAtReturn();
}
unsigned DispatchTotalAtReturn() {
    return WorkerPool::Instance().TotalAtReturn();
}
unsigned DispatchChunkAtReturn() {
    return WorkerPool::Instance().ChunkAtReturn();
}
unsigned long long DispatchGenerationAtReturn() {
    return WorkerPool::Instance().GenerationAtReturn();
}

// RAWRXD_B77_INLINE_PATH_RECORDED_001
// ParallelRows returns on `threads <= 1` BEFORE consulting the pool, so the
// pool's last_* geometry fields retained the PREVIOUS dispatch's values. A
// requested value of 1 was therefore reported as whatever ran last -- which is
// exactly the "a requested configuration disappeared from the report" symptom,
// reproduced deterministically by thread_geometry_probe. Execution was always
// correct; only the record was stale.
//
// Recording here rather than only inside RunThreads closes it: this is the path
// the pool never sees.
void RecordInlineGeometry(unsigned requested, size_t total_rows) {
    WorkerPool::Instance().RecordInline(requested, total_rows);
}

// RAWRXD_B77_THREAD_TERMINOLOGY_001: free-function accessors mirroring
// DispatchStalls(), so a benchmark can report the geometry that ACTUALLY
// executed rather than the one it requested.
unsigned LastRequestedThreads() {
    return WorkerPool::Instance().LastRequestedThreads();
}
unsigned LastActualWorkers() {
    return WorkerPool::Instance().LastActualWorkers();
}
bool LastCallerParticipates() {
    return WorkerPool::Instance().LastCallerParticipates();
}
unsigned LastEffectiveParticipants() {
    return WorkerPool::Instance().LastEffectiveParticipants();
}
size_t LastTotalRows() { return WorkerPool::Instance().LastTotalRows(); }
size_t LastChunk()     { return WorkerPool::Instance().LastChunk(); }
bool   LastInlined()   { return WorkerPool::Instance().LastInlined(); }

// RAWRXD_THREAD_GEOMETRY_TRACE_001: the per-request entry point. The
// process-wide accessors above answer "what ran last", which a benchmark cannot
// use: one forward pass issues hundreds of dispatches, so the last one is an
// inner op and not the configuration under test.
DispatchRecord GeometryForRequested(unsigned requested) {
    return WorkerPool::Instance().GeometryForRequested(requested);
}

void ResetDispatchTrace() {
    WorkerPool::Instance().ResetGeometryTrace();
}

} // namespace cpu
} // namespace rawrxd
