// rawrxd_cpu_math.hpp - CPU inference kernels.
//
// Dispatch is RUNTIME (CPUID), not compile-time, so one binary runs correctly
// on AVX-512, AVX2, and plain SSE2 hosts. The AVX-512 path is compiled with
// __AVX512F__ guards by the build; when the guard is absent we still get the
// portable path plus runtime dispatch of whatever MSVC auto-vectorizes.
//
// Numerics are held to the scalar reference: changes are accepted only after
// rawrxd_math_parity_check reports agreement.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rawrxd {
namespace cpu {

// ---- capability detection (leaf 7 for AVX2/AVX-512, leaf 1 for FMA/F16C) ----
struct Caps {
    bool sse2 = false;
    bool fma = false;
    bool f16c = false;
    bool avx = false;
    bool avx2 = false;
    bool avx512f = false;
    bool avx512dq = false;
    bool avx512bw = false;
    bool avx512vl = false;
    bool avx512vnni = false;
    unsigned logical_cpus = 1;
};

const Caps& Detect();
const char* BackendName();

// y[0..n) = sum_l W[i*k + l] * x[l]  for every output row i in [0,n).
// W is row-major [n x k]; x is [k]. `y` is resized to n.
void MatMulRow(std::vector<float>& y, const float* x, const float* W,
               size_t k, size_t n);

// Same math, but writes into an existing buffer sized >= n.
void MatMulRowInto(float* y, const float* x, const float* W, size_t k, size_t n);

// Batched variant: computes rows of y for a single x vector. Used by the fused
// QKV path where the same activation feeds several projections.
void MatMulRowsInto(float* y, size_t y_stride, const float* x, const float* W,
                    size_t w_count, size_t k, size_t n);

// y = rmsnorm(x) * weight, in place semantics on separate buffers.
void RmsNorm(float* out, const float* x, const float* weight, size_t n, float eps);

// In-place softmax over n floats.
void Softmax(float* x, size_t n);

// Applies SiLU (x * sigmoid(x)) to n floats in place.
void SiluInPlace(float* x, size_t n);

// elementwise a[i] = a[i] * b[i] over n floats.
void MulInPlace(float* a, const float* b, size_t n);

// Rotary embedding over head_dim (interleaved-half convention).
void ApplyRope(float* v, size_t head_dim, float pos, const float* inv_freq);

// Adds src into dst over n floats.
void AddInPlace(float* dst, const float* src, size_t n);

// Dot product of two n-element vectors. Used for QK attention scores.
float Dot(const float* a, const float* b, size_t n);

// dst[i] += sum_p w[p] * V[p*stride + i] for i in [0,width), p in [0,count).
// `width` is the number of elements written per row (head_dim), while `stride`
// is the distance between rows in V (kv_dim). These differ under GQA, where
// stride > width; conflating them writes past the caller's destination.
// `scratch` must hold at least `width` floats; passing it avoids a heap
// allocation per call, which dominated decode cost at long context.
void WeightedSum(float* dst, const float* w, const float* V, size_t stride,
                 size_t width, size_t count, float* scratch);

// ---- coarse-grained parallel primitives -------------------------------------
//
// These split a CONTIGUOUS range of independent work units (output rows, or
// attention heads) across a persistent worker pool. Each unit writes a disjoint
// output range and reads shared inputs read-only, so no reduction is needed.
// That disjointness is what makes these cheap: the caller keeps its unit and
// only the remainder is dispatched, and the barrier cost is amortized over a
// large unit rather than a tiny one.

using RowTask = void (*)(void* ctx, size_t begin, size_t end);

// Split [0, total_rows) into `threads` contiguous chunks and run fn on each.
// threads <= 1 runs inline on the calling thread with no synchronization.
void ParallelRows(RowTask fn, void* ctx, size_t total_rows, unsigned threads);

// RAWRXD_WORKERPOOL_BOUNDED_WAIT_001: a dispatch whose workers did not finish
// is bounded at 10s and counted rather than waited on forever, so a lost
// wakeup cannot present as a silent hang. DispatchStalls() is monotonic for the
// process: a benchmark samples it before and after a configuration and must
// REJECT that configuration if it moved, because the work overlapped an
// unfinished dispatch and the timing means nothing.
unsigned long long DispatchStalls();

// RAWRXD_THREAD_GEOMETRY_TRACE_001
// One record per ParallelRows call, describing what was ASKED for and what
// ACTUALLY ran. These are deliberately separate fields with explicit names.
// A single "threads" integer cannot answer "did my requested 2 threads run?":
// ParallelRows inlines at threads<=1, RunThreads subtracts the caller
// (use = threads - 1), and then re-clamps `use` to the number of slices that
// actually have rows. Three transformations sit between the caller's number and
// the thread count, and conflating them is how a requested configuration
// disappears from a report without anyone noticing.
struct DispatchRecord {
    uint64_t    seq             = 0;   // monotonic; 0 means "never dispatched"
    unsigned    requestedThreads = 0; // exactly what the caller passed
    unsigned    requestedWorkers = 0; // requestedThreads - 1 (the caller is one)
    unsigned    actualWorkers    = 0; // workers that were given a non-empty slice
    bool        callerParticipates = false;
    unsigned    effectiveParticipants = 0;  // actualWorkers + callerParticipates
    size_t      totalRows        = 0;
    size_t      chunk            = 0;
    size_t      rowsDispatched   = 0;     // rows handed to workers + caller
    bool        inlined          = false; // ran on the caller with no pool at all
    bool        requestedLostWork = false; // total_rows not fully covered
    // Observed count of dispatches that carried this requested value. Lets a
    // report distinguish "requested 4 never happened" from "requested 4 ran 84
    // times at geometry G".
    uint64_t    timesRequested   = 0;
};

// RAWRXD_THREAD_GEOMETRY_TRACE_001
// A DispatchRecord is the full description of one dispatch: what was requested,
// what ran, and how many times that request was seen. The canonical, per-request
// entry point is GeometryForRequested(); the process-wide LastDispatch() is a
// DispatchInfo and CANNOT answer a per-configuration question (see below).
//
// RAWRXD_THREAD_GEOMETRY_TRACE_001
// LastDispatch() alone CANNOT answer a per-configuration question. A single
// model forward pass issues hundreds of ParallelRows calls, so the process-wide
// last-dispatch register ends up describing whatever inner op ran last --
// measured in regime_sweep, every cell reported effective_participants=8
// rows=512 because the final down-projection was the last dispatch, regardless
// of what the cell requested. Tallying per requested value is what makes a
// requested configuration distinguishable in a receipt.
DispatchRecord GeometryForRequested(unsigned requested);

void           ResetDispatchTrace();

// RAWRXD_B77_THREAD_TERMINOLOGY_001
// Canonical execution geometry for the most recent ParallelRows dispatch.
// `threads` is ambiguous on its own: threads==1 runs INLINE on the caller with
// zero workers dispatched, while threads>=2 splits the range between the
// caller and (threads-1) workers. A label of "N threads" does not distinguish
// those, so a benchmark must report the geometry that executed.
unsigned LastRequestedThreads();
unsigned LastActualWorkers();
bool LastCallerParticipates();
// actual_workers + (caller_participates ? 1 : 0) -- 1 when inline, N when split.
unsigned LastEffectiveParticipants();
// The row count and slice size the last dispatch actually used. Without these a
// geometry report cannot distinguish "8 participants over 8 rows" from "8
// participants over 1376 rows", which are different amounts of work.
size_t LastTotalRows();
size_t LastChunk();
bool   LastInlined();

// RAWRXD_THREAD_POLICY_SHARED_001
// One minimum-work-per-thread policy, shared by MatMulThreadCount and
// ParallelRows, so the two paths cannot drift apart again. kMinRowsPerThread=4
// used to be consulted only by MatMulThreadCount, which the attention path
// bypasses entirely -- measured at depth=4096 that produced rows=8 split 8
// ways (slice=1 per worker) across 11040 dispatches per cell.
//
// `requested` is TOTAL PARTICIPANTS (the caller keeps slice 0 and is itself a
// participant), so the ceiling is ceil(total_rows / kMinRowsPerThread).
// At rows=8 that is 2 participants, not 3.
//
// These report what the policy did to the most recent request. A clamped
// request and a genuinely narrow one produce identical geometry, so the
// geometry alone cannot distinguish them.
unsigned PolicyRequested();
unsigned PolicyEffective();
// Clamps ONLY -- requests the policy actually reduced. Divide by
// PolicyRequests() for the clamp rate. Do NOT divide by total dispatches:
// most dispatches are the inline threads<=1 path and never reach the policy,
// which makes that ratio meaningless.
unsigned long long PolicyClamps();
unsigned long long PolicyRequests();

// B75A_TIMEOUT_ESCAPE_IMPOSSIBLE
// State captured at the instant the most recent dispatch returned. With
// RAWRXD_WORKERPOOL_WAIT_INFINITE=1 the wait cannot expire, so a diagnostic
// run can assert PendingAtReturn() == 0 rather than inferring completion from a
// throughput number. A nonzero PendingAtReturn() is a completion-protocol
// break, not measurement noise.
unsigned DispatchPendingAtReturn();
unsigned DispatchActiveAtReturn();
// P0_POOL_TRANSITION_001: total_rows of the dispatch those return-values
// describe. One Forward() issues several, so callers must match on this to
// attribute geometry to the operator they actually measured.
unsigned DispatchTotalAtReturn();
unsigned DispatchChunkAtReturn();
unsigned long long DispatchGenerationAtReturn();
unsigned long long DispatchCount();

// Read an integer thread-count override from the environment.
// RAWRXD_MATMUL_THREADS / RAWRXD_MLP_THREADS / RAWRXD_ATTN_THREADS
// Unset means "not forced"; callers then apply their own default policy.
int EnvThreads(const char* name);

// Fixed context-depth boundary for the two parallelization regimes.
// RAWRXD_CTX_THRESHOLD: ctx <= threshold -> MLP regime; ctx > -> attention.
// Deliberately fixed rather than adaptive, so the policy is not itself a
// variable in the experiment.
int EnvCtxThreshold();

} // namespace cpu
} // namespace rawrxd