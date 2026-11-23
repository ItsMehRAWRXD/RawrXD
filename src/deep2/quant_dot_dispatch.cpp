// RAWRXD_DEEP2_GPU_QUANT_DOT_001 - implementation.
//
// GPU-first dispatch with a real CPU fallback. The GPU kernel lives in
// RawrXD::Deep2::QuantDot (RawrXD_GPU.obj) and is driven through the Vulkan
// wrapper in src/vulkan_compute.cpp. When the GPU path cannot run, this layer
// falls back to the caller's CpuDot so the caller still gets REAL numbers.
//
// Honest accounting: DotBlocked reports which path actually ran via
// LastReceipt(), and the executor increments gpu_calls_ / cpu_calls_ from that
// truth rather than from intent. A GPU failure is therefore visible as a
// cpu-run, not as a silent pretend-success.

#include "quant_dot_dispatch.hpp"

#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <atomic>
#include <cstdio>
#include <cstdlib>

#include "include/vulkan_compute.h"   // canonical path; quoted includes search this file's own directory (src/deep2/) first, where a DIFFERENT Deep2::VulkanCompute class lives in vulkan_compute.h and would silently shadow this one

// Dispatch-layer trace, gated so steady-state runs pay nothing. Prints the
// batch lifecycle so a hang can be localised to Begin/Queue/End without a
// debugger. Cost is one getenv check per call.
#define QDTRACE_DISPATCH(msg) do { \
    static const bool qd_trace_on_ = (std::getenv("RR_QD_TRACE") != nullptr); \
    if (qd_trace_on_) std::fprintf(stderr, "[qd-trace-dispatch] %s\n", \
        (std::ostringstream() << msg).str().c_str()); \
} while (0)

namespace RawrXD {
namespace Deep2 {
namespace QuantDot {

namespace {

bool g_force_cpu = false;
thread_local Receipt g_receipt;
thread_local BackendStats g_backend;
int32_t g_preferred_device = -1;   // STRATA_S05: device pin, applied at first init
thread_local int32_t g_active_device = -1; // RAWRXD_MULTI_GPU: per-thread device override (-1 = default Gpu(); set via SetActiveDevice for split-model dual-GPU). Default keeps single-GPU behaviour byte-identical.
int64_t g_weight_cache_budget = 0;
static bool g_weight_cache_retention = false; // RAWRXD_G04: residency budget pin, applied at first init
std::atomic<GpuInitializationState> g_primary_gpu_state{
    GpuInitializationState::Pending};

VulkanCompute& Gpu()
{
    static VulkanCompute gpu;              // one device for the process
    static std::once_flag init_once;
    std::call_once(init_once, [&]() {
        g_primary_gpu_state.store(GpuInitializationState::Initializing,
                                  std::memory_order_release);
        // STRATA_S05: honour a device pin requested before the first dispatch.
        gpu.SetPreferredDeviceIndex(g_preferred_device);
        // RAWRXD_G04: honour a residency-budget pin requested before the first
        // dispatch (0 keeps the derived default).
        gpu.SetQuantWeightBudgetBytes((size_t)g_weight_cache_budget);
        const bool initialized = gpu.Initialize();
        if (!initialized) {
            // Initialize() may have created an instance or device before a
            // later stage failed.  Release that partial context immediately;
            // a call_once failure must never leave live Vulkan handles behind.
            gpu.Cleanup();
        }
        g_primary_gpu_state.store(
            initialized ? GpuInitializationState::Ready
                       : GpuInitializationState::Failed,
            std::memory_order_release);
    });
    return gpu;
}

// RAWRXD_MULTI_GPU: a SECOND (or Nth) device context for one process. The
// primary Gpu() above is unchanged (its device = g_preferred_device, default
// score-select) so single-GPU behaviour is byte-for-byte preserved. GpuFor
// lazily creates one VulkanCompute per requested device index; a device index
// < 0 or equal to the primary pin delegates to Gpu(). Fails closed (throws) if
// a requested device cannot be initialised - the caller turns that into a CPU
// fallback with a receipt, never silent success.
VulkanCompute& GpuFor(int32_t device_index)
{
    const int32_t key = (device_index < 0) ? g_preferred_device : device_index;
    if (key < 0 || key == g_preferred_device) return Gpu();
    static std::mutex reg_mu;
    static std::map<int32_t, std::unique_ptr<VulkanCompute>> registry;
    std::lock_guard<std::mutex> lk(reg_mu);
    auto it = registry.find(key);
    if (it != registry.end()) return *it->second;
    auto vk = std::make_unique<VulkanCompute>();
    vk->SetPreferredDeviceIndex(key);
    if (g_weight_cache_budget > 0) vk->SetQuantWeightBudgetBytes((size_t)g_weight_cache_budget);
    if (!vk->Initialize())
        throw std::runtime_error("GpuFor: device init failed");
    VulkanCompute& ref = *vk;
    registry.emplace(key, std::move(vk));
    return ref;
}


// Packed row stride per kind (same geometry the shader and ExecuteQuantDot
// use). Legacy kinds quantise 32 values per block; the k-quants 256.
// 0=Q4_K(144) 1=Q6_K(210) 5=Q2_K(84) 6=Q3_K(110) 8=Q5_K(176);
// 2..4 = legacy 32-value.
size_t RowBytesForKind(int kind, size_t n_in)
{
    if (kind == 5) return ((n_in + 255u) / 256u) * 84u;    // Q2_K
    if (kind == 6) return ((n_in + 255u) / 256u) * 110u;   // Q3_K
    if (kind == 8) return ((n_in + 255u) / 256u) * 176u;   // Q5_K
    if (kind == 7) return ((n_in + 63u) / 64u) * 36u;      // NVFP4: 64 elems per 36-byte block
    switch (kind) {
    case 0: return ((n_in + 255u) / 256u) * 144u;               // Q4_K
    case 1: return ((n_in + 255u) / 256u) * 210u;               // Q6_K
    case 2: return ((n_in + 31u) / 32u) * 22u;         // Q5_0
    case 3: return ((n_in + 31u) / 32u) * 34u;         // Q8_0
    default: return ((n_in + 31u) / 32u) * 18u;        // Q4_0
    }
}

// Serialises the batch state and the device fast path. DotBlocked's own
// dispatch is unchanged; only the batch begin/queue/end sequence locks.
std::mutex g_gpu_mutex;

// ---- batch mode (RAWRXD_DEEP2_LEGACY_QUANT_GPU_001) --------------------------
// DotBlocked defers instead of executing: the caller begins a batch, queues
// the dots whose outputs it will only read after EndBatch, and ends it. The
// queued dots run inside ONE command buffer behind ONE fence, so a MoE block
// pays one submission instead of 2*selected. Queued dots MUST NOT have their
// output consumed before EndBatch: the batch is not a dependency resolver.
struct QueuedDot {
    int kind;
    const void* packed;
    size_t packed_bytes;
    std::vector<float> q8_storage;   // OWNED copy of the activation bytes
    const void* q8;                  // points into q8_storage (never dangling)
    size_t q8_bytes;
    void* out;
    size_t out_bytes;
    size_t n_out;
    size_t n_in;
    CpuDot cpu;
};
thread_local bool g_batch_active = false;
thread_local std::vector<QueuedDot> g_queued;

// RAWRXD_DEEP2_BATCH_SYNC_AUDIT (Sprint9 P0).
//
// g_batch_active and g_queued describe ONE logical resource: the open batch and
// the dots queued into it. They must therefore share ONE mutex. Before this fix
// the begin/end sequence locked g_gpu_mutex while DotBlocked mutated g_queued
// with no lock at all, which is a data race on the vector (push_back racing
// swap/clear) and a check-then-act race on the flag: two threads could both
// observe false, both open a device batch, and the second g_queued.clear() then
// erased the first thread's already-queued dots. Their callers had been told
// "queued", so the outputs were never written and the loss was silent.
//
// g_batch_mutex is held only for O(1) bookkeeping plus the activation copy, so
// producers never block on the GPU: device submission stays under g_gpu_mutex.
// Lock order is always g_batch_mutex -> g_gpu_mutex and never the reverse, so no
// path can deadlock.
std::mutex g_batch_mutex;

// Batch accounting. Every accepted dot must reach exactly one terminal outcome:
//     accepted == completed + failed + pending
// with pending == 0 once EndBatch has returned. A queued dot is "accepted", not
// "completed": only a chunk that actually reached the device increments
// completed, and a dot replayed on the CPU fallback increments failed.
struct BatchStats {
    uint64_t accepted = 0;
    uint64_t completed = 0;
    uint64_t failed = 0;
    uint64_t batches_opened = 0;
    uint64_t device_batches_opened = 0;   // real Gpu().BeginQuantDotBatch() calls
};
BatchStats g_batch_stats;
uint64_t g_active_batch_count = 0;
uint64_t g_pending_queued_count = 0;

// Implementation of the public BeginBatch: opens a logical batch for this
// executor thread. Device ownership is acquired only while EndBatch submits;
// independent executor threads may therefore collect work concurrently while
// g_gpu_mutex still serializes access to the single Vulkan context.
bool BeginBatchImpl()
{
    // Differential execution consumes every result immediately.  Keep the
    // executor's logical batch bookkeeping alive, but do not open the device
    // batch: DotBlocked must execute synchronously so the checker sees the
    // freshly written output rather than a queued zero.  EndBatchImpl treats
    // the matching logical close as a no-op below.
    if (std::getenv("RR_GPU_CHECK")) return true;
    // P0: the ownership check and the claim are one critical section. The
    // logical state is thread-local, so this rejects only nested batches on the
    // same executor while allowing independent executors to collect work.
    std::lock_guard<std::mutex> bk(g_batch_mutex);
    if (g_batch_active) return false;
    g_batch_active = true;
    g_queued.clear();
    ++g_batch_stats.batches_opened;
    ++g_active_batch_count;
    return true;
}

// Fail-closed replay: if the batched submission itself cannot be produced, run
// every queued dot through the supplied CPU fallback - the identical path a
// single DotBlocked call takes when the GPU is unavailable - and set the
// receipt so the caller accounts a CPU run. Nothing is silently substituted.
void ReplayRangeOnCpu(std::vector<QueuedDot>& qs, size_t from)
{
    // from == qs.size() means nothing is replayed (every chunk already ran on the
    // device). Replaying a completed chunk would execute its dots twice and
    // corrupt the outputs, so error recovery must be range-bounded.
    for (size_t i = from; i < qs.size(); ++i) {
        const QueuedDot& e = qs[i];
        const size_t rb = RowBytesForKind(e.kind, e.n_in);
        float* out = static_cast<float*>(e.out);
        for (size_t j = 0; j < e.n_out; ++j) {
            const uint8_t* row =
                static_cast<const uint8_t*>(e.packed) + j * rb;
            out[j] = e.cpu(row, e.q8, j);
        }
        g_receipt.cpu_rows += e.n_out;
    }
    if (!g_receipt.fallback_reason)
        g_receipt.fallback_reason = "quant-dot batch failed; CPU replay";
}

void ReplayQueuedOnCpu(std::vector<QueuedDot>& qs)
{
    ReplayRangeOnCpu(qs, 0);
    g_receipt.used_gpu = false;
}

// Implementation of the public EndBatch: submits every queued dot in one
// command buffer behind one fence and copies the results to the caller buffers.
bool EndBatchImpl()
{
    // P0: the ownership check, the flip and the queue swap are one critical
    // section under the same mutex that guards push_back. Flipping the flag to
    // false IS the closing transition: a producer that acquires the mutex after
    // this point observes "closed" and executes synchronously instead of
    // appending to a queue that is about to be submitted. No accepted dot can be
    // lost between the close and the submission.
    std::vector<QueuedDot> qs;
    {
        std::lock_guard<std::mutex> lk(g_batch_mutex);
        if (!g_batch_active) {
            // Differential-check mode opens no device batch, so a matching close is
            // a no-op success. Any other unmatched close is a caller error.
            return std::getenv("RR_GPU_CHECK") != nullptr;
        }
        g_batch_active = false;
        if (g_active_batch_count > 0) --g_active_batch_count;
        const size_t queued_count = g_queued.size();
        if (queued_count <= g_pending_queued_count)
            g_pending_queued_count -= queued_count;
        else
            g_pending_queued_count = 0;
        qs.swap(g_queued);
    }
    // Device work is serialized by g_gpu_mutex alone: producers never block on
    // the GPU, and no two threads touch the device at once. The logical batch
    // was detached above, so the device-level batch is opened and closed within
    // this critical section and cannot leak across executor lifetimes.
    std::lock_guard<std::mutex> lk(g_gpu_mutex);
    if (qs.empty()) {
        // Preserve the real device lifecycle even for an empty logical batch.
        // This catches a close failure instead of reporting a false success.
        if (!PrimaryGpuReady() || !Gpu().BeginQuantDotBatch()) {
            g_receipt = Receipt{};
            g_receipt.used_gpu = false;
            QDTRACE_DISPATCH("EndBatch empty-begin ok=0");
            return false;
        }
        {
            std::lock_guard<std::mutex> slk(g_batch_mutex);
            ++g_batch_stats.device_batches_opened;
        }
        const bool closed = Gpu().EndQuantDotBatch();
        g_receipt = Receipt{};
        g_receipt.used_gpu = false;
        QDTRACE_DISPATCH("EndBatch empty-close ok=" << (int)closed);
        return closed;
    }
    QDTRACE_DISPATCH("EndBatch queued=" << qs.size());
    // RAWRXD_DEEP2_MOE_BATCH_CHUNK_001. One device batch holds BatchCapacity()
    // descriptor sets. A MoE block queues one dot per selected expert, so a
    // 199-expert model asks for 199 entries and entry 32 was rejected before any
    // submission, collapsing the whole block to CPU replay. Split the list into
    // capacity-sized chunks and submit each one behind its own fence. The first
    // chunk uses the device batch opened below; later chunks reopen it.
    const size_t cap = BatchCapacity();
    const size_t chunk = cap ? cap : qs.size();
    bool ok = true;
    size_t total_rows = 0;
    size_t fail_index = 0;
    const char* fail_stage = nullptr;
    size_t replay_from = qs.size();   // nothing to replay until a chunk fails
    size_t chunks_ok = 0;
    if (!PrimaryGpuReady() || !Gpu().BeginQuantDotBatch()) {
        ok = false;
        fail_stage = "begin";
        fail_index = qs.size();
        replay_from = 0;
    } else {
        std::lock_guard<std::mutex> slk(g_batch_mutex);
        ++g_batch_stats.device_batches_opened;
    }
    for (size_t base = 0; base < qs.size() && ok; base += chunk) {
        const size_t end = (qs.size() - base) < chunk ? qs.size() : base + chunk;
        if (base > 0 && !Gpu().BeginQuantDotBatch()) {
            ok = false;
            fail_stage = "begin";
            fail_index = qs.size();
            replay_from = base;
            break;
        }
        if (base > 0) {
            std::lock_guard<std::mutex> slk(g_batch_mutex);
            ++g_batch_stats.device_batches_opened;
        }
        for (size_t i = base; i < end; ++i) {
            const QueuedDot& e = qs[i];
            const bool queued_ok =
                Gpu().QueueQuantDot(e.packed, e.packed_bytes, e.q8, e.q8_bytes,
                                    e.out, e.out_bytes, e.n_out, e.n_in, e.kind);
            if (!queued_ok) {
                ok = false;
                fail_index = i;
                fail_stage = "queue";
                replay_from = base;
                break;
            }
            total_rows += e.n_out;
        }
        if (!ok) break;
        QDTRACE_DISPATCH("EndBatch chunk base=" << base << " count=" << (end - base));
        if (!Gpu().EndQuantDotBatch()) {
            ok = false;
            fail_stage = "end";
            fail_index = qs.size();
            replay_from = base;
            break;
        }
        ++chunks_ok;
    }
    QDTRACE_DISPATCH("EndBatch done ok=" << (int)ok << " chunks_ok=" << chunks_ok);
    g_receipt = Receipt{};
    // used_gpu stays true when earlier chunks already ran on the device, even if a
    // later chunk failed: those rows were really computed there and must not be
    // double-executed by the replay below.
    g_receipt.used_gpu = (chunks_ok > 0);
    g_receipt.gpu_rows = total_rows;
    // P0 accounting: dots in chunks that reached the device are completed; the
    // failing chunk and everything after it are replayed on the CPU and are
    // therefore failed, not completed. pending is zero by construction because the
    // queue was swapped out before submission and the flag already reads closed.
    {
        std::lock_guard<std::mutex> stats_lk(g_batch_mutex);
        const size_t done = ok ? qs.size() : replay_from;
        g_batch_stats.completed += done;
        g_batch_stats.failed += qs.size() - done;
    }
    if (ok) return true;
    // Record which stage and which entry failed BEFORE the replay overwrites the
    // receipt, and name the failing geometry. A rejected queue configuration and a
    // failed submission need different repairs, and this is the only place that
    // can tell them apart.
    {
        const QueuedDot* bad = nullptr;
        if (fail_stage && fail_index < qs.size()) bad = &qs[fail_index];
        g_receipt.fail_stage = fail_stage;
        g_receipt.fail_index = fail_index;
        g_receipt.batch_entries = qs.size();
        if (bad) {
            g_receipt.fail_kind = bad->kind;
            g_receipt.fail_n_in = bad->n_in;
            g_receipt.fail_n_out = bad->n_out;
            g_receipt.fail_packed_bytes = bad->packed_bytes;
            g_receipt.fail_q8_bytes = bad->q8_bytes;
            g_receipt.fail_out_bytes = bad->out_bytes;
        }
        std::printf("MOE_UP_BATCH_FAIL stage=%s index=%zu/%zu kind=%d n_in=%zu n_out=%zu "
                    "packed_bytes=%zu q8_bytes=%zu out_bytes=%zu chunk=%zu chunks_ok=%zu "
                    "replay_from=%zu\n",
                    fail_stage ? fail_stage : "unknown", fail_index, qs.size(),
                    bad ? bad->kind : -1, bad ? bad->n_in : 0, bad ? bad->n_out : 0,
                    bad ? bad->packed_bytes : 0, bad ? bad->q8_bytes : 0,
                    bad ? bad->out_bytes : 0, chunk, chunks_ok, replay_from);
        std::fflush(stdout);
    }
    // Only the failing chunk is replayed. Entries belonging to chunks that already
    // submitted are left with their GPU results.
    ReplayRangeOnCpu(qs, replay_from);
    return false;
}

} // namespace

// RAWRXD_G04: read the residency-safety observability off the device that
// actually served the run, so a certificate never mixes two GPUs' counters.
// Declared after Gpu()/GpuFor() because unqualified lookup in a free function
// body does not see names declared later in the same namespace.
namespace {
uint64_t QuantDot_DevicePinned() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).PinnedWeightCount();
}
uint64_t QuantDot_DeviceLeases() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).OutstandingWeightLeases();
}
uint64_t QuantDot_DeviceRetiredPending() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).RetiredWeightCount();
}
uint64_t QuantDot_DeviceRetiredReaped() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).RetiredWeightsReaped();
}
uint64_t QuantDot_DeviceBudgetOverrides() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).BudgetOverrides();
}
uint64_t QuantDot_DeviceEpoch() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).WeightResidencyEpoch();
}
uint64_t QuantDot_DeviceCompletedEpoch() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).CompletedWeightEpoch();
}
} // namespace

// Public batch API. A batch collects DotBlocked calls that queues up while it
// is open and executes them in ONE submission: a MoE block then costs two
// submits (up-dots, then down-dots) instead of one per expert dot.
//   * Queue ONLY dots whose output is not read until EndBatch returns; the
//     batch is not a dependency resolver.
//   * Batch does not nest; EndBatch of an empty batch succeeds trivially.
//   * On failure every queued dot is replayed on the supplied CPU fallback and
//     EndBatch returns false, so the caller accounts a CPU run.
bool BeginBatch()
{
    return BeginBatchImpl();
}

bool EndBatch()
{
    return EndBatchImpl();
}

#if defined(RAWRXD_QUANT_DOT_TEST_HOOKS)
bool InjectEndBatchFailureForTest()
{
    Gpu().InjectQuantDotEndFailureForTest();
    return true;
}
#endif

bool BeginFusedLayer()
{
    return Gpu().BeginFusedLayer();
}
bool EndFusedLayer()
{
    return Gpu().EndFusedLayer();
}
bool ForceHostSync()
{
    return Gpu().ForceHostSync();
}
bool FusedRecording()
{
    return Gpu().FusedRecording();
}

bool AttnDecodeGqa(const float* q, size_t q_floats,
                   const float* k_cache, size_t k_floats,
                   const float* v_cache, size_t v_floats,
                   float* out, size_t out_floats,
                   uint32_t head_dim, uint32_t heads, uint32_t kv_heads,
                   uint32_t seq_len, float scale)
{
    if (!PrimaryGpuReady()) return false;
    return Gpu().ExecuteAttnDecodeGqa(
        q, q_floats, k_cache, k_floats, v_cache, v_floats,
        out, out_floats, head_dim, heads, kv_heads, seq_len, scale);
}

void SetForceCpu(bool force) { g_force_cpu = force; }
bool ForceCpu() { return g_force_cpu; }

// RAWRXD_MULTI_GPU: set the Vulkan device index for subsequent quant/f16 dots
// in THIS call path (-1 restores the default primary device). Lets a
// split-model executor route a block's ops to a specific GPU while every
// single-GPU caller that never sets this keeps the exact existing behaviour.
void SetActiveDevice(int32_t device) { g_active_device = device; }
int32_t ActiveDevice() { return g_active_device; }

bool IsWeightResident(const void* packed, size_t bytes, int kind) {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).IsQuantWeightResident(packed, bytes, kind);
}

bool PrefetchWeight(const void* packed, size_t bytes, int kind) {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).PrefetchQuantWeight(packed, bytes, kind);
}

// RAWRXD_G04: a residency lease is a *reference*, so it is applied to the same
// device the corresponding dispatches use (the active override when set).
uint64_t AcquireWeightLease(const void* packed, size_t bytes, int kind) {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu()).AcquireWeightLease(packed, bytes, kind);
}

void ReleaseWeightLease(uint64_t lease_id) {
    if (!lease_id) return;
    // A lease is device-scoped; releasing through the device that may have
    // issued it is always safe (an unknown id is a no-op there).
    if (g_active_device >= 0) GpuFor(g_active_device).ReleaseWeightLease(lease_id);
    Gpu().ReleaseWeightLease(lease_id);
}

void SetCachePolicy(int policy) {
    Gpu().SetWeightCachePolicy(policy == 1 ? 1 : 0);
}

size_t TrimUnpinnedQuantWeights() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu())
        .TrimUnpinnedQuantWeights();
}

// RAWRXD_G04: the budget is a device-lifetime setting resolved on first use, so
// it is recorded here and applied by Gpu()/GpuFor() at initialisation, exactly
// like SetPreferredDevice's device pin.
void SetWeightCacheBudget(int64_t bytes) { g_weight_cache_budget = bytes; }
void SetWeightCacheRetention(bool enabled) { g_weight_cache_retention = enabled; }
bool WeightCacheRetention() { return g_weight_cache_retention; }

// RAWRXD_G04: expose the device the dispatcher actually uses, so gates can
// drive device-level residency primitives on that same context.
VulkanCompute& DispatchDevice(int32_t device) {
    if (device < 0) return (g_active_device >= 0) ? GpuFor(g_active_device) : Gpu();
    const int32_t key = (device < 0) ? g_preferred_device : device;
    return (key >= 0 && key != g_preferred_device) ? GpuFor(key) : Gpu();
}

CacheStats GetCacheStats() {
    const GpuCounters& c = Gpu().GetGpuCounters();
    CacheStats s;
    s.hits = c.weight_cache_hits;
    s.misses = c.weight_cache_misses;
    s.evictions = c.weight_cache_evictions;
    s.evictions_budget = c.weight_cache_evictions_budget;
    s.evictions_trim = c.weight_cache_evictions_trim;
    s.prefetches = c.weight_prefetches;
    s.prefetch_hits = c.weight_prefetch_hits;
    s.upload_bytes = c.upload_bytes;
    s.download_bytes = c.download_bytes;
    s.device_bytes_live = c.device_bytes_live;
    s.device_bytes_peak = c.device_bytes_peak;
    s.submits = c.submits;
    s.waits = c.waits;
    s.kernel_ms = c.kernel_ms;
    s.submit_ms = c.submit_ms;
    s.wait_ms = c.wait_ms;
    // RAWRXD_G04: residency-safety observability (primary device).
    s.pinned = QuantDot_DevicePinned();
    s.leases = QuantDot_DeviceLeases();
    s.retired_pending = QuantDot_DeviceRetiredPending();
    s.retired_reaped = QuantDot_DeviceRetiredReaped();
    s.budget_overrides = QuantDot_DeviceBudgetOverrides();
    s.epoch = QuantDot_DeviceEpoch();
    s.completed_epoch = QuantDot_DeviceCompletedEpoch();
    return s;
}

// RAWRXD_MULTI_GPU: per-device counters for a SECONDARY device (via GpuFor),
// so a split-model run can prove the content GPU actually dispatched. device<0
// or == the primary pin returns the primary counters.
CacheStats GetCacheStatsOn(int32_t device) {
    const int32_t key = (device < 0) ? g_preferred_device : device;
    const GpuCounters& c = (key >= 0 && key != g_preferred_device)
                               ? GpuFor(key).GetGpuCounters()
                               : Gpu().GetGpuCounters();
    CacheStats s;
    s.hits = c.weight_cache_hits;
    s.misses = c.weight_cache_misses;
    s.evictions = c.weight_cache_evictions;
    s.evictions_budget = c.weight_cache_evictions_budget;
    s.evictions_trim = c.weight_cache_evictions_trim;
    s.prefetches = c.weight_prefetches;
    s.prefetch_hits = c.weight_prefetch_hits;
    s.upload_bytes = c.upload_bytes;
    s.download_bytes = c.download_bytes;
    s.device_bytes_live = c.device_bytes_live;
    s.device_bytes_peak = c.device_bytes_peak;
    s.submits = c.submits;
    s.waits = c.waits;
    s.kernel_ms = c.kernel_ms;
    s.submit_ms = c.submit_ms;
    s.wait_ms = c.wait_ms;
    // RAWRXD_G04: the SECONDARY device's residency-safety counters. The accessor
    // resolves the requested device, not the active per-op override, so a split
    // run can certify each GPU independently.
    s.pinned = GpuFor(key).PinnedWeightCount();
    s.leases = GpuFor(key).OutstandingWeightLeases();
    s.retired_pending = GpuFor(key).RetiredWeightCount();
    s.retired_reaped = GpuFor(key).RetiredWeightsReaped();
    s.budget_overrides = GpuFor(key).BudgetOverrides();
    s.epoch = GpuFor(key).WeightResidencyEpoch();
    s.completed_epoch = GpuFor(key).CompletedWeightEpoch();
    return s;
}

void SetPreferredDevice(int index) {
    // Applied by Gpu() at first initialisation; calling this after the first
    // dispatch has no effect (the device already exists).
    g_preferred_device = (int32_t)index;
}

GpuInitializationState PrimaryGpuInitializationState() {
    Gpu();
    return g_primary_gpu_state.load(std::memory_order_acquire);
}

bool PrimaryGpuReady() {
    return PrimaryGpuInitializationState() == GpuInitializationState::Ready;
}

size_t BatchCapacity() {
    // kQuantBatchMaxSets: the descriptor ring bounds one batch. Reported, not
    // asserted, so callers can chunk instead of failing closed.
    return Gpu().QuantDotBatchCapacity();
}

const Receipt& LastReceipt() { return g_receipt; }

// RAWRXD_DEEP2_BATCH_SYNC_AUDIT (Sprint9 P0). Coherent observation of the batch
// lifecycle counters. Read under the same mutex that guards the queue, so a
// snapshot can never observe a half-applied begin/end transition.
BatchAccounting BatchAccountingSnapshot()
{
    std::lock_guard<std::mutex> lk(g_batch_mutex);
    BatchAccounting a;
    a.accepted = g_batch_stats.accepted;
    a.completed = g_batch_stats.completed;
    a.failed = g_batch_stats.failed;
    a.batches_opened = g_batch_stats.batches_opened;
    a.device_batches_opened = g_batch_stats.device_batches_opened;
    a.batch_active = g_batch_active;
    a.queued = g_queued.size();
    a.active_batches = g_active_batch_count;
    a.pending_queued = g_pending_queued_count;
    return a;
}

const BackendStats& BackendCounters() {
    const GpuCounters& c = Gpu().GetGpuCounters();
    g_backend.buffer_allocations = c.buffer_allocations;
    g_backend.descriptor_allocations = c.descriptor_allocations;
    g_backend.descriptor_reuses = c.descriptor_reuses;
    g_backend.descriptor_alloc_attempts = c.descriptor_alloc_attempts;
    g_backend.descriptor_alloc_failures = c.descriptor_alloc_failures;
    g_backend.descriptor_pool_creates = c.descriptor_pool_creates;
    g_backend.descriptor_pool_resets = c.descriptor_pool_resets;
    g_backend.descriptor_sets_in_flight = c.descriptor_sets_in_flight;
    g_backend.descriptor_sets_peak = c.descriptor_sets_peak;
    g_backend.submits = c.submits;
    g_backend.waits = c.waits;
    g_backend.upload_bytes = c.upload_bytes;
    g_backend.download_bytes = c.download_bytes;
    g_backend.weight_cache_hits = c.weight_cache_hits;
    g_backend.weight_cache_misses = c.weight_cache_misses;
    g_backend.device_bytes_live = c.device_bytes_live;
    g_backend.device_bytes_peak = c.device_bytes_peak;
    g_backend.kernel_ms = c.kernel_ms;
    g_backend.submit_ms = c.submit_ms;
    g_backend.wait_ms = c.wait_ms;
    g_backend.gpu_ms = c.gpu_ms;
    return g_backend;
}

bool DotF16(const void* wBytes, size_t wBytesCount,
            const float* x, size_t n_in,
            float* y, size_t n_out,
            const CpuDot& cpu,
            bool force_cpu)
{
    g_receipt = Receipt{};
    if (!wBytes || !x || !y || n_in == 0 || n_out == 0) {
        g_receipt.fallback_reason = "bad arguments";
        return false;
    }
    if (!cpu) {
        g_receipt.fallback_reason = "no CPU fallback supplied";
        return false;
    }
    // The kernel reads fp16 weights as uint32 word pairs.
    if ((n_in % 2u) != 0 || reinterpret_cast<uintptr_t>(wBytes) % 4u != 0) {
        g_receipt.fallback_reason = "f16: n_in odd or weight bytes misaligned";
        return false;
    }
    if (wBytesCount < n_out * n_in * sizeof(uint16_t)) {
        g_receipt.fallback_reason = "f16: weight bytes short";
        return false;
    }
    if (!g_force_cpu && !force_cpu && PrimaryGpuReady()) {
        std::lock_guard<std::mutex> lk(g_gpu_mutex);
        VulkanCompute& gpu = (g_active_device >= 0) ? GpuFor(g_active_device) : Gpu();
        if (gpu.ExecuteF16Dot(wBytes, wBytesCount, x, n_in, y,
                                 n_out * sizeof(float), n_out)) {
            g_receipt.used_gpu = true;
            g_receipt.gpu_rows = n_out;
            return true;
        }
    }
    // CPU fallback: the caller decodes one packed fp16 row at a time (ggml's
    // own conversion) and dots it against the same raw activation.
    const size_t row_bytes = n_in * sizeof(uint16_t);
    for (size_t j = 0; j < n_out; ++j) {
        const uint8_t* row = static_cast<const uint8_t*>(wBytes) + j * row_bytes;
        y[j] = cpu(row, nullptr, j);
    }
    g_receipt.used_gpu = false;
    g_receipt.cpu_rows = n_out;
    g_receipt.fallback_reason = (force_cpu || g_force_cpu) ? "force_cpu" : "f16 dot: gpu unavailable";
    return false;
}

bool DotBlocked(int kind,
                const void* wBytes, size_t wBytesCount,
                const float* x, size_t n_in,
                float* y, size_t n_out,
                const CpuDot& cpu,
                const void* q8_interleaved,
                size_t q8_bytes,
                bool force_cpu)
{
    // kind: 0 = Q4_K, 1 = Q6_K, 2 = Q5_0, 3 = Q8_0, 4 = Q4_0,
    //       5 = Q2_K, 6 = Q3_K, 7 = NVFP4, 8 = Q5_K.
    // Q5_K is deliberately a separate capability id: GGML type ids and
    // dispatch capability ids are different domains, and kind 8 must not be
    // confused with the GGML Q8_0 type id.
    if (kind < 0 || kind > 8) {
        g_receipt.fallback_reason = "unsupported kind";
        return false;
    }
    if (!wBytes || !x || !y || n_in == 0 || n_out == 0) {
        g_receipt.fallback_reason = "bad arguments";
        return false;
    }
    if (cpu == nullptr) {
        g_receipt.fallback_reason = "no CPU fallback supplied";
        return false;
    }
    // NVFP4 requires 64 elements per block (36-byte block: 32 packed + 4 scale).
    if (kind == 7 && (n_in % 64u) != 0) {
        g_receipt.fallback_reason = "nvfp4: n_in not a multiple of 64";
        return false;
    }
    // Packed row stride and activation super-block count per kind. The legacy
    // kinds quantise 32 values per block, so a row is ceil(n_in/32) blocks and
    // the 256-value Q8 activation carries ceil(n_in/256) super-blocks (the
    // last one is partial when n_in % 256 != 0).
    const bool legacy = (kind >= 2);
    if (legacy && (n_in % 32u) != 0) {
        g_receipt.fallback_reason = "legacy kind with n_in not a multiple of 32";
        return false;
    }
    const size_t row_bytes = legacy ? RowBytesForKind(kind, n_in)
                                   : (kind == 0 ? (n_in / 256u) * 144u : (n_in / 256u) * 210u);
    const size_t n_sb = legacy ? (n_in + 255u) / 256u : (n_in / 256u);

    // ---- batched (deferred) mode -------------------------------------------
    // Inside a batch the dot is queued instead of executed: all queued dots run
    // in ONE submission behind ONE fence (see BeginBatch/EndBatch). The caller
    // contract is that the output is not read until EndBatch returns, and that
    // a caller-pinned CPU call never queues. The receipt reports the GPU path
    // as committed; the batch's own success/failure is reported by EndBatch and
    // accounted by the caller.
    // The per-op differential checker consumes `y` immediately after this
    // call.  It deliberately disables executor-side batch joining, so a dot
    // must execute synchronously even if a surrounding graph opened a batch
    // for other operations.  Queueing here would return true with an
    // untouched zero-filled output and report a false GPU divergence before
    // EndBatch has a chance to submit the work.
    const bool differential_check = std::getenv("RR_GPU_CHECK") != nullptr;
    // P0: no unsynchronised reads of the batch state remain. The trace only needs
    // an advisory snapshot; the queuing decision re-checks under the mutex.
    bool batch_active_snapshot = false;
    {
        std::lock_guard<std::mutex> lk(g_batch_mutex);
        batch_active_snapshot = g_batch_active;
    }
    if (std::getenv("DEEP2_SUBMIT_TRACE") &&
        !(batch_active_snapshot && !differential_check && g_active_device < 0 &&
          !force_cpu && !g_force_cpu)) {
        std::fprintf(stderr,
            "SUBMIT_TRACE kind=DotBlocked mode=SYNC n_out=%zu "
            "dependency=HOST_READBACK necessary=1\n",
            n_out);
        std::fflush(stderr);
    }
    // Q4_K batch descriptors currently share a packed activation arena with
    // per-entry offsets. Keep Q4_K on the synchronous path until that arena
    // contract is proven against real model projections; the synchronous path
    // has independent upload/barrier/readback ownership and is numerically
    // verified. Do not return a queued result for Q4_K while its output is not
    // yet trustworthy.
    //
    // P0: the eligibility test, the owned activation copy and the push_back are
    // one critical section. Deciding from an unlocked read and pushing afterwards
    // is exactly the interleaving that let EndBatch swap the queue between the two
    // steps and silently drop the dot. A dot that observes the batch closed now
    // falls through to the synchronous path instead of vanishing.
    bool queued = false;
    {
        std::lock_guard<std::mutex> lk(g_batch_mutex);
        if (g_batch_active && kind != 0 && !differential_check && g_active_device < 0 &&
            !force_cpu && !g_force_cpu) {
            if (!q8_interleaved) {
                g_receipt.fallback_reason = "batch queue without a Q8 activation buffer";
                return false;
            }
            QueuedDot qd;
            qd.kind = kind;
            qd.packed = wBytes;
            qd.packed_bytes = wBytesCount;
            // OWN the activation bytes: the caller's buffer may a per-expert local
            // that does not outlive the loop iteration (the MoE down-phase does
            // exactly that), and the dot only executes at EndBatch.
            if (q8_bytes % sizeof(float) != 0) {
                g_receipt.fallback_reason = "batch queue with a misaligned activation buffer";
                return false;
            }
            qd.q8_storage.resize(q8_bytes / sizeof(float));
            std::memcpy(qd.q8_storage.data(), q8_interleaved, q8_bytes);
            qd.q8 = qd.q8_storage.data();
            qd.q8_bytes = q8_bytes;
            qd.out = y;
            qd.out_bytes = n_out * sizeof(float);
            qd.n_out = n_out;
            qd.n_in = n_in;
            qd.cpu = cpu;
            g_queued.push_back(std::move(qd));
            ++g_batch_stats.accepted;
            ++g_pending_queued_count;
            queued = true;
        }
    }
    if (queued) {
        // "queued" reports ACCEPTANCE only. It is not evidence of GPU completion:
        // EndBatch decides that and overwrites the receipt.
        g_receipt.used_gpu = true;
        g_receipt.queued = true;
        g_receipt.gpu_rows = n_out;
        return true;
    }

    // The caller wants the CPU path (parity harness). Either the process-wide
    // override or this call's explicit pin counts.
    if (g_force_cpu || force_cpu) {
        // CpuDot's contract is (row, q8_act, rowIndex): it decodes the
        // INTERLEAVED Q8_K activation, not the raw float vector. Passing the
        // raw activation here made every CPU fallback read x[b*273] for
        // b = 0..n_in/256-1, which for n_in=4096 walks 4351 floats past a
        // 4096-element buffer and returns garbage. When no Q8 buffer was
        // supplied there is no correct CPU path, so fail closed.
        if (!q8_interleaved) {
            g_receipt.fallback_reason = "force_cpu without a Q8 activation buffer";
            return false;
        }
        for (size_t j = 0; j < n_out; ++j) {
            const uint8_t* row =
                static_cast<const uint8_t*>(wBytes) + j * row_bytes;
            y[j] = cpu(row, q8_interleaved, j);
        }
    g_receipt.used_gpu = false;
        g_receipt.cpu_rows = n_out;
        g_receipt.fallback_reason = "force_cpu";
        return false;
    }

    // GPU path. The packed kernel is proven; a dispatch failure is reported.
    VulkanCompute* gpu = nullptr;
    if (g_active_device >= 0) {
        try {
            gpu = &GpuFor(g_active_device);
        } catch (const std::exception& e) {
            g_receipt.fallback_reason = e.what();
        }
    } else if (PrimaryGpuReady()) {
        gpu = &Gpu();
    }
    const bool gpuOk = gpu && q8_interleaved && q8_bytes >= n_sb * 273u * sizeof(float)
        ? gpu->ExecuteQuantDot(wBytes, wBytesCount,
                               q8_interleaved, q8_bytes,
                               y, n_out * sizeof(float),
                               n_out, n_in, n_sb, kind)
        : false;
    if (gpuOk) {
        g_receipt.used_gpu = true;
        g_receipt.gpu_rows = n_out;
        return true;
    }

    // GPU unavailable: use the CPU fallback so the caller still gets real math.
    // It decodes the same interleaved Q8 layout the shader was handed, so the
    // two paths stay numerically comparable.
    if (!q8_interleaved) {
        // NVFP4 (kind 7): decode packed FP4 weights directly without Q8 activation buffer.
        if (kind == 7) {
            static const float nvfp4_values[16] = {
                0.0f, 0.5f, 1.0f, 1.5f, 2.0f, 3.0f, 4.0f, 6.0f,   // sign=0
               -0.0f,-0.5f,-1.0f,-1.5f,-2.0f,-3.0f,-4.0f,-6.0f   // sign=1
            };
            for (size_t j = 0; j < n_out; ++j) {
                const uint8_t* row = static_cast<const uint8_t*>(wBytes) + j * row_bytes;
                float acc = 0.0f;
                for (size_t c = 0; c < n_in; ++c) {
                    int block_idx = c / 64;
                    int in_block = c % 64;
                    // Bounds check: block must fit in wBytes
                    if ((size_t)(block_idx + 1) * 36 > wBytesCount) {
                        g_receipt.fallback_reason = "nvfp4: block index out of bounds";
                        return false;
                    }
                    uint8_t byte = row[block_idx * 36 + in_block / 2];
                    uint8_t nibble = (in_block % 2 == 0) ? (byte >> 4) : (byte & 0xF);
                    int scale_idx = in_block / 16;
                    uint8_t scale_byte = row[block_idx * 36 + 32 + scale_idx];
                    // NVFP4 scale uses the same FP4 E2M1 encoding; mask to low nibble.
                    float w = nvfp4_values[nibble] * nvfp4_values[scale_byte & 0xF];
                    acc += w * x[c];
                }
                y[j] = acc;
            }
            g_receipt.used_gpu = false;
            g_receipt.cpu_rows = n_out;
            g_receipt.fallback_reason = "nvfp4 cpu fallback";
            return false;
        }
        g_receipt.fallback_reason = "gpu unavailable and no Q8 activation buffer";
        return false;
    }
    for (size_t j = 0; j < n_out; ++j) {
        const uint8_t* row =
            static_cast<const uint8_t*>(wBytes) + j * row_bytes;
        y[j] = cpu(row, q8_interleaved, j);
    }
    g_receipt.used_gpu = false;
    g_receipt.cpu_rows = n_out;
    g_receipt.fallback_reason = "gpu dispatch failed";
    return false;
}

// ---------------------------------------------------------------------------
// RAWRXD_MULTI_GPU: device-parametrated dispatch (split-model dual-GPU).
// DotBlockedOn/DotF16On route the GPU path to a specific Vulkan device via
// GpuFor(device) while keeping the identical CPU fallback + receipt semantics.
// device<0 or device==g_preferred_device behaves exactly like DotBlocked/DotF16.
// Batched mode is intentionally NOT used here: the dual-GPU schedule is serial
// across the device boundary, so these execute immediately (correctness-first).
// ---------------------------------------------------------------------------
bool DotBlockedOn(int32_t device, int kind,
                  const void* wBytes, size_t wBytesCount,
                  const float* x, size_t n_in,
                  float* y, size_t n_out,
                  const CpuDot& cpu,
                  const void* q8_interleaved,
                  size_t q8_bytes,
                  bool force_cpu)
{
    g_receipt = Receipt{};
    if (kind < 0 || kind > 8) { g_receipt.fallback_reason = "unsupported kind"; return false; }
    if (!wBytes || !x || !y || n_in == 0 || n_out == 0) { g_receipt.fallback_reason = "bad arguments"; return false; }
    if (cpu == nullptr) { g_receipt.fallback_reason = "no CPU fallback supplied"; return false; }
    const bool legacy = (kind >= 2);
    if (legacy && (n_in % 32u) != 0) { g_receipt.fallback_reason = "legacy kind with n_in not a multiple of 32"; return false; }
    const size_t row_bytes = legacy ? RowBytesForKind(kind, n_in)
                                    : (kind == 0 ? (n_in / 256u) * 144u : (n_in / 256u) * 210u);
    const size_t n_sb = legacy ? (n_in + 255u) / 256u : (n_in / 256u);

    if (g_force_cpu || force_cpu) {
        if (!q8_interleaved) { g_receipt.fallback_reason = "force_cpu without a Q8 activation buffer"; return false; }
        for (size_t j = 0; j < n_out; ++j) {
            const uint8_t* row = static_cast<const uint8_t*>(wBytes) + j * row_bytes;
            y[j] = cpu(row, q8_interleaved, j);
        }
        g_receipt.used_gpu = false; g_receipt.cpu_rows = n_out; g_receipt.fallback_reason = "force_cpu";
        return false;
    }

    VulkanCompute* gpu = nullptr;
    try { gpu = &GpuFor(device); } catch (const std::exception& e) {
        g_receipt.fallback_reason = e.what();
    }
    const bool gpuOk = gpu && q8_interleaved && q8_bytes >= n_sb * 273u * sizeof(float)
        ? gpu->ExecuteQuantDot(wBytes, wBytesCount, q8_interleaved, q8_bytes,
                               y, n_out * sizeof(float), n_out, n_in, n_sb, kind)
        : false;
    if (gpuOk) { g_receipt.used_gpu = true; g_receipt.gpu_rows = n_out; return true; }
    if (!q8_interleaved) {
        g_receipt.fallback_reason = "gpu unavailable and no Q8 activation buffer";
        return false;
    }
    for (size_t j = 0; j < n_out; ++j) {
        const uint8_t* row = static_cast<const uint8_t*>(wBytes) + j * row_bytes;
        y[j] = cpu(row, q8_interleaved, j);
    }
    g_receipt.used_gpu = false; g_receipt.cpu_rows = n_out;
    g_receipt.fallback_reason = "gpu dispatch failed (requested device)";
    return false;
}

bool DotF16On(int32_t device,
              const void* wBytes, size_t wBytesCount,
              const float* x, size_t n_in,
              float* y, size_t n_out,
              const CpuDot& cpu,
              bool force_cpu)
{
    g_receipt = Receipt{};
    if (!wBytes || !x || !y || n_in == 0 || n_out == 0) { g_receipt.fallback_reason = "bad arguments"; return false; }
    if (!cpu) { g_receipt.fallback_reason = "no CPU fallback supplied"; return false; }
    if ((n_in % 2u) != 0 || reinterpret_cast<uintptr_t>(wBytes) % 4u != 0) {
        g_receipt.fallback_reason = "f16: n_in odd or weight bytes misaligned"; return false;
    }
    if (wBytesCount < n_out * n_in * sizeof(uint16_t)) {
        g_receipt.fallback_reason = "f16: weight bytes short"; return false;
    }
    if (!g_force_cpu && !force_cpu) {
        VulkanCompute* gpu = nullptr;
        try { gpu = &GpuFor(device); } catch (const std::exception& e) { g_receipt.fallback_reason = e.what(); }
        if (gpu && gpu->ExecuteF16Dot(wBytes, wBytesCount, x, n_in, y, n_out * sizeof(float), n_out)) {
            g_receipt.used_gpu = true; g_receipt.gpu_rows = n_out; return true;
        }
    }
    const size_t row_bytes = n_in * sizeof(uint16_t);
    for (size_t j = 0; j < n_out; ++j) {
        const uint8_t* row = static_cast<const uint8_t*>(wBytes) + j * row_bytes;
        y[j] = cpu(row, nullptr, j);
    }
    g_receipt.used_gpu = false; g_receipt.cpu_rows = n_out;
    g_receipt.fallback_reason = (force_cpu || g_force_cpu) ? "force_cpu" : "f16 dot: gpu unavailable";
    return false;
}

// ---------------------------------------------------------------------------
// RAWRXD_DEEP2_SPEC_FUSED_LMHEAD_001: fused multi-token LM-head projection.
// Runs a batched Q4_K GEMV over P token-position hidden vectors, loading the
// output-weight matrix once and producing P logits vectors in one kernel
// launch. Returns true if the GPU path executed, false if CPU fallback used.
bool DispatchLmHeadBatchQ4K(
    const void* wBytes, size_t wBytesCount,
    const float* inputBatch, size_t inputBatchCount,
    float* outputBatch, size_t outputBatchCount,
    size_t rows,     // vocab size
    size_t cols,     // hidden dimension
    size_t batch,    // number of token positions (P)
    bool force_cpu,
    int quant_type)
{
    g_receipt = Receipt{};
    if (!wBytes || wBytesCount == 0 || !inputBatch || inputBatchCount == 0 ||
        !outputBatch || outputBatchCount == 0 || rows == 0 || cols == 0 || batch == 0 ||
        batch > 8) {
        g_receipt.fallback_reason = "lmhead-batch: invalid arguments";
        return false;
    }
    if (inputBatchCount != batch * cols) {
        g_receipt.fallback_reason = "lmhead-batch: inputBatchCount mismatch";
        return false;
    }
    if (outputBatchCount != batch * rows) {
        g_receipt.fallback_reason = "lmhead-batch: outputBatchCount mismatch";
        return false;
    }
    if (force_cpu || g_force_cpu) {
        // No CPU fallback inside this layer: the caller (Executor::
        // PrefillBatch) runs its serial per-token OpLinear path, which is the
        // exact arithmetic reference. Returning false here routes it there.
        g_receipt.used_gpu = false;
        g_receipt.cpu_rows = batch * rows;
        g_receipt.fallback_reason = "force_cpu; caller uses serial per-token path";
        return false;
    }

    if (quant_type != 12 && quant_type != 14) {
        g_receipt.fallback_reason = "lmhead-batch: unsupported quant type";
        return false;
    }

    // Use the canonical VulkanCompute's fused Q4_K/Q6_K batch GEMV via its
    // scratch system. The caller supplies the real GGUF type so a Q6_K output
    // head is not silently routed through a Q4-only kernel.
    if (!PrimaryGpuReady()) {
        g_receipt.fallback_reason = "lmhead-batch: primary GPU initialization failed";
        return false;
    }
    auto& gpu = Gpu();
    const size_t in_bytes = batch * cols * sizeof(float);
    const size_t out_bytes = batch * rows * sizeof(float);

    // Acquire scratch buffers for input and output batches
    VulkanCompute::QuantScratch* inScratch = gpu.AcquireQuantScratch(in_bytes);
    if (!inScratch) {
        g_receipt.fallback_reason = "lmhead-batch: input scratch allocation failed";
        return false;
    }
    VulkanCompute::QuantScratch* outScratch = gpu.AcquireQuantScratch(out_bytes);
    if (!outScratch) {
        gpu.ReleaseQuantScratch(inScratch);
        g_receipt.fallback_reason = "lmhead-batch: output scratch allocation failed";
        return false;
    }

    // Upload concatenated hidden vectors to input scratch
    if (!gpu.UploadBuffer(inScratch->buffer, inputBatch, inputBatchCount * sizeof(float))) {
        gpu.ReleaseQuantScratch(outScratch);
        gpu.ReleaseQuantScratch(inScratch);
        g_receipt.fallback_reason = "lmhead-batch: input upload failed";
        return false;
    }

    // Dispatch fused multi-row GEMV
    if (!gpu.DispatchGemvQ4KBatch(
            wBytes, wBytesCount,
            inScratch->buffer, outScratch->buffer,
            static_cast<uint32_t>(rows),
            static_cast<uint32_t>(cols),
            static_cast<uint32_t>(batch),
            static_cast<uint32_t>(quant_type))) {
        gpu.ReleaseQuantScratch(outScratch);
        gpu.ReleaseQuantScratch(inScratch);
        g_receipt.fallback_reason = "lmhead-batch: fused dispatch failed";
        return false;
    }

    // Download concatenated logits
    if (!gpu.DownloadBuffer(outScratch->buffer, outputBatch, outputBatchCount * sizeof(float))) {
        gpu.ReleaseQuantScratch(outScratch);
        gpu.ReleaseQuantScratch(inScratch);
        g_receipt.fallback_reason = "lmhead-batch: output download failed";
        return false;
    }

    gpu.ReleaseQuantScratch(outScratch);
    gpu.ReleaseQuantScratch(inScratch);

    g_receipt.used_gpu = true;
    g_receipt.gpu_rows = batch * rows;
    return true;
}

} } }
