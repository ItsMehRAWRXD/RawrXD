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

#include <mutex>
#include <vector>

#include "include/vulkan_compute.h"   // canonical path; quoted includes search this file's own directory (src/deep2/) first, where a DIFFERENT Deep2::VulkanCompute class lives in vulkan_compute.h and would silently shadow this one

namespace RawrXD {
namespace Deep2 {
namespace QuantDot {

namespace {

bool g_force_cpu = false;
Receipt g_receipt;
BackendStats g_backend;
int32_t g_preferred_device = -1;   // STRATA_S05: device pin, applied at first init

VulkanCompute& Gpu()
{
    static VulkanCompute gpu;              // one device for the process
    static bool initialised = false;
    if (!initialised) {
        initialised = true;
        // STRATA_S05: honour a device pin requested before the first dispatch.
        gpu.SetPreferredDeviceIndex(g_preferred_device);
        gpu.Initialize();                  // false stays false; receipt explains
    }
    return gpu;
}

// Packed row stride per kind (same geometry the shader and ExecuteQuantDot
// use). Legacy kinds quantise 32 values per block; the k-quants 256.
size_t RowBytesForKind(int kind, size_t n_in)
{
    switch (kind) {
    case 0: return (n_in / 256u) * 144u;               // Q4_K
    case 1: return (n_in / 256u) * 210u;               // Q6_K
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
bool g_batch_active = false;
std::vector<QueuedDot> g_queued;

// Implementation of the public BeginBatch: opens a batch on the device fast
// path. Batches do not nest; an open batch makes DotBlocked queue instead of
// executing.
bool BeginBatchImpl()
{
    if (g_batch_active) return false;
    std::lock_guard<std::mutex> lk(g_gpu_mutex);
    if (!Gpu().BeginQuantDotBatch()) return false;
    g_batch_active = true;
    g_queued.clear();
    return true;
}

// Fail-closed replay: if the batched submission itself cannot be produced, run
// every queued dot through the supplied CPU fallback - the identical path a
// single DotBlocked call takes when the GPU is unavailable - and set the
// receipt so the caller accounts a CPU run. Nothing is silently substituted.
void ReplayQueuedOnCpu(std::vector<QueuedDot>& qs)
{
    for (const QueuedDot& e : qs) {
        const size_t rb = RowBytesForKind(e.kind, e.n_in);
        float* out = static_cast<float*>(e.out);
        for (size_t j = 0; j < e.n_out; ++j) {
            const uint8_t* row =
                static_cast<const uint8_t*>(e.packed) + j * rb;
            out[j] = e.cpu(row, e.q8, j);
        }
        g_receipt.cpu_rows += e.n_out;
    }
    g_receipt.used_gpu = false;
    if (!g_receipt.fallback_reason)
        g_receipt.fallback_reason = "quant-dot batch failed; CPU replay";
}

// Implementation of the public EndBatch: submits every queued dot in one
// command buffer behind one fence and copies the results to the caller buffers.
bool EndBatchImpl()
{
    if (!g_batch_active) return false;
    g_batch_active = false;
    std::vector<QueuedDot> qs;
    qs.swap(g_queued);
    if (qs.empty()) return true;
    std::lock_guard<std::mutex> lk(g_gpu_mutex);
    bool ok = true;
    size_t total_rows = 0;
    for (const QueuedDot& e : qs) {
        ok = ok && Gpu().QueueQuantDot(e.packed, e.packed_bytes, e.q8, e.q8_bytes,
                                       e.out, e.out_bytes, e.n_out, e.n_in, e.kind);
        total_rows += e.n_out;
    }
    ok = ok && Gpu().EndQuantDotBatch();
    g_receipt = Receipt{};
    if (ok) {
        g_receipt.used_gpu = true;
        g_receipt.gpu_rows = total_rows;
        return true;
    }
    ReplayQueuedOnCpu(qs);
    return false;
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

void SetForceCpu(bool force) { g_force_cpu = force; }
bool ForceCpu() { return g_force_cpu; }

bool IsWeightResident(const void* packed, size_t bytes, int kind) {
    return Gpu().IsQuantWeightResident(packed, bytes, kind);
}

bool PrefetchWeight(const void* packed, size_t bytes, int kind) {
    return Gpu().PrefetchQuantWeight(packed, bytes, kind);
}

void SetCachePolicy(int policy) {
    Gpu().SetWeightCachePolicy(policy == 1 ? 1 : 0);
}

CacheStats GetCacheStats() {
    const GpuCounters& c = Gpu().GetGpuCounters();
    CacheStats s;
    s.hits = c.weight_cache_hits;
    s.misses = c.weight_cache_misses;
    s.evictions = c.weight_cache_evictions;
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
    return s;
}

void SetPreferredDevice(int index) {
    // Applied by Gpu() at first initialisation; calling this after the first
    // dispatch has no effect (the device already exists).
    g_preferred_device = (int32_t)index;
}

size_t BatchCapacity() {
    // kQuantBatchMaxSets: the descriptor ring bounds one batch. Reported, not
    // asserted, so callers can chunk instead of failing closed.
    return Gpu().QuantDotBatchCapacity();
}

const Receipt& LastReceipt() { return g_receipt; }

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
    if (!g_force_cpu && !force_cpu) {
        std::lock_guard<std::mutex> lk(g_gpu_mutex);
        if (Gpu().ExecuteF16Dot(wBytes, wBytesCount, x, n_in, y,
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
    g_receipt = Receipt{};

    // kind: 0 = Q4_K, 1 = Q6_K, 2 = Q5_0, 3 = Q8_0, 4 = Q4_0.
    if (kind < 0 || kind > 4) {
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
    if (g_batch_active && !force_cpu && !g_force_cpu) {
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
    VulkanCompute& gpu = Gpu();
    const bool gpuOk = q8_interleaved && q8_bytes >= n_sb * 273u * sizeof(float)
        ? gpu.ExecuteQuantDot(wBytes, wBytesCount,
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

} } }
