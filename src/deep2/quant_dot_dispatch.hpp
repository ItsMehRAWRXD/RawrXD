#pragma once
// RAWRXD_DEEP2_GPU_QUANT_DOT_001
//
// Quantised dot-product dispatch: GPU-first, CPU fallback, fail-closed.
//
// The kernel itself (packed Q4_K/Q6_K x Q8_K) is proven correct by
// RAWRXD_DEEP2_GPU_QUANT_DOT_001 - 4/4 shapes on two discrete AMD GPUs at
// cosine 1.0. This header is the DISPATCH layer that decides which path runs.
//
// Contract for callers (OpLinear):
//   * kind     : 0 = Q4_K, 1 = Q6_K
//   * wBytes   : the packed weight block bytes, exactly as stored in the GGUF
//   * x        : raw float activations, n_in elements
//   * y        : output, n_out elements (must be zeroed by the caller)
//   * cpu      : a CpuDot(row, q8_act, rowIndex) callback. It is invoked when
//                the GPU path cannot run, and it may also be used by the GPU
//                path to dot ONE packed row. It returns a float.
//
// Design notes:
//   * DotBlocked returns true when it definitely used the GPU, false when it
//     definitely used the CPU path, and never silently mixes the two for one
//     call. Callers count the receipt rather than assume.
//   * Fallback is REAL arithmetic, not a stub. It dequantises the packed row
// with ggml's own type traits and dots it against a Q8_K-quantised activation,
// so GpU and CPU paths are numerically comparable.
//   * ForceCpu/SetForceCpu let a harness pin the CPU path to measure parity.

#include <functional>
#include <cstddef>
#include <cstdint>

namespace RawrXD {
namespace Deep2 {
namespace QuantDot {

// Row-dequantising CPU dot, supplied by the caller so this layer stays free of
// ggml dependencies.
using CpuDot = std::function<float(const uint8_t* row, const void* q8_act, size_t rowIndex)>;

// Pin the CPU path (harnesses use this to measure GPU-vs-CPU parity).
// This is a PROCESS-WIDE override. Prefer the per-call force_cpu parameter so
// one executor's CPU pin cannot leak into another's comparison.
void SetForceCpu(bool force);
bool ForceCpu();

// Run n_out dot products, each n_in long, using packed quantised weights.
// force_cpu pins THIS call to the CPU path regardless of the GPU.
// Returns true if the GPU path executed, false if the CPU path executed.
bool DotBlocked(int kind,
                const void* wBytes, size_t wBytesCount,
                const float* x, size_t n_in,
                float* y, size_t n_out,
                const CpuDot& cpu,
                const void* q8_interleaved = nullptr,
                size_t q8_bytes = 0,
                bool force_cpu = false);

// FP16-weight dot (RAWRXD_DEEP2_F16_QUANT_DOT_CLOSURE). Several model families
// carry FP16 projections (qwen3: blk.N.attn_v.weight) among otherwise
// quantised weights. The GPU kernel dots the raw fp16 weights against the raw
// float activation with no quantisation; the CPU fallback decodes with ggml's
// own fp16 path, so the two agree to fp32 rounding. Same receipt contract as
// DotBlocked.
bool DotF16(const void* wBytes, size_t wBytesCount,
            const float* x, size_t n_in,
            float* y, size_t n_out,
            const CpuDot& cpu,
            bool force_cpu = false);

// ---------------------------------------------------------------------------
// Batched dispatch (RAWRXD_DEEP2_LEGACY_QUANT_GPU_001).
//
// BeginBatch opens a batch; while it is open every DotBlocked call QUEUES
// instead of executing, and EndBatch runs the queued dots in ONE command
// buffer behind ONE fence. A MoE block with `selected` experts therefore pays
// two submissions (up-dots, then down-dots) instead of 2*selected.
//
// Caller contract:
//   * Queue only dots whose output is NOT read until EndBatch returns. The
//     batch is not a dependency resolver; an up-dot must not feed a down-dot
//     queued in the same batch.
//   * Batches do not nest. An empty batch ends successfully.
//   * On any failure EndBatch replays every queued dot on the supplied CPU
//     fallback and returns false, so the caller accounts a real CPU run
//     (nothing is silently substituted).
//   * The reference executor must NOT batch: it pins force_cpu per call and
//     keeps the compared path deterministic.
bool BeginBatch();
bool EndBatch();

// Diagnostic receipt describing the last DotBlocked call.
struct Receipt {
    bool     used_gpu = false;      // GPU executed at least one row
    size_t   gpu_rows = 0;          // rows dispatched to the GPU
    size_t   cpu_rows = 0;          // rows dispatched to the CPU
    const char* fallback_reason = nullptr;   // non-null when !used_gpu
    bool     queued = false;        // this dot was queued into a batch, not yet run
};

const Receipt& LastReceipt();

// Backend instrumentation mirror (RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY).
// Kernel time is queue-side execution; submit time is host recording
// overhead; wait time is the host blocked on the fence. Transfer bytes and
// allocation/reuse counts make resource churn measurable instead of guessed.
struct BackendStats {
    uint64_t buffer_allocations = 0;
    uint64_t descriptor_allocations = 0;
    uint64_t descriptor_reuses = 0;
    uint64_t descriptor_alloc_attempts = 0;
    uint64_t descriptor_alloc_failures = 0;
    uint64_t descriptor_pool_creates = 0;
    uint64_t descriptor_pool_resets = 0;
    uint64_t descriptor_sets_in_flight = 0;
    uint64_t descriptor_sets_peak = 0;
    uint64_t submits = 0;
    uint64_t waits = 0;
    uint64_t upload_bytes = 0;
    uint64_t download_bytes = 0;
    uint64_t weight_cache_hits = 0;
    uint64_t weight_cache_misses = 0;
    uint64_t device_bytes_live = 0;
    uint64_t device_bytes_peak = 0;
    double kernel_ms = 0;
    double submit_ms = 0;
    double wait_ms = 0;
    double gpu_ms = 0;                 // TRUE device-side time (GPU timestamps)
};

// Never touches the GPU; safe to call before any dispatch.
const BackendStats& BackendCounters();

// ---------------------------------------------------------------------------
// RAWRXD_DEEP2_STRATA_S01..S08: VRAM expert-residency observation and control.
//
// The backend already keeps dispatched weights in a device-local, budgeted,
// fingerprint-validated cache (Upload-once / reuse-every-decode). These
// accessors let the Strata expert layer OBSERVE that cache and STEER it
// without changing dispatch semantics:
//   * IsWeightResident - read-only query, no mutation (cache HIT accounting).
//   * PrefetchWeight   - cache-insertion ahead of a dependent dispatch; either
//                        it was already resident (prefetch hit) or it is
//                        uploaded now under the same budget and fingerprint
//                        rules, so a later dispatch can never read stale bytes.
//   * SetCachePolicy   - 0 = LRU (default), 1 = hotness (STRATA_S08).
//   * CacheStats       - the measured hit/miss/eviction/prefetch/transfer
//                        counters the S01/S02/S04/S08 certificates reduce to.
// ---------------------------------------------------------------------------
bool IsWeightResident(const void* packed, size_t bytes, int kind);
bool PrefetchWeight(const void* packed, size_t bytes, int kind);
void SetCachePolicy(int policy);   // 0 = LRU, 1 = hotness

struct CacheStats {
    uint64_t hits = 0;            // dispatches served from VRAM
    uint64_t misses = 0;          // first uploads
    uint64_t evictions = 0;       // budget evictions
    uint64_t prefetches = 0;      // explicit prefetch uploads
    uint64_t prefetch_hits = 0;   // prefetches that found it resident
    uint64_t upload_bytes = 0;    // host -> device
    uint64_t download_bytes = 0;  // device -> host
    uint64_t device_bytes_live = 0;
    uint64_t device_bytes_peak = 0;
    uint64_t submits = 0;
    uint64_t waits = 0;
    double kernel_ms = 0;
    double submit_ms = 0;
    double wait_ms = 0;
};

CacheStats GetCacheStats();

// STRATA_S05: pin the compute device (e.g. 0 = first discrete GPU, the second
// discrete AMD card in a two-GPU host). -1 restores score-based auto-select.
// Must be called before the first dispatch; selection is otherwise automatic.
void SetPreferredDevice(int index);

} } }
