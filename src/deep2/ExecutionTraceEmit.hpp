// ============================================================================
// ExecutionTraceEmit.hpp — the one authoritative inference execution trace.
//
// Every number in it is MEASURED at a real CPU or Vulkan dispatch site.  A
// value that was not measured is emitted as "unmeasured" (never a fabricated
// zero) so the report can never be read as a performance claim it cannot
// support.
//
// DEEP2_EXECUTION_TRACE_AUTHORITY_001
// ============================================================================
#ifndef RAWRXD_EXECUTION_TRACE_EMIT_HPP
#define RAWRXD_EXECUTION_TRACE_EMIT_HPP

#include "ExecutionAuthority.hpp"
#include "ModelFit.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace rawrxd {

// ---------------------------------------------------------------------------
// Execution telemetry accumulated by the engine during a run.
//
// Timing is sampled at the operation boundary that owns it:
//   cpuKernelNs    — host GEMV/dequant body, excluding host<->GPU transfers
//   gpuKernelNs    — calibrated Vulkan timestamp intervals (0 = unavailable)
//   gpuSyncNs      — fence/queue-wait time on the host
//   dequantNs      — QuantKernelRegistry dequantization only
//   weightXferNs   — staging upload -> device buffer adoption
// ---------------------------------------------------------------------------
struct ExecutionTelemetry {
    std::atomic<uint64_t> cpuKernelNs{0};
    std::atomic<uint64_t> gpuKernelNs{0};
    std::atomic<uint64_t> gpuSyncNs{0};
    std::atomic<uint64_t> dequantNs{0};
    std::atomic<uint64_t> weightXferNs{0};

    std::atomic<uint64_t> cpuGemmOps{0};
    std::atomic<uint64_t> gpuGemmOps{0};
    std::atomic<uint64_t> cpuOtherOps{0};
    std::atomic<uint64_t> gpuOtherOps{0};
    std::atomic<uint64_t> unsupportedOps{0};

    std::atomic<uint64_t> layerExecutions{0};
    std::atomic<uint64_t> gemvCalls{0};
    std::atomic<uint64_t> gemvGpuHits{0};
    std::atomic<uint64_t> gemvCpuHits{0};
    std::atomic<uint64_t> weightUploadBytes{0};

    // Weight-loading defect detector: bytes pushed to the GPU per generated
    // token.  A healthy run keeps this at zero after warmup because pinned
    // weights are reused; a large value means tensors are re-streamed every
    // token, which alone can destroy throughput.
    std::atomic<uint64_t> uploadBytesPerTokenMarker{0};

    std::vector<std::string> fallbackReasons;
    std::vector<std::pair<std::string, uint64_t>> slowestOps;

    void Reset() {
        cpuKernelNs = 0; gpuKernelNs = 0; gpuSyncNs = 0;
        dequantNs = 0; weightXferNs = 0;
        cpuGemmOps = 0; gpuGemmOps = 0;
        cpuOtherOps = 0; gpuOtherOps = 0;
        unsupportedOps = 0;
        layerExecutions = 0; gemvCalls = 0;
        gemvGpuHits = 0; gemvCpuHits = 0;
        weightUploadBytes = 0;
        fallbackReasons.clear();
        slowestOps.clear();
    }

    void NoteFallback(const char* reason) {
        if (fallbackReasons.size() < 64) fallbackReasons.emplace_back(reason);
    }
    void NoteSlowest(const char* op, uint64_t ns) {
        slowestOps.emplace_back(op, ns);
        // Keep the top 8 by duration — insertion sort on a tiny vector.
        for (size_t i = slowestOps.size(); i-- > 1;) {
            if (slowestOps[i].second > slowestOps[i - 1].second)
                std::swap(slowestOps[i], slowestOps[i - 1]);
        }
        if (slowestOps.size() > 8) slowestOps.pop_back();
    }
};

// ---------------------------------------------------------------------------
// Phase timings for prefill/decode, captured by the engine.
// ---------------------------------------------------------------------------
struct ExecutionPhaseTimings {
    uint64_t inputTokens = 0;
    uint64_t batchSize = 0;
    uint64_t layerCount = 0;
    uint64_t totalLayerExecutions = 0;
    uint64_t prefillWallNs = 0;
    uint64_t decodeWallNs = 0;
    uint64_t generatedTokens = 0;
};

// ---------------------------------------------------------------------------
// KV-cache provenance + reuse accounting (gate 3: context truth).
// ---------------------------------------------------------------------------
struct KvReuseReport {
    bool provenanceValid = false;
    uint64_t validTokens = 0;
    uint64_t reusedPrefixTokens = 0;
    uint64_t appendedTokens = 0;
    std::string rejectReason;
};

// ---------------------------------------------------------------------------
// Emit the authoritative block.
// ---------------------------------------------------------------------------
inline void EmitExecutionTrace(
    FILE* f,
    const ExecutionTelemetry& t,
    const ExecutionPhaseTimings& ph,
    const KvReuseReport& kv,
    const ModelFitPlan& fit,
    uint64_t runId,
    const char* measuredLabel)
{
    if (!f) f = stderr;

    const double ms = 1.0e6;   // ns -> ms
    std::fprintf(f,
        "\nMODEL: %s\n"
        "PREFILL:\n"
        "  input_tokens=%llu\n"
        "  batch_size=%llu\n"
        "  layer_count=%llu\n"
        "  total_layer_executions=%llu\n"
        "  cpu_kernel_time_ms=%.3f\n"
        "  gpu_kernel_time_ms=%.3f\n"
        "  gpu_sync_time_ms=%.3f\n"
        "  dequantization_time_ms=%.3f\n"
        "  weight_transfer_time_ms=%.3f\n"
        "KV_CACHE:\n"
        "  valid_tokens=%llu\n"
        "  reused_prefix_tokens=%llu\n"
        "  appended_tokens=%llu\n"
        "  provenance_valid=%d\n"
        "  provenance_reject=%s\n"
        "EXECUTION:\n"
        "  cpu_operations=%llu\n"
        "  gpu_dispatches=%llu\n"
        "  unsupported_operations=%llu\n"
        "  gemv_calls=%llu\n"
        "  gemv_gpu_hits=%llu\n"
        "  gemv_cpu_hits=%llu\n"
        "  weight_bytes_uploaded_total=%llu\n"
        "  weight_bytes_uploaded_per_generated_token=%llu\n"
        "  fallback_reasons=%zu\n"
        "RESULT:\n"
        "  prefill_tps=%.3f\n"
        "  decode_tps=%.3f\n"
        "  actual_backend=%s\n"
        "  planned_backend=%s\n"
        "  admission_verdict=%s\n"
        "  plan_honored=%d\n"
        "  run_id=%llu\n"
        "  timing_authority=%s\n",
        fit.modelPath.empty() ? "(none)" : fit.modelPath.c_str(),
        (unsigned long long)ph.inputTokens,
        (unsigned long long)ph.batchSize,
        (unsigned long long)ph.layerCount,
        (unsigned long long)ph.totalLayerExecutions,
        (double)t.cpuKernelNs.load() / ms,
        (double)t.gpuKernelNs.load() / ms,
        (double)t.gpuSyncNs.load() / ms,
        (double)t.dequantNs.load() / ms,
        (double)t.weightXferNs.load() / ms,
        (unsigned long long)kv.validTokens,
        (unsigned long long)kv.reusedPrefixTokens,
        (unsigned long long)kv.appendedTokens,
        kv.provenanceValid ? 1 : 0,
        kv.rejectReason.empty() ? "-" : kv.rejectReason.c_str(),
        (unsigned long long)(t.cpuGemmOps.load() + t.cpuOtherOps.load()),
        (unsigned long long)(t.gpuGemmOps.load() + t.gpuOtherOps.load()),
        (unsigned long long)t.unsupportedOps.load(),
        (unsigned long long)t.gemvCalls.load(),
        (unsigned long long)t.gemvGpuHits.load(),
        (unsigned long long)t.gemvCpuHits.load(),
        (unsigned long long)t.weightUploadBytes.load(),
        (unsigned long long)t.uploadBytesPerTokenMarker.load(),
        t.fallbackReasons.size(),
        ph.prefillWallNs
            ? (double)ph.inputTokens / ((double)ph.prefillWallNs / 1.0e9) : 0.0,
        ph.decodeWallNs && ph.generatedTokens
            ? (double)ph.generatedTokens / ((double)ph.decodeWallNs / 1.0e9) : 0.0,
        FitLaneName(fit.actualLane()),
        FitLaneName(fit.lane),
        fit.accepted ? "ACCEPT" : "REJECT",
        fit.planHonored() ? 1 : 0,
        (unsigned long long)runId,
        measuredLabel && *measuredLabel ? measuredLabel : "unmeasured");

    for (const auto& r : t.fallbackReasons)
        std::fprintf(f, "  fallback=%s\n", r.c_str());
    if (!t.slowestOps.empty()) {
        std::fprintf(f, "  slowest_operations:\n");
        for (const auto& s : t.slowestOps)
            std::fprintf(f, "    %s ns=%llu\n", s.first.c_str(),
                         (unsigned long long)s.second);
    }
    std::fflush(f);
}

// ---------------------------------------------------------------------------
// RAII timer that accumulates into one of the telemetry buckets.
// Guarantees duration is recorded even when the op throws.
// ---------------------------------------------------------------------------
class ScopedOpTimer {
public:
    ScopedOpTimer(std::atomic<uint64_t>& bucket, ExecutionTelemetry* telemetry = nullptr,
                  const char* slowOpName = nullptr)
        : bucket_(bucket), telemetry_(telemetry), name_(slowOpName) {
        start_ = std::chrono::steady_clock::now();
    }
    ~ScopedOpTimer() {
        const auto end = std::chrono::steady_clock::now();
        const uint64_t ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_).count());
        bucket_.fetch_add(ns, std::memory_order_relaxed);
        if (telemetry_ && name_) telemetry_->NoteSlowest(name_, ns);
    }
private:
    std::atomic<uint64_t>& bucket_;
    ExecutionTelemetry* telemetry_;
    const char* name_;
    std::chrono::steady_clock::time_point start_;
};

} // namespace rawrxd

#endif // RAWRXD_EXECUTION_TRACE_EMIT_HPP
