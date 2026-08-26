#pragma once

#include "../telemetry/LockFreeLatencyTracker.hpp"
#include "../telemetry/DoubleBufferedHistogram.hpp"
#include "QuantKB.hpp"
#include <cstdint>
#include <cmath>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Deep2 Telemetry Control Matrix
// Maps telemetry signatures to routing actions
// ============================================================================
enum class SystemHealth {
    HEALTHY_PREFETCH,       // residency_wait ~0, gpu_dispatch flat, bw high
    PCIE_HOST_BOTTLENECK,   // host_write P99 spikes, residency_wait spikes
    VRAM_BW_SATURATED,      // effective_bw drops, gpu_dispatch spikes
    COMPUTE_BOUND,          // gpu_dispatch spikes, bw drops, host_write flat
    UNKNOWN
};

struct TelemetrySnapshot {
    uint64_t host_write_ns{0};        // PCIe transfer latency
    uint64_t gpu_dispatch_ns{0};      // Vulkan compute dispatch time
    float effective_bw_gbps{0.0f};    // Achieved memory bandwidth
    uint64_t residency_wait_ns{0};    // Time waiting for residency ops
    uint64_t timestamp_ns{0};           // Sample timestamp
};

// ============================================================================
// Deep2 Active Control Matrix
// ============================================================================
class Deep2TelemetryController {
public:
    // Hot path: record latency from inference loop (~3-5 cycles)
    inline void record_host_write(uint64_t ns) noexcept {
        host_write_tracker_.record(ns);
    }

    inline void record_gpu_dispatch(uint64_t ns) noexcept {
        gpu_dispatch_tracker_.record(ns);
    }

    inline void record_residency_wait(uint64_t ns) noexcept {
        residency_wait_tracker_.record(ns);
    }

    // Cold path: evaluate telemetry and return routing action
    SystemHealth evaluate_and_route() noexcept;

    // Get latest snapshot for external monitoring
    TelemetrySnapshot get_snapshot() const noexcept;

    // QuantKB integration: report compression stats
    void report_quantkb_stats(size_t original_bytes, size_t compressed_bytes) noexcept;

private:
    rawrxd::telemetry::DefaultLatencyTracker host_write_tracker_;
    rawrxd::telemetry::DefaultLatencyTracker gpu_dispatch_tracker_;
    rawrxd::telemetry::DefaultLatencyTracker residency_wait_tracker_;

    std::vector<uint64_t> scratch_buffer_;
    float last_bw_gbps_{0.0f};
    uint64_t last_residency_wait_ns_{0};
};

// ============================================================================
// Inline implementation
// ============================================================================
inline SystemHealth Deep2TelemetryController::evaluate_and_route() noexcept {
    auto host_stats = host_write_tracker_.compute_percentiles(scratch_buffer_);
    auto gpu_stats = gpu_dispatch_tracker_.compute_percentiles(scratch_buffer_);
    auto residency_stats = residency_wait_tracker_.compute_percentiles(scratch_buffer_);

    // Classify system state based on telemetry signatures
    bool host_spike = host_stats.p99 > 50000;      // >50us PCIe stall
    bool gpu_spike = gpu_stats.p99 > 100000;       // >100us dispatch
    bool residency_spike = residency_stats.p99 > 10000; // >10us residency wait
    bool bw_low = last_bw_gbps_ < 400.0f;         // <400 GB/s on R9700

    if (host_spike && residency_spike && !gpu_spike) {
        return SystemHealth::PCIE_HOST_BOTTLENECK;
    }
    if (bw_low && gpu_spike && !host_spike) {
        return SystemHealth::VRAM_BW_SATURATED;
    }
    if (gpu_spike && !host_spike && bw_low) {
        return SystemHealth::COMPUTE_BOUND;
    }
    if (!host_spike && !gpu_spike && !residency_spike) {
        return SystemHealth::HEALTHY_PREFETCH;
    }

    return SystemHealth::UNKNOWN;
}

inline TelemetrySnapshot Deep2TelemetryController::get_snapshot() const noexcept {
    TelemetrySnapshot snap;
    snap.effective_bw_gbps = last_bw_gbps_;
    snap.residency_wait_ns = last_residency_wait_ns_;
    snap.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    return snap;
}

inline void Deep2TelemetryController::report_quantkb_stats(
    size_t original_bytes, size_t compressed_bytes) noexcept {
    if (original_bytes > 0) {
        float ratio = static_cast<float>(original_bytes) / static_cast<float>(compressed_bytes);
        // Log or export compression ratio for telemetry dashboard
        (void)ratio; // TODO: wire to telemetry export
    }
}

} // namespace Deep2
