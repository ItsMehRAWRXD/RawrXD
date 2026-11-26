// AdaptiveThroughputLock.hpp — RAWRXD_ADAPTIVE_THROUGHPUT_LOCK_001
//
// Universal, hardware-adaptive throughput model. No fixed GPU count, bandwidth
// ceiling, VRAM capacity or throughput target: the caller supplies an editable
// per-GPU list (name, peak GB/s, VRAM GB); the model combines them, applies
// utilization/overlap, and reverse-engineers the batch required for ANY target.
//
// AGGREGATE is the sum across devices (single card ~600 GB/s cannot meet a
// 1000 GB/s lock). An override (RAWRXD_AGGREGATE_BANDWIDTH_GBPS) lets you feed
// any aggregate and try it. Modeled results are NOT measured hardware results.
#pragma once
#include <string>
#include <vector>
#include <cstdlib>
#include <cmath>
#include <cstdint>

namespace rawrxd {
namespace adaptive {

struct GpuBw {
    std::string name;
    double peakGbps = 0.0; // per-device theoretical memory bandwidth
    double vramGB   = 0.0; // per-device VRAM capacity
};

// Sum of per-device peak bandwidth (theoretical aggregate).
inline double CombinedPeakGbps(const std::vector<GpuBw>& gpus) {
    double s = 0.0;
    for (const auto& g : gpus) s += g.peakGbps;
    return s;
}

// Reverse-engineering override (aggregate GB/s), or 0 when unset.
inline double AggregateOverrideGbps() {
    const char* e = std::getenv("RAWRXD_AGGREGATE_BANDWIDTH_GBPS");
    if (e) { const double v = std::atof(e); if (v > 0.0) return v; }
    return 0.0;
}

// Effective aggregate = (override or combined peak) * utilization * overlap.
inline double EffectiveAggregateGbps(const std::vector<GpuBw>& gpus,
                                     double utilization = 1.0,
                                     double overlap = 1.0) {
    const double o = AggregateOverrideGbps();
    const double base = o > 0.0 ? o : CombinedPeakGbps(gpus);
    return base * utilization * overlap;
}

// Throughput model (bytes-based):
//   T = B*S / ( W/V + W(1-R)/D + overhead )
// W=active weight bytes, V=effective aggregate VRAM B/s, B=effective token
// batch, R=residency, D=storage B/s, S=speculative speedup, overhead in ms.
inline double ModeledTps(double W_bytes, double V_Bps, double batch,
                         double residency, double storage_Bps,
                         double spec, double overheadMs = 0.0) {
    if (V_Bps <= 0.0 || batch <= 0.0 || W_bytes <= 0.0) return 0.0;
    const double gpu     = W_bytes / V_Bps;
    const double storage = (storage_Bps > 0.0)
        ? W_bytes * (1.0 - residency) / storage_Bps : 0.0;
    const double denom = gpu + storage + overheadMs / 1000.0;
    if (denom <= 0.0) return 0.0;
    return (batch * spec) / denom;
}

// Minimum effective batch to reach a target TPS (ceil).
inline double MinBatchForTarget(double targetTps, double W_bytes, double V_Bps,
                                double residency = 1.0, double storage_Bps = 0.0,
                                double spec = 1.0, double overheadMs = 0.0) {
    if (V_Bps <= 0.0 || targetTps <= 0.0 || W_bytes <= 0.0) return 0.0;
    const double gpu     = W_bytes / V_Bps;
    const double storage = (storage_Bps > 0.0)
        ? W_bytes * (1.0 - residency) / storage_Bps : 0.0;
    const double denom = gpu + storage + overheadMs / 1000.0;
    if (denom <= 0.0) return 0.0;
    return std::ceil(targetTps * denom / spec);
}

} // namespace adaptive
} // namespace rawrxd