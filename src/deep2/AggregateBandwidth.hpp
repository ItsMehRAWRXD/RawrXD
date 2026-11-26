// AggregateBandwidth.hpp — RAWRXD_AGGREGATE_BANDWIDTH_LOCK_001
//
// Modifiable aggregate VRAM bandwidth for the dual-GPU performance lock.
//   * Detected: sum of each physical GPU's measured/theoretical peak bandwidth
//     (R9700 640 + RX 7800 XT 624 = 1264 GB/s combined).
//   * Override: set RAWRXD_AGGREGATE_BANDWIDTH_GBPS=<value> to reverse-engineer
//     the throughput model with ANY aggregate bandwidth and try it.
//   * Effective: override if set (>0), else the detected combined value.
//
// The 1,000 GB/s lock target is AGGREGATE (both cards); a single card (~600)
// cannot satisfy it. This value feeds the throughput/bandwidth model only and
// is never presented as a measured hardware result.
#pragma once
#include "HostHardwareProbe.hpp"
#include <cstdlib>
#include <vector>

namespace rawrxd {

// Detect a physical GPU's peak memory bandwidth (GB/s) from its adapter name.
// Known AMD parts; unknown -> 0 (caller must supply a measured value or override).
inline double DetectPeakBandwidthGbps(const std::string& name) {
    auto has = [&](const char* s) { return name.find(s) != std::string::npos; };
    if (has("R9700")) return 640.0;  // Radeon AI PRO R9700 (32 GB)
    if (has("7800"))  return 624.0;  // Radeon RX 7800 XT (16 GB)
    return 0.0;                      // unknown
}

// Sum of detected per-GPU peak memory bandwidth (theoretical, GB/s).
inline double DetectedCombinedBandwidthGbps(
    const std::vector<GpuDeviceInfo>& gpus) {
    double s = 0.0;
    for (const auto& g : gpus) s += DetectPeakBandwidthGbps(g.name);
    return s;
}

// Reverse-engineering override (GB/s), or 0 when unset. Put any value here to
// test the model against an arbitrary aggregate bandwidth.
inline double AggregateBandwidthOverrideGbps() {
    const char* e = std::getenv("RAWRXD_AGGREGATE_BANDWIDTH_GBPS");
    if (e) {
        const double v = std::atof(e);
        if (v > 0.0) return v;
    }
    return 0.0;
}

// Effective aggregate = override when set, else detected combined.
inline double EffectiveAggregateBandwidthGbps(
    const std::vector<GpuDeviceInfo>& gpus) {
    const double o = AggregateBandwidthOverrideGbps();
    return o > 0.0 ? o : DetectedCombinedBandwidthGbps(gpus);
}

// No-arg convenience using the host probe (gpus empty unless enumerated; the
// override still applies). The engine should pass enumerated gpus instead.
inline double EffectiveAggregateBandwidthGbps() {
    return EffectiveAggregateBandwidthGbps(
        HostHardwareProbe::Probe().gpus);
}

} // namespace rawrxd