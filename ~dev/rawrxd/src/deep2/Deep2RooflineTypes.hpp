#pragma once
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <cmath>

namespace Deep2 {

struct DeviceRoofline {
    double bandwidthGBs = 0.0;
    double fp16TFLOPs = 0.0;
    uint32_t computeUnits = 0;
    uint32_t waveWidth = 64;
    uint64_t vramBytes = 0;
};

struct KernelSample {
    uint64_t bytesRead = 0;
    uint64_t bytesWritten = 0;
    uint64_t operations = 0;
    uint64_t durationNs = 0;
    uint64_t queueIdleNs = 0;
    uint64_t submitNs = 0;
};

struct DecodeSample {
    uint64_t tokenNs = 0;
    uint64_t gpu0Ns = 0;
    uint64_t gpu1Ns = 0;
    uint64_t overlapNs = 0;
    uint64_t hostSyncNs = 0;
    uint64_t transferBytes = 0;
    uint64_t weightReloadBytes = 0;
    uint64_t kernelLaunches = 0;
    uint64_t hostMaterializations = 0;
    bool parity = false;
};

inline double ns_to_s(uint64_t ns) noexcept { return double(ns) * 1e-9; }

inline double measured_gbs(const KernelSample& s) noexcept {
    if (!s.durationNs) return 0.0;
    return (double(s.bytesRead + s.bytesWritten) / 1.0e9) / ns_to_s(s.durationNs);
}

inline double roofline_fraction(const KernelSample& s, const DeviceRoofline& d) noexcept {
    if (d.bandwidthGBs <= 0.0) return 0.0;
    return measured_gbs(s) / d.bandwidthGBs;
}

inline double completion_skew(const DecodeSample& s) noexcept {
    const uint64_t hi = std::max(s.gpu0Ns, s.gpu1Ns);
    if (!hi) return 0.0;
    const uint64_t lo = std::min(s.gpu0Ns, s.gpu1Ns);
    return double(hi - lo) / double(hi);
}

inline double overlap_ratio(const DecodeSample& s) noexcept {
    const uint64_t hi = std::max(s.gpu0Ns, s.gpu1Ns);
    if (!hi) return 0.0;
    return std::min(1.0, double(s.overlapNs) / double(hi));
}

} // namespace Deep2
