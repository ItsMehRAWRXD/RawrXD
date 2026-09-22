#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cmath>
#include <limits>
#include <numeric>
#include <string>
#include <vector>

namespace Deep2::Roofline {

using u64 = std::uint64_t;
using u32 = std::uint32_t;

inline constexpr double AGGREGATE_BANDWIDTH_GBS = 640.0 + 624.0;
inline constexpr double QWEN32_Q4KM_SIZE_GB = 18.49;
inline constexpr double THEORETICAL_SINGLE_PASS_TPS = AGGREGATE_BANDWIDTH_GBS / QWEN32_Q4KM_SIZE_GB; // ~68.36

struct HardwareProfile {
    double gpuBandwidthGBs[2]{640.0, 624.0};
    double gpuComputeTOPS[2]{0.0, 0.0}; // optional: 0 disables compute roofline
    u64 gpuVramBytes[2]{32ull << 30, 16ull << 30};
};

inline HardwareProfile R9700_Rx7800XT() noexcept { return {}; }

struct DeviceSample {
    double workUnits = 0.0;
    u64 bytesRead = 0;
    u64 bytesWritten = 0;
    u64 elapsedNs = 0;
    u64 busyNs = 0;
    u64 waitNs = 0;
    u64 forwards = 0;
};

struct SplitPlan {
    double fraction[2]{0.5, 0.5};
    u32 rows[2]{0, 0};
};

struct TokenMetrics {
    u64 tokenIndex = 0;
    u64 tokenWallNs = 0;
    u64 overlapNs = 0;
    DeviceSample gpu[2]{};
    u64 weightReuploads = 0;
    u64 descriptorRebuilds = 0;
    u64 residencyHits = 0;
    u64 residencyMisses = 0;
    u64 prefetchHits = 0;
    u64 prefetchMisses = 0;
    u64 hostBytesTransferred = 0;
    u64 speculativeProposed = 0;
    u64 speculativeAccepted = 0;
    bool argmaxParity = true;
    bool outputStable = true;

    double tps() const noexcept {
        return tokenWallNs ? 1.0e9 / static_cast<double>(tokenWallNs) : 0.0;
    }
    double overlapRatio() const noexcept {
        const u64 denom = std::min(gpu[0].busyNs, gpu[1].busyNs);
        return denom ? static_cast<double>(overlapNs) / static_cast<double>(denom) : 0.0;
    }
    double completionSkew() const noexcept {
        const double a = static_cast<double>(gpu[0].elapsedNs);
        const double b = static_cast<double>(gpu[1].elapsedNs);
        const double m = std::max(a, b);
        return m > 0.0 ? std::abs(a - b) / m : 0.0;
    }
};

struct RooflineEstimate {
    double bandwidthLimitedTps = 0.0;
    double computeLimitedTps = std::numeric_limits<double>::infinity();
    double rooflineTps = 0.0;
};

inline RooflineEstimate EstimateRoofline(const HardwareProfile& hw,
                                         u64 bytesPerToken,
                                         double teraOpsPerToken) noexcept {
    RooflineEstimate r{};
    const double gbps = hw.gpuBandwidthGBs[0] + hw.gpuBandwidthGBs[1];
    if (bytesPerToken) {
        r.bandwidthLimitedTps = (gbps * 1.0e9) / static_cast<double>(bytesPerToken);
    }
    const double tops = hw.gpuComputeTOPS[0] + hw.gpuComputeTOPS[1];
    if (tops > 0.0 && teraOpsPerToken > 0.0) {
        r.computeLimitedTps = tops / teraOpsPerToken;
    }
    r.rooflineTps = std::min(r.bandwidthLimitedTps, r.computeLimitedTps);
    return r;
}

struct CertTargets {
    u64 minTokens = 32;
    double minMeasuredTps = 0.0;          // 0 => report only, never invent a target
    double minRooflineFraction = 0.0;     // 0 => report only
    double minOverlapRatio = 0.60;
    double maxCompletionSkew = 0.15;
    u64 maxSteadyWeightReuploads = 0;
    u64 maxSteadyDescriptorRebuilds = 0;
    u64 maxSteadyHostTrafficBytes = 0;
    double minSpeculativeAcceptanceRatio = 0.0;
    bool requireBothGpus = true;
    bool requireParity = true;
    bool requireStableOutput = true;
};

inline u32 RoundRows(u32 rows, u32 granularity) noexcept {
    if (!granularity) return rows;
    return (rows / granularity) * granularity;
}

} // namespace Deep2::Roofline
