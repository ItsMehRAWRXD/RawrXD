#include "Deep2RooflineRatchet.hpp"
#include <algorithm>

namespace Deep2 {

RooflineState RooflineRatchet::measure(const DecodeSample& d,
                                       const KernelSample& memoryKernel,
                                       double aggregateBandwidthGBs) noexcept {
    RooflineState s{};
    const double gotGBs = measured_gbs(memoryKernel);
    s.bandwidthFraction = aggregateBandwidthGBs > 0.0 ?
        gotGBs / aggregateBandwidthGBs : 0.0;
    s.overlapRatio = overlap_ratio(d);
    s.completionSkew = completion_skew(d);
    s.hostSyncFraction = d.tokenNs ?
        double(d.hostSyncNs) / double(d.tokenNs) : 1.0;
    s.weightReloadBytes = d.weightReloadBytes;
    s.hostMaterializations = d.hostMaterializations;
    s.parity = d.parity;
    return s;
}

RooflineDecision RooflineRatchet::certify(const RooflineState& s,
                                          const RooflineTargets& t) noexcept {
    if (t.requireParity && !s.parity)
        return {false, "ARGMAX_PARITY"};
    if (s.weightReloadBytes > t.maxWeightReloadBytes)
        return {false, "WEIGHT_RELOAD"};
    if (s.hostMaterializations > t.maxHostMaterializations)
        return {false, "HOST_MATERIALIZATION"};
    if (s.overlapRatio < t.minOverlapRatio)
        return {false, "GPU_OVERLAP"};
    if (s.completionSkew > t.maxCompletionSkew)
        return {false, "COMPLETION_SKEW"};
    if (s.hostSyncFraction > t.maxHostSyncFraction)
        return {false, "HOST_SYNC"};
    if (s.bandwidthFraction < t.minBandwidthFraction)
        return {false, "BANDWIDTH_FRACTION"};
    return {true, "PASS"};
}

} // namespace Deep2
