#pragma once
#include "Deep2RooflineTypes.hpp"
#include <cstdint>

namespace Deep2 {

struct RooflineTargets {
    double minBandwidthFraction = 0.70;
    double minOverlapRatio = 0.80;
    double maxCompletionSkew = 0.05;
    double maxHostSyncFraction = 0.05;
    uint64_t maxWeightReloadBytes = 0;
    uint64_t maxHostMaterializations = 0;
    bool requireParity = true;
};

struct RooflineState {
    double bandwidthFraction = 0.0;
    double overlapRatio = 0.0;
    double completionSkew = 1.0;
    double hostSyncFraction = 1.0;
    uint64_t weightReloadBytes = 0;
    uint64_t hostMaterializations = 0;
    bool parity = false;
};

struct RooflineDecision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class RooflineRatchet {
public:
    static RooflineState measure(const DecodeSample& d,
                                 const KernelSample& memoryKernel,
                                 double aggregateBandwidthGBs) noexcept;
    static RooflineDecision certify(const RooflineState& s,
                                    const RooflineTargets& t) noexcept;
};

} // namespace Deep2
