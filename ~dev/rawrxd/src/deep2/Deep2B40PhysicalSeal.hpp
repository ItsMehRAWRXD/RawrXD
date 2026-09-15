#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace Deep2 {

struct B40PhysicalSample {
    double tps = 0.0;
    double achievedVsRoofline = 0.0;
    double bandwidthFraction = 0.0;
    double computeFraction = 0.0;
    double overlap = 0.0;
    double skew = 1.0;
    double hostSync = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    bool parity = false;
    bool stable = false;
};

struct B40PhysicalGate {
    size_t minSamples = 128;
    double minP10Tps = 0.0;
    double minMedianTps = 0.0;
    double minP10RooflineFraction = 0.85;
    double minMedianRooflineFraction = 0.90;
    double minP10Bandwidth = 0.88;
    double minP10Compute = 0.82;
    double minMedianOverlap = 0.94;
    double maxP90Skew = 0.035;
    double maxP90HostSync = 0.012;
    uint64_t maxReloadBytes = 0;
    uint64_t maxHostMaterializations = 0;
    uint64_t maxHostTokenCopies = 0;
};

struct B40PhysicalStats {
    size_t samples = 0;
    double p10Tps = 0.0;
    double medianTps = 0.0;
    double p10RooflineFraction = 0.0;
    double medianRooflineFraction = 0.0;
    double p10Bandwidth = 0.0;
    double p10Compute = 0.0;
    double medianOverlap = 0.0;
    double p90Skew = 1.0;
    double p90HostSync = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    bool parityAll = false;
    bool stableAll = false;
};

struct B40PhysicalDecision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class B40PhysicalSeal {
public:
    static B40PhysicalStats summarize(const std::vector<B40PhysicalSample>&);
    static B40PhysicalDecision certify(const B40PhysicalStats&,
                                       const B40PhysicalGate&) noexcept;
};

} // namespace Deep2