#pragma once
#include <cstdint>
#include <vector>
#include <cstddef>

namespace Deep2 {

struct B50Sample {
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
    uint64_t peerCopyBytes = 0;
    bool parity = false;
    bool stable = false;
    bool bothGpus = false;
};

struct B50Gate {
    size_t minSamples = 192;
    double minP10Tps = 0.0;
    double minMedianTps = 0.0;
    double minP10Roofline = 0.93;
    double minMedianRoofline = 0.95;
    double minP10Bandwidth = 0.93;
    double minP10Compute = 0.85;
    double minMedianOverlap = 0.97;
    double maxP90Skew = 0.025;
    double maxP90HostSync = 0.0075;
    uint64_t maxReloadBytes = 0;
    uint64_t maxHostMaterializations = 0;
    uint64_t maxHostTokenCopies = 0;
    uint64_t maxPeerCopyBytes = 0;
};

struct B50Stats {
    size_t samples = 0;
    double p10Tps = 0.0;
    double medianTps = 0.0;
    double p10Roofline = 0.0;
    double medianRoofline = 0.0;
    double p10Bandwidth = 0.0;
    double p10Compute = 0.0;
    double medianOverlap = 0.0;
    double p90Skew = 1.0;
    double p90HostSync = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    uint64_t peerCopyBytes = 0;
    bool parityAll = false;
    bool stableAll = false;
    bool bothGpusAll = false;
};

struct B50Decision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class B50ChallengeSeal {
public:
    static B50Stats summarize(const std::vector<B50Sample>&);
    static B50Decision certify(const B50Stats&,
                               const B50Gate&) noexcept;
};

}
