#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace Deep2 {

struct B55Sample {
    double tps = 0.0;
    double achievedVsRoofline = 0.0;
    double bandwidthFraction = 0.0;
    double computeFraction = 0.0;
    double overlap = 0.0;
    double skew = 1.0;
    double hostSync = 1.0;
    double queueIdle = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    uint64_t peerCopyBytes = 0;
    bool parity = false;
    bool stable = false;
    bool bothGpus = false;
};

struct B55Gate {
    size_t minSamples = 256;
    double minP10Tps = 0.0;
    double minMedianTps = 0.0;
    double minP10Roofline = 0.95;
    double minMedianRoofline = 0.975;
    double minP10Bandwidth = 0.95;
    double minP10Compute = 0.88;
    double minMedianOverlap = 0.98;
    double maxP90Skew = 0.02;
    double maxP90HostSync = 0.005;
    double maxP90QueueIdle = 0.01;
    uint64_t maxReloadBytes = 0;
    uint64_t maxHostMaterializations = 0;
    uint64_t maxHostTokenCopies = 0;
    uint64_t maxPeerCopyBytes = 0;
};

struct B55Stats {
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
    double p90QueueIdle = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    uint64_t peerCopyBytes = 0;
    bool parityAll = false;
    bool stableAll = false;
    bool bothGpusAll = false;
};

struct B55Decision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class B55AsymptoticSeal {
public:
    static B55Stats summarize(const std::vector<B55Sample>&);
    static B55Decision certify(const B55Stats&,
                               const B55Gate&) noexcept;
};

}
