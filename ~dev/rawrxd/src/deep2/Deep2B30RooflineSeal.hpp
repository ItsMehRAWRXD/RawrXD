#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace Deep2 {

struct B30TokenSample {
    double targetTps = 0.0;
    double effectiveTps = 0.0;
    double bandwidthFraction = 0.0;
    double overlap = 0.0;
    double skew = 1.0;
    double hostSyncFraction = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;
    bool parity = false;
    bool stableOutput = false;
};

struct B30Gate {
    size_t minSamples = 64;
    double minP10TargetTps = 0.0;
    double minMedianTargetTps = 0.0;
    double minP10BandwidthFraction = 0.75;
    double minMedianOverlap = 0.85;
    double maxP90Skew = 0.05;
    double maxP90HostSyncFraction = 0.03;
    double maxTargetTpsCV = 0.10;
    uint64_t maxSteadyReloadBytes = 0;
    uint64_t maxHostMaterializations = 0;
    bool requireBothGpus = true;
    bool requireParityAll = true;
    bool requireStableOutputAll = true;
};

struct B30Stats {
    size_t samples = 0;
    double p10TargetTps = 0.0;
    double medianTargetTps = 0.0;
    double medianEffectiveTps = 0.0;
    double p10BandwidthFraction = 0.0;
    double medianOverlap = 0.0;
    double p90Skew = 1.0;
    double p90HostSyncFraction = 1.0;
    double targetTpsCV = 1.0;
    uint64_t totalReloadBytes = 0;
    uint64_t totalHostMaterializations = 0;
    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;
    bool parityAll = false;
    bool stableAll = false;
};

struct B30Decision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class B30RooflineSeal {
public:
    static B30Stats summarize(const std::vector<B30TokenSample>&);
    static B30Decision certify(const B30Stats&, const B30Gate&) noexcept;
};

} // namespace Deep2
