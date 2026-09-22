#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace Deep2 {

struct B60Sample {
    double rawTps = 0.0;
    double effectiveTps = 0.0;
    double rooflineFraction = 0.0;
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
    bool bothGpus = false;
    bool parity = false;
    bool stable = false;
};

struct B60Contract {
    std::string modelKey;
    size_t minSamples = 320;
    double minP10RawTps = 0.0;
    double minMedianRawTps = 0.0;
    double minP10Roofline = 0.965;
    double minMedianRoofline = 0.985;
    double minP10Bandwidth = 0.96;
    double minP10Compute = 0.90;
    double minMedianOverlap = 0.985;
    double maxP90Skew = 0.015;
    double maxP90HostSync = 0.003;
    double maxP90QueueIdle = 0.0075;
};

struct B60Stats {
    size_t samples = 0;
    double p10RawTps = 0.0;
    double medianRawTps = 0.0;
    double medianEffectiveTps = 0.0;
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
    bool bothGpusAll = false;
    bool parityAll = false;
    bool stableAll = false;
};

struct B60Decision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class B60ModelContract {
public:
    static B60Stats summarize(const std::vector<B60Sample>&);
    static B60Decision certify(const B60Stats&,
                               const B60Contract&) noexcept;
};

}
