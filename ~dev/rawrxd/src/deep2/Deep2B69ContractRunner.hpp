#pragma once
#include "Deep2B66RuntimeMeta.hpp"
#include "Deep2B67LiveTelemetry.hpp"
#include "Deep2B68TargetCalibrator.hpp"
#include <cstdint>
#include <vector>
#include <string>

namespace Deep2 {

struct B69Contract {
    std::string name;
    uint32_t contextBucketMax = 8192;
    size_t minSamples = 320;

    double minP10Tps = 0.0;
    double minMedianTps = 0.0;
    double minP10RooflineFraction = 0.0;
    double minMedianOverlap = 0.0;
    double maxP90Skew = 1.0;
    double maxP90HostSync = 1.0;
    double maxP90QueueIdle = 1.0;
};

struct B69Stats {
    size_t samples = 0;
    double p10Tps = 0.0;
    double medianTps = 0.0;
    double p10RooflineFraction = 0.0;
    double medianOverlap = 0.0;
    double p90Skew = 1.0;
    double p90HostSync = 1.0;
    double p90QueueIdle = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    uint64_t peerCopyBytes = 0;
    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;
    bool parityAll = false;
    bool stableAll = false;
};

struct B69Result {
    bool pass = false;
    const char* failure = "UNSET";
    B69Stats stats{};
};

class B69ContractRunner {
public:
    static B69Result run(const B69Contract&,
                         const B68Calibration&,
                         const std::vector<B67TokenTelemetry>&);
};

} // namespace Deep2
