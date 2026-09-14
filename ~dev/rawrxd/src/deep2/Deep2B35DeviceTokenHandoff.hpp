#pragma once
#include <cstdint>
#include <vector>
#include <cstddef>

namespace Deep2 {

struct B35TokenState {
    int32_t token = -1;
    uint32_t ownerDevice = 0;
    uint64_t sequence = 0;
    bool valid = false;
};

struct B35HandoffPlan {
    uint32_t producerDevice = 0;
    uint32_t consumerMask = 3;
    uint32_t ringSize = 4;
    bool hostPoll = false;
    bool hostTokenCopy = false;
    bool deviceSemaphore = true;
    bool keepNextEmbedOnDevice = true;
};

struct B35Sample {
    double targetTps = 0.0;
    double bandwidthFraction = 0.0;
    double overlap = 0.0;
    double skew = 1.0;
    double hostSyncFraction = 1.0;
    uint64_t hostTokenCopies = 0;
    uint64_t hostMaterializations = 0;
    uint64_t reloadBytes = 0;
    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;
    bool parity = false;
    bool stable = false;
};

struct B35Gate {
    size_t minSamples = 96;
    double minP10Tps = 0.0;
    double minMedianTps = 0.0;
    double minP10Bandwidth = 0.85;
    double minMedianOverlap = 0.92;
    double maxP90Skew = 0.04;
    double maxP90HostSync = 0.02;
    uint64_t maxHostTokenCopies = 0;
    uint64_t maxHostMaterializations = 0;
    uint64_t maxReloadBytes = 0;
};

struct B35Stats {
    size_t samples = 0;
    double p10Tps = 0.0;
    double medianTps = 0.0;
    double p10Bandwidth = 0.0;
    double medianOverlap = 0.0;
    double p90Skew = 1.0;
    double p90HostSync = 1.0;
    uint64_t hostTokenCopies = 0;
    uint64_t hostMaterializations = 0;
    uint64_t reloadBytes = 0;
    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;
    bool parityAll = false;
    bool stableAll = false;
};

struct B35Decision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class B35DeviceTokenHandoff {
public:
    static B35HandoffPlan make(double gpu0LogitRate, double gpu1LogitRate) noexcept;
    static B35Stats summarize(const std::vector<B35Sample>&);
    static B35Decision certify(const B35Stats&, const B35Gate&) noexcept;
};

} // namespace Deep2
