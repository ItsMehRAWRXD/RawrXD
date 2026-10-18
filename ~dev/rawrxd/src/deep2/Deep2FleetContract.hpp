#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace Deep2 {

enum class FleetFamily : uint8_t {
    Qwen3Next,
    Nemotron35Lightning,
    GptOss120B,
    LagunaS21,
    DeepSeekV4Flash
};

struct ModelEnvelope {
    FleetFamily family{};
    const char* key = "";
    double totalParamsB = 0.0;
    double activeParamsB = 0.0;
    uint32_t layers = 0;              // 0 => runtime metadata authoritative
    uint32_t experts = 0;             // 0 => runtime metadata authoritative
    uint32_t expertsPerToken = 0;     // 0 => runtime metadata authoritative
    uint32_t sharedExperts = 0;
    uint32_t hidden = 0;              // 0 => runtime metadata authoritative
    uint32_t heads = 0;               // 0 => runtime metadata authoritative
    uint32_t kvHeads = 0;             // 0 => runtime metadata authoritative
    uint32_t headDim = 0;
    uint32_t context = 0;
    bool useMLA = false;
    bool useSSM = false;
    bool useHybridLinearAttention = false;
    bool useSlidingWindow = false;
};

struct RuntimeModelMeta {
    double totalParamsB = 0.0;
    double activeParamsB = 0.0;
    uint32_t layers = 0;
    uint32_t experts = 0;
    uint32_t expertsPerToken = 0;
    uint32_t sharedExperts = 0;
    uint32_t hidden = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t context = 0;
    bool useMLA = false;
    bool useSSM = false;
    bool useHybridLinearAttention = false;
    bool useSlidingWindow = false;
};

struct ModelPerformanceContract {
    ModelEnvelope envelope{};
    uint32_t contextBucketMax = 8192;
    size_t minSamples = 320;
    double minP10RawTps = 0.0;
    double minMedianRawTps = 0.0;
    double minP10RooflineFraction = 0.90;
    double minMedianRooflineFraction = 0.92;
    double minP10BandwidthFraction = 0.0;
    double minP10ComputeFraction = 0.0;
    double minMedianOverlap = 0.95;
    double maxP90Skew = 0.03;
    double maxP90HostSync = 0.01;
    double maxP90QueueIdle = 0.015;
    double minRooflineHeadroom = 1.02;
};

struct ContractSample {
    double rawTps = 0.0;
    double effectiveTps = 0.0;
    double physicalRooflineTps = 0.0;
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
    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;
    bool parity = false;
    bool stable = false;
};

struct ContractStats {
    size_t samples = 0;
    double p10RawTps = 0.0;
    double medianRawTps = 0.0;
    double medianEffectiveTps = 0.0;
    double p10PhysicalRooflineTps = 0.0;
    double p10RooflineFraction = 0.0;
    double medianRooflineFraction = 0.0;
    double p10BandwidthFraction = 0.0;
    double p10ComputeFraction = 0.0;
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

struct ContractDecision {
    bool pass = false;
    const char* firstFailure = "UNSET";
};

class FleetContract {
public:
    static bool metadataMatches(const ModelEnvelope&,
                                const RuntimeModelMeta&) noexcept;
    static ContractStats summarize(const std::vector<ContractSample>&);
    static ContractDecision certify(const ModelPerformanceContract&,
                                    const RuntimeModelMeta&,
                                    const ContractStats&) noexcept;
    static const char* familyName(FleetFamily) noexcept;
};

} // namespace Deep2
