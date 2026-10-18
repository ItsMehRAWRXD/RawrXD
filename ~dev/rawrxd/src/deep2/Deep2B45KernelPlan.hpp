#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstddef>

namespace Deep2 {

struct B45Geometry {
    uint32_t layers=0;
    uint32_t hidden=0;
    uint32_t heads=0;
    uint32_t kvHeads=0;
    uint32_t headDim=0;
    uint32_t intermediate=0;
    uint32_t experts=0;
    uint32_t expertsPerToken=0;
    uint32_t qLoraRank=0;
    uint32_t kvLoraRank=0;
    uint32_t ropeDim=0;
    bool useMLA=false;
    bool hasSSM=false;
};

struct B45LiveDevice {
    double bandwidthGBs=0.0;
    double computeTFLOPs=0.0;
    double nsPerRow=0.0;
    uint64_t freeVramBytes=0;
    uint32_t waveWidth=64;
};

struct B45KernelPlan {
    uint32_t attentionWG=256;
    uint32_t ffnWG=256;
    uint32_t rowsPerGroup=4;
    uint32_t prefetchDistance=4;
    uint32_t layerFence=2;
    uint32_t expertConcurrency=1;
    uint32_t gpu0SharePermille=500;
    bool flashMLA=false;
    bool moeWaveKernel=false;
    bool deviceLogits=true;
    bool deviceTokenHandoff=true;
    bool persistentLayerChain=true;
};

struct B45SealSample {
    double tps=0.0;
    double achievedVsRoofline=0.0;
    double bandwidthFraction=0.0;
    double computeFraction=0.0;
    double overlap=0.0;
    double skew=1.0;
    double hostSync=1.0;
    uint64_t reloadBytes=0;
    uint64_t hostMaterializations=0;
    uint64_t hostTokenCopies=0;
    bool parity=false;
    bool stable=false;
};

struct B45SealGate {
    size_t minSamples=160;
    double minP10Tps=0.0;
    double minMedianTps=0.0;
    double minP10RooflineFraction=0.85;
    double minMedianRooflineFraction=0.90;
    double minP10Bandwidth=0.90;
    double minP10Compute=0.80;
    double minMedianOverlap=0.95;
    double maxP90Skew=0.03;
    double maxP90HostSync=0.01;
    uint64_t maxReloadBytes=0;
    uint64_t maxHostMaterializations=0;
    uint64_t maxHostTokenCopies=0;
};

struct B45SealStats {
    size_t samples=0;
    double p10Tps=0.0;
    double medianTps=0.0;
    double p10RooflineFraction=0.0;
    double medianRooflineFraction=0.0;
    double p10Bandwidth=0.0;
    double p10Compute=0.0;
    double medianOverlap=0.0;
    double p90Skew=1.0;
    double p90HostSync=1.0;
    uint64_t reloadBytes=0;
    uint64_t hostMaterializations=0;
    uint64_t hostTokenCopies=0;
    bool parityAll=false;
    bool stableAll=false;
};

struct B45Decision {
    bool pass=false;
    const char* firstFailure="UNSET";
};

class B45KernelPlanner {
public:
    static B45KernelPlan derive(const B45Geometry&,
                                const B45LiveDevice&,
                                const B45LiveDevice&) noexcept;
    static std::string describe(const B45KernelPlan&);
    static B45SealStats summarize(const std::vector<B45SealSample>&);
    static B45Decision certify(const B45SealStats&,
                               const B45SealGate&) noexcept;
};

}
