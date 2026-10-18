#pragma once
#include <cstdint>
#include <string>

namespace Deep2 {

struct B49Geometry {
    uint32_t hidden = 0;
    uint32_t intermediate = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t experts = 0;
    uint32_t expertsPerToken = 0;
    uint32_t qLoraRank = 0;
    uint32_t kvLoraRank = 0;
    uint32_t ropeDim = 0;
    uint32_t layers = 0;
    uint32_t quantBits = 4;
    bool useMLA = false;
    bool hasSSM = false;
};

struct B49Device {
    uint32_t waveWidth = 64;
    uint32_t maxWorkgroup = 1024;
    uint32_t ldsBytes = 65536;
    double bandwidthGBs = 0.0;
    double computeTFLOPs = 0.0;
};

struct B49ShaderKey {
    uint64_t hash = 0;
    uint32_t workgroup = 256;
    uint32_t vectorWidth = 8;
    uint32_t rowsPerGroup = 4;
    uint32_t prefetch = 4;
    uint32_t expertConcurrency = 1;
    uint32_t layerChain = 2;
    bool flashMLA = false;
    bool moeRegisterFusion = false;
    bool ssmFastPath = false;
};

class B49ShaderSpecializer {
public:
    static B49ShaderKey derive(const B49Geometry&,
                               const B49Device&) noexcept;
    static std::string macroPreamble(const B49ShaderKey&);
};

}
