#pragma once
#include <cstdint>

namespace Deep2 {

struct B44MlaShape {
    uint32_t context = 0;
    uint32_t heads = 0;
    uint32_t kvRank = 0;
    uint32_t ropeDim = 0;
    uint32_t vDim = 0;
};

struct B44DeviceProfile {
    double bandwidthGBs = 0.0;
    double computeTFLOPs = 0.0;
    uint32_t waveWidth = 64;
};

struct B44MlaPlan {
    uint32_t tokenTile = 128;
    uint32_t headTile = 4;
    uint32_t rankTile = 128;
    uint32_t valueTile = 128;
    double estimatedArithmeticIntensity = 0.0;
    bool computeBoundTarget = false;
    bool fuseOnlineSoftmax = true;
    bool fuseValueAccumulate = true;
    bool compressedKvOnly = true;
};

class B44MlaComputeBalance {
public:
    static B44MlaPlan make(const B44MlaShape&,
                           const B44DeviceProfile&) noexcept;
};

}
