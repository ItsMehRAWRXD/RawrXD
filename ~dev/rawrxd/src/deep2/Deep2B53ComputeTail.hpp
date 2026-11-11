#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

struct B53ComputeShape {
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint32_t waveWidth = 64;
};

struct B53Variant {
    uint32_t workgroup = 256;
    uint32_t accumulators = 8;
    uint32_t unroll = 4;
    uint32_t rowsPerGroup = 4;
    uint32_t splitK = 1;
    uint32_t estimatedRegs = 64;
};

struct B53Measured {
    B53Variant variant{};
    double kernelNs = 0.0;
    double computeFraction = 0.0;
    double occupancyFraction = 0.0;
    bool parity = false;
};

struct B53Decision {
    bool pass = false;
    size_t best = static_cast<size_t>(-1);
};

class B53ComputeTail {
public:
    static std::vector<B53Variant> enumerate(const B53ComputeShape&);
    static B53Decision choose(const std::vector<B53Measured>&,
                              double minComputeFraction,
                              double minOccupancyFraction) noexcept;
};

}
