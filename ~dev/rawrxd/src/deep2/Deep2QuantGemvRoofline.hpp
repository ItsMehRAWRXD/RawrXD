#pragma once
#include "Deep2RooflineTypes.hpp"
#include <cstdint>
#include <cstddef>

namespace Deep2 {

struct QuantGemvShape {
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint32_t quantBits = 4;
    uint32_t groupSize = 32;
};

struct QuantGemvPlan {
    uint32_t rowsPerGroup = 1;
    uint32_t colsPerLane = 4;
    uint32_t workgroupSize = 64;
    uint32_t vectorWidth = 4;
    uint32_t prefetchBlocks = 2;
    bool fuseDequantDot = true;
    bool useSubgroupReduce = true;
};

class QuantGemvRoofline {
public:
    static QuantGemvPlan plan(const QuantGemvShape& s, const DeviceRoofline& d) noexcept;
    static double arithmeticIntensity(const QuantGemvShape& s) noexcept;
    static double theoreticalTokensPerSecond(uint64_t bytesPerToken,
                                              double effectiveBandwidthGBs) noexcept;
};

} // namespace Deep2
