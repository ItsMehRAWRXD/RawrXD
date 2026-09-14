#pragma once
#include <cstdint>

namespace Deep2 {

enum class B41Quant : uint8_t { Q4=4, Q6=6, Q8=8 };

struct B41PackedDotShape {
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint32_t waveWidth = 64;
    B41Quant quant = B41Quant::Q4;
    uint32_t block = 32;
};

struct B41PackedDotPlan {
    uint32_t workgroup = 256;
    uint32_t packedValuesPerWord = 8;
    uint32_t wordsPerLane = 4;
    uint32_t accumulatorsPerLane = 8;
    uint32_t rowsPerGroup = 4;
    uint32_t subgroupWidth = 64;
    bool integerUnpack = true;
    bool scaleDecodeFused = true;
    bool subgroupReduce = true;
    bool prepacked = true;
};

class B41PackedDot {
public:
    static B41PackedDotPlan make(const B41PackedDotShape&) noexcept;
    static uint64_t packedBytes(const B41PackedDotShape&) noexcept;
    static double idealDotOpsPerByte(const B41PackedDotShape&) noexcept;
};

}
