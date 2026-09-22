#pragma once
#include <cstdint>

namespace Deep2 {

enum class B46QuantFormat : uint8_t {
    Q4_K = 4,
    Q6_K = 6,
    Q8_0 = 8
};

struct B46QuantGeometry {
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint32_t blockSize = 32;
    B46QuantFormat format = B46QuantFormat::Q4_K;
    uint32_t waveWidth = 64;
};

struct B46NativeQuantPlan {
    uint32_t workgroup = 256;
    uint32_t rowsPerGroup = 4;
    uint32_t packedLoadsPerLane = 4;
    uint32_t valuesPerDecode = 8;
    uint32_t accumulatorsPerLane = 8;
    uint32_t scaleCacheEntries = 8;
    bool decodeNativeBlock = true;
    bool scaleInRegisters = true;
    bool zeroIntermediateF32 = true;
    bool subgroupReduce = true;
};

class B46NativeQuant {
public:
    static B46NativeQuantPlan make(const B46QuantGeometry&) noexcept;
    static uint64_t packedPayloadBytes(const B46QuantGeometry&) noexcept;
};

}
