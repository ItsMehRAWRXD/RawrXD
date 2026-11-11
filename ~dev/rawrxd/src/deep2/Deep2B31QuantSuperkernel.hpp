#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

enum class B31QuantType : uint8_t { Q4_K=4, Q6_K=6, Q8_0=8 };

struct B31QuantShape {
    uint32_t rows = 0;
    uint32_t cols = 0;
    B31QuantType type = B31QuantType::Q4_K;
    uint32_t block = 32;
    uint32_t wave = 64;
};

struct B31QuantPlan {
    uint32_t workgroup = 256;
    uint32_t rowsPerGroup = 1;
    uint32_t vectorBytes = 16;
    uint32_t blocksPerPrefetch = 4;
    uint32_t unpackLanes = 8;
    bool fusedScaleDecode = true;
    bool registerDequant = true;
    bool subgroupReduce = true;
    bool prepackedLayout = true;
};

class B31QuantSuperkernel {
public:
    static B31QuantPlan make(const B31QuantShape&) noexcept;
    static double bytesPerWeight(const B31QuantShape&) noexcept;
    static uint64_t estimatedWeightBytes(const B31QuantShape&) noexcept;
};

} // namespace Deep2
