#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace Deep2 {

enum class QuantKind : uint8_t { Q4=4, Q6=6, Q8=8 };

struct QuantPackInput {
    uint32_t rows = 0;
    uint32_t cols = 0;
    QuantKind kind = QuantKind::Q4;
    uint32_t groupSize = 32;
    uint32_t waveWidth = 64;
};

struct QuantPackPlan {
    uint32_t tileRows = 1;
    uint32_t tileCols = 256;
    uint32_t vectorBytes = 16;
    uint32_t swizzle = 0;
    uint32_t groupsPerTile = 1;
    bool prepackAtLoad = true;
    bool dequantInRegisters = true;
};

class B21QuantPack {
public:
    static QuantPackPlan make(const QuantPackInput&) noexcept;
    static uint64_t packedWeightBytes(const QuantPackInput&) noexcept;
    static uint64_t scaleBytes(const QuantPackInput&) noexcept;
};

}
