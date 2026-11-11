#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

struct B42StageInput {
    uint32_t cols = 0;
    uint32_t workgroup = 256;
    uint32_t ldsBytesAvailable = 65536;
    uint32_t bytesPerPackedWord = 4;
    uint32_t vectorBytes = 16;
    uint32_t estimatedRegs = 64;
};

struct B42StagePlan {
    uint32_t tileCols = 256;
    uint32_t stages = 2;
    uint32_t bytesPerStage = 0;
    uint32_t xTileBytes = 0;
    uint32_t estimatedGroupsPerCU = 1;
    bool doubleBuffer = true;
    bool tripleBuffer = false;
    bool overlapLoadCompute = true;
    bool keepXResident = true;
};

class B42AsyncLds {
public:
    static B42StagePlan make(const B42StageInput&) noexcept;
};

}
