#pragma once
#include <cstdint>

namespace Deep2 {

struct LdsReuseInput {
    uint32_t hidden = 0;
    uint32_t intermediate = 0;
    uint32_t waveWidth = 64;
    uint32_t ldsBytesAvailable = 65536;
    uint32_t registersPerThread = 64;
};

struct LdsReusePlan {
    uint32_t xTile = 256;
    uint32_t weightStageBytes = 0;
    uint32_t wavesPerGroup = 4;
    uint32_t groupsPerCU = 1;
    uint32_t subgroupTreeWidth = 64;
    bool cacheX = true;
    bool doubleBufferWeights = true;
    bool subgroupReduce = true;
};

class B22LdsReuse {
public:
    static LdsReusePlan make(const LdsReuseInput&) noexcept;
};

}
