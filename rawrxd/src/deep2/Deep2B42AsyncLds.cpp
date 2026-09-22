#include "Deep2B42AsyncLds.hpp"
#include <algorithm>

namespace Deep2 {

B42StagePlan B42AsyncLds::make(const B42StageInput& in) noexcept {
    B42StagePlan p{};
    p.tileCols = in.cols >= 8192 ? 1024u : (in.cols >= 4096 ? 512u : 256u);
    p.xTileBytes = p.tileCols * sizeof(float);

    const uint32_t budget = in.ldsBytesAvailable > p.xTileBytes ?
        in.ldsBytesAvailable - p.xTileBytes : 0u;

    p.stages = budget >= 49152u ? 3u : 2u;
    p.tripleBuffer = p.stages == 3u;
    p.doubleBuffer = p.stages >= 2u;

    p.bytesPerStage = p.stages ? budget / p.stages : 0u;
    p.bytesPerStage = std::min(p.bytesPerStage, 24576u);

    const uint32_t ldsUse = p.xTileBytes + p.bytesPerStage * p.stages;
    uint32_t ldsGroups = ldsUse ? in.ldsBytesAvailable / ldsUse : 1u;
    if (!ldsGroups) ldsGroups = 1u;

    uint32_t regGroups = in.estimatedRegs > 96 ? 1u :
                         (in.estimatedRegs > 64 ? 2u : 4u);
    p.estimatedGroupsPerCU = std::max(1u, std::min(ldsGroups, regGroups));
    return p;
}

}
