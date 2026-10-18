#include "Deep2B22LdsReuse.hpp"
#include <algorithm>

namespace Deep2 {

LdsReusePlan B22LdsReuse::make(const LdsReuseInput& in) noexcept {
    LdsReusePlan p{};
    p.xTile = in.hidden >= 8192 ? 512u : 256u;
    const uint32_t xBytes = p.xTile * 4u;
    const uint32_t halfLds = std::max(4096u, in.ldsBytesAvailable / 2u);
    p.weightStageBytes = std::min(halfLds > xBytes ? halfLds - xBytes : 4096u, 32768u);
    p.wavesPerGroup = in.waveWidth >= 64 ? 4u : 8u;
    p.subgroupTreeWidth = in.waveWidth ? in.waveWidth : 64u;
    const uint32_t regLimit = in.registersPerThread > 96 ? 1u :
                              (in.registersPerThread > 64 ? 2u : 4u);
    const uint32_t ldsUse = xBytes + (p.doubleBufferWeights ? 2u*p.weightStageBytes : p.weightStageBytes);
    const uint32_t ldsLimit = ldsUse ? std::max(1u, in.ldsBytesAvailable / ldsUse) : 1u;
    p.groupsPerCU = std::max(1u, std::min(regLimit, ldsLimit));
    return p;
}

}
