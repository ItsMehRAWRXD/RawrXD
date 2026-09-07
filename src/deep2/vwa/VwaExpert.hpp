// vwa/VwaExpert.hpp — router expert IDs → gate/up/down block ranges
#pragma once
#include "VwaTypes.hpp"
#include <vector>

namespace Deep2 {
namespace vwa {

struct ExpertTensorIds {
    TensorId gate = 0;
    TensorId up = 0;
    TensorId down = 0;
};

// Map selected experts to exact quant-block ranges inside 3D expert tensors.
inline bool PlanExpertBlocks(const VirtualTensorRef& gate,
                             const VirtualTensorRef& up,
                             const VirtualTensorRef& down,
                             const uint32_t* experts, size_t nExperts,
                             std::vector<BlockRange>& out) {
    if (!experts || nExperts == 0) return false;
    if (gate.expertCount == 0 || gate.expertStrideBytes == 0) return false;
    if (gate.blockBytes == 0 || up.blockBytes == 0 || down.blockBytes == 0)
        return false;
    out.clear();
    out.reserve(nExperts * 3);
    auto pushOne = [&](const VirtualTensorRef& t, uint32_t eid) -> bool {
        if (eid >= t.expertCount) return false;
        if (t.expertStrideBytes % t.blockBytes) return false;
        const uint32_t blocksPer = static_cast<uint32_t>(
            t.expertStrideBytes / t.blockBytes);
        const uint32_t first = eid * blocksPer;
        if (first + blocksPer > t.numBlocks) return false;
        out.push_back(BlockRange{t.desc.id, first, blocksPer});
        return true;
    };
    for (size_t i = 0; i < nExperts; ++i) {
        const uint32_t eid = experts[i];
        if (!pushOne(gate, eid) || !pushOne(up, eid) || !pushOne(down, eid))
            return false;
    }
    return true;
}

} // namespace vwa
} // namespace Deep2
