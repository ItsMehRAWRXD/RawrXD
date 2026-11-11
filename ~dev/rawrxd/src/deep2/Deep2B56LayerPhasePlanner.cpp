#include "Deep2B56LayerPhasePlanner.hpp"

namespace Deep2 {

std::vector<B56LayerPlan> B56LayerPhasePlanner::make(
    const std::vector<B56LayerDesc>& in) noexcept {
    std::vector<B56LayerPlan> out;
    out.reserve(in.size());

    for (const auto& d : in) {
        B56LayerPlan p{};
        p.layer = d.layer;
        p.workgroup = d.hidden >= 4096 ? 256u : 128u;
        p.rowsPerGroup = d.hidden >= 8192 ? 8u : (d.hidden >= 4096 ? 4u : 2u);
        p.prefetch = d.hidden >= 8192 ? 8u : 4u;
        p.layerFenceGroup = d.layer / 6u;

        p.flashAttention = d.kind == B56LayerKind::MLA ||
                           d.kind == B56LayerKind::DenseAttention;
        p.registerExpert = d.kind == B56LayerKind::MoE;
        p.ssmFastPath = d.kind == B56LayerKind::SSM;

        if (d.kind == B56LayerKind::MoE) {
            p.expertConcurrency = d.expertsPerToken >= 8 ? 8u :
                                  (d.expertsPerToken >= 4 ? 4u : 2u);
        }
        out.push_back(p);
    }
    return out;
}

}
