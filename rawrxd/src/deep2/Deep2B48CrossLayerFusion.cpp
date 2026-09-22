#include "Deep2B48CrossLayerFusion.hpp"
#include <algorithm>

namespace Deep2 {

B48FusionPlan B48CrossLayerFusion::make(uint32_t layers,
                                        bool moe,
                                        bool ssm,
                                        bool deviceLogits) noexcept {
    B48FusionPlan p{};
    p.layersPerChain = layers >= 64 ? 8u :
                       (layers >= 48 ? 6u :
                       (layers >= 24 ? 4u : 2u));

    for (uint32_t l=0; l<layers; ++l) {
        p.regions.push_back({l,B48Region::Attention,3,false});
        if (ssm && (l % 2u)) p.regions.push_back({l,B48Region::SSM,3,false});
        else if (moe) p.regions.push_back({l,B48Region::MoE,3,false});
        else p.regions.push_back({l,B48Region::FFN,3,false});
    }

    if (deviceLogits)
        p.regions.push_back({layers,B48Region::Logits,3,true});

    p.fencesPerToken =
        std::max(1u, (layers + p.layersPerChain - 1u) / p.layersPerChain);
    return p;
}

uint32_t B48CrossLayerFusion::expectedHostBoundaries(const B48FusionPlan& p) noexcept {
    return p.noHostActivation ? 0u : p.fencesPerToken;
}

}
