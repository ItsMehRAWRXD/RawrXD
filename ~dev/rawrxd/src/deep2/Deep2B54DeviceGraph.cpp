#include "Deep2B54DeviceGraph.hpp"
#include <algorithm>

namespace Deep2 {

B54GraphPlan B54DeviceGraph::make(uint32_t layers,
                                  bool moe,
                                  bool ssm,
                                  uint32_t layersPerEpoch) noexcept {
    B54GraphPlan p{};
    p.epochSize = std::max(1u,layersPerEpoch);
    p.epochsPerToken = (layers + p.epochSize - 1u) / p.epochSize;

    uint32_t id=0, prev=0xFFFFFFFFu;
    for (uint32_t l=0;l<layers;++l) {
        p.nodes.push_back({id,l,B54NodeType::Attention,3,prev});
        prev=id++;
        B54NodeType t = ssm && (l&1u) ? B54NodeType::SSM :
                           (moe ? B54NodeType::MoE : B54NodeType::FFN);
        p.nodes.push_back({id,l,t,3,prev});
        prev=id++;
    }

    p.nodes.push_back({id,layers,B54NodeType::Logits,3,prev});
    prev=id++;
    p.nodes.push_back({id,layers,B54NodeType::TokenHandoff,3,prev});
    return p;
}

}
