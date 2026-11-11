#include "Deep2B29LayerChain.hpp"

namespace Deep2 {

B29ChainPlan B29LayerChain::make(uint32_t layers, bool moe,
                                 bool logitsOnDevice) noexcept {
    B29ChainPlan p{};
    p.layersPerFence = layers >= 48 ? 4u : (layers >= 24 ? 2u : 1u);
    p.maxInflightLayers = p.layersPerFence;
    p.hostSyncsPerToken = 0;
    for (uint32_t l=0; l<layers; ++l) {
        p.nodes.push_back({l, B29Region::Attention, 3, true, false});
        p.nodes.push_back({l, moe ? B29Region::MoE : B29Region::DenseFFN,
                           3, true, false});
    }
    if (logitsOnDevice)
        p.nodes.push_back({layers, B29Region::Logits, 3, true, false});
    return p;
}

uint32_t B29LayerChain::expectedSubmits(const B29ChainPlan& p) noexcept {
    if (p.nodes.empty()) return 0;
    const uint32_t regionsPerLayer = 2u;
    const uint32_t layerCount =
        static_cast<uint32_t>((p.nodes.size() - (p.nodes.back().region == B29Region::Logits ? 1u : 0u))
                              / regionsPerLayer);
    const uint32_t chunks =
        (layerCount + p.layersPerFence - 1u) / p.layersPerFence;
    // one attention/FFN chain per device per chunk; logits folded into final chunk.
    return chunks * 2u;
}

} // namespace Deep2
