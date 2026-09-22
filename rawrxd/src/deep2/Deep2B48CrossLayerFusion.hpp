#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

enum class B48Region : uint8_t { Attention, FFN, MoE, SSM, Logits };

struct B48LayerRegion {
    uint32_t layer = 0;
    B48Region region = B48Region::Attention;
    uint32_t deviceMask = 3;
    bool requiresFence = false;
};

struct B48FusionPlan {
    std::vector<B48LayerRegion> regions;
    uint32_t layersPerChain = 1;
    uint32_t activationBuffers = 2;
    uint32_t fencesPerToken = 1;
    bool activationPingPong = true;
    bool noHostActivation = true;
    bool chainAcrossLayers = true;
    bool finalLogitsInChain = true;
};

class B48CrossLayerFusion {
public:
    static B48FusionPlan make(uint32_t layers,
                              bool moe,
                              bool ssm,
                              bool deviceLogits) noexcept;
    static uint32_t expectedHostBoundaries(const B48FusionPlan&) noexcept;
};

}
