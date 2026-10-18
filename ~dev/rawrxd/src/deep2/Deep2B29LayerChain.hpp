#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

enum class B29Region : uint8_t { Attention, MoE, DenseFFN, Logits };

struct B29LayerNode {
    uint32_t layer = 0;
    B29Region region = B29Region::Attention;
    uint32_t deviceMask = 3;
    bool activationResident = true;
    bool requiresHost = false;
};

struct B29ChainPlan {
    std::vector<B29LayerNode> nodes;
    uint32_t layersPerFence = 1;
    uint32_t maxInflightLayers = 1;
    uint32_t hostSyncsPerToken = 0;
    bool persistentActivationPingPong = true;
    bool deviceToDeviceEdges = true;
    bool hostMaterialization = false;
};

class B29LayerChain {
public:
    static B29ChainPlan make(uint32_t layers, bool moe, bool logitsOnDevice) noexcept;
    static uint32_t expectedSubmits(const B29ChainPlan&) noexcept;
};

} // namespace Deep2
