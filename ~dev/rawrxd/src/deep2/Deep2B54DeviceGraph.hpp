#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

enum class B54NodeType : uint8_t {
    Attention,
    FFN,
    MoE,
    SSM,
    Logits,
    TokenHandoff
};

struct B54Node {
    uint32_t id = 0;
    uint32_t layer = 0;
    B54NodeType type = B54NodeType::Attention;
    uint32_t deviceMask = 3;
    uint32_t dependency = 0xFFFFFFFFu;
};

struct B54GraphPlan {
    std::vector<B54Node> nodes;
    uint32_t epochSize = 1;
    uint32_t epochsPerToken = 1;
    uint32_t hostWakesPerToken = 0;
    uint32_t hostWaitsPerToken = 0;
    bool deviceTimeline = true;
    bool persistentDescriptors = true;
    bool tokenLoopsOnDevice = true;
};

class B54DeviceGraph {
public:
    static B54GraphPlan make(uint32_t layers,
                             bool moe,
                             bool ssm,
                             uint32_t layersPerEpoch) noexcept;
};

}
