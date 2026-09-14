#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

enum class B56LayerKind : uint8_t {
    DenseAttention,
    MLA,
    DenseFFN,
    MoE,
    SSM
};

struct B56LayerDesc {
    uint32_t layer = 0;
    B56LayerKind kind = B56LayerKind::DenseAttention;
    uint32_t hidden = 0;
    uint32_t intermediate = 0;
    uint32_t experts = 0;
    uint32_t expertsPerToken = 0;
    uint32_t kvRank = 0;
};

struct B56LayerPlan {
    uint32_t layer = 0;
    uint32_t workgroup = 256;
    uint32_t rowsPerGroup = 4;
    uint32_t prefetch = 4;
    uint32_t expertConcurrency = 1;
    uint32_t layerFenceGroup = 0;
    bool flashAttention = false;
    bool registerExpert = false;
    bool ssmFastPath = false;
};

class B56LayerPhasePlanner {
public:
    static std::vector<B56LayerPlan> make(const std::vector<B56LayerDesc>&) noexcept;
};

}
