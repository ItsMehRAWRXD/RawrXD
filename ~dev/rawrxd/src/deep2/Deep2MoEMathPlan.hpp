#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>

namespace Deep2 {

struct RoutedExpert {
    uint32_t expert = 0;
    float weight = 0.0f;
    uint32_t device = 0;
    uint64_t residentBytes = 0;
    double recentNs = 0.0;
};

struct MoEMathPlan {
    std::vector<RoutedExpert> ordered;
    uint32_t gpu0Count = 0;
    uint32_t gpu1Count = 0;
    bool fuseGateUp = true;
    bool fuseActivationMul = true;
    bool combineExpertOutputs = true;
};

class MoEExpertMathPlanner {
public:
    static MoEMathPlan make(std::vector<RoutedExpert> experts) noexcept;
};

} // namespace Deep2
