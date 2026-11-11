#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>

namespace Deep2 {

struct B27ExpertTask {
    uint32_t expert = 0;
    uint32_t device = 0;
    float routeWeight = 0.0f;
    uint64_t weightBytes = 0;
    bool resident = false;
    double lastNs = 0.0;
};

struct B27MoEPlan {
    std::vector<B27ExpertTask> ordered;
    uint32_t gpu0Tasks = 0;
    uint32_t gpu1Tasks = 0;
    uint32_t maxConcurrentExperts = 1;
    bool fuseGateUp = true;
    bool fuseSiluMul = true;
    bool fuseDownAccumulate = true;
    bool deviceCombine = true;
    bool oneSubmitPerDevice = true;
};

class B27MoESuperkernel {
public:
    static B27MoEPlan make(std::vector<B27ExpertTask>, uint32_t computeUnits0,
                           uint32_t computeUnits1) noexcept;
    static uint64_t avoidableActivationTraffic(uint32_t activeExperts,
                                               uint32_t intermediate,
                                               uint32_t scalarBytes = 2) noexcept;
};

} // namespace Deep2
