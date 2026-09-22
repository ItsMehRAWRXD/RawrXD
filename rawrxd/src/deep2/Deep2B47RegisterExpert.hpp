#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

struct B47ExpertSlice {
    uint32_t expert = 0;
    uint32_t device = 0;
    uint32_t rowBegin = 0;
    uint32_t rowEnd = 0;
    bool resident = false;
    double recentNs = 0.0;
};

struct B47RegisterExpertPlan {
    std::vector<B47ExpertSlice> slices;
    uint32_t concurrentExperts = 1;
    uint32_t rowsPerSlice = 1024;
    uint32_t accumulatorCount = 8;
    bool keepGateUpInRegisters = true;
    bool fuseActivation = true;
    bool fuseDownAccumulate = true;
    bool noIntermediateGlobal = true;
    bool deviceCombine = true;
};

class B47RegisterExpert {
public:
    static B47RegisterExpertPlan make(uint32_t intermediate,
                                      std::vector<uint32_t> experts,
                                      std::vector<uint32_t> devices,
                                      uint32_t maxConcurrent) noexcept;
    static uint64_t avoidedIntermediateBytes(uint32_t activeExperts,
                                             uint32_t intermediate,
                                             uint32_t scalarBytes = 2) noexcept;
};

}
