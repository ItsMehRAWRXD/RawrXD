#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

struct B43Expert {
    uint32_t expert = 0;
    uint32_t device = 0;
    uint32_t intermediate = 0;
    uint64_t bytes = 0;
    bool resident = false;
    double recentNs = 0.0;
};

struct B43WaveAssignment {
    uint32_t expert = 0;
    uint32_t device = 0;
    uint32_t waveSlot = 0;
    uint32_t rowBegin = 0;
    uint32_t rowEnd = 0;
};

struct B43MoEWavePlan {
    std::vector<B43WaveAssignment> assignments;
    uint32_t gpu0Waves = 0;
    uint32_t gpu1Waves = 0;
    uint32_t maxConcurrentExperts = 1;
    bool residentOnlyFastPath = true;
    bool deviceCombine = true;
    bool oneFencePerExpertSet = true;
};

class B43MoEWave {
public:
    static B43MoEWavePlan make(std::vector<B43Expert>,
                               uint32_t gpu0WaveBudget,
                               uint32_t gpu1WaveBudget) noexcept;
};

}
