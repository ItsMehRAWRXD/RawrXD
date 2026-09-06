// RegenerativeFacts.hpp — sealed fact inputs (no patch history)
#pragma once
#include <cstdint>

namespace Deep2 {
namespace Regenerative {

struct HardwareFacts {
    double gpu0BusyPct = 0.0;
    double gpu1BusyPct = 0.0;
    double gpu0VramFreeGiB = 0.0;
    double gpu1VramFreeGiB = 0.0;
    uint32_t numComputeLanes = 2;
};

struct WorkloadFacts {
    uint32_t numLayers = 0;
    uint32_t numExperts = 0;
    uint32_t kvHeads = 0;
    bool mla = false;
    uint64_t bytesPerLayer = 0; // estimated compressed layer footprint; 0 = unknown
};

struct BudgetFacts {
    double targetMsPerToken = 20.0;
    double targetTps = 50.0;
    bool powerIncreaseAllowed = false;
    uint64_t maxResidentBytes = 0; // 0 = unlimited; else cap active layer weights
};

} // namespace Regenerative
} // namespace Deep2
