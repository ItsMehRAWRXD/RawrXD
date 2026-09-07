// ElasticDynamicBudget.hpp — live warm/hot/lookahead (not reverse-static)
#pragma once
#include "ElasticResidencyManager.hpp"
#include <cstdint>

namespace Deep2 {

struct ElasticDynamicProbe {
    uint64_t ramTotal = 0;
    uint64_t ramAvail = 0;
    uint64_t vramTotal = 0;
    uint32_t layers = 0;
    uint32_t experts = 0;
    uint64_t modelBytes = 0;
    uint32_t fusedPrefetchDepth = 0;
    bool vramPressure = false;
    bool ramHeadroom = true;
};

// Fill RAM + DXGI VRAM. layers/modelBytes optional (caller).
void ElasticBudget_ProbeHost(ElasticDynamicProbe& out);

// Derive caps from probe. Env overrides only if set (force floor/ceiling).
ElasticResidencyConfig ElasticBudget_Derive(const ElasticDynamicProbe& p);

void ElasticBudget_Emit(FILE* f, const ElasticResidencyConfig& c,
                        const ElasticDynamicProbe& p);

} // namespace Deep2
