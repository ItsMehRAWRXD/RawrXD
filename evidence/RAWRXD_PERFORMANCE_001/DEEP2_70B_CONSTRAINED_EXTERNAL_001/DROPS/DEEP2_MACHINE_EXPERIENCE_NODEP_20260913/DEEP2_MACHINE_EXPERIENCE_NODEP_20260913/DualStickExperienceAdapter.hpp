#pragma once
/* Narrow adapter contract: source-ready, not product-bound by this drop. */
#include "Deep2MachineExperience.hpp"

namespace Deep2 {
struct DualStickExperience {
    mx::Store store;
    mx::Epoch epoch;
    mx::Regime regime;
    uint64_t tick;
};
void DualStickExperienceInit(DualStickExperience& x,const mx::Epoch& e,const mx::Regime& r);
uint64_t DualStickExperienceCost(DualStickExperience& x,uint32_t layer,int expert,
                                 unsigned gpu,uint32_t quant,uint32_t inDim,
                                 uint32_t outDim,int resident,uint64_t fallbackNs,
                                 uint32_t* confidencePpm=nullptr);
void DualStickExperienceObserve(DualStickExperience& x,uint32_t layer,int expert,
                                unsigned gpu,uint32_t quant,uint32_t inDim,
                                uint32_t outDim,int resident,uint64_t actualNs,
                                uint64_t predictedNs,bool truthValidated);
}
