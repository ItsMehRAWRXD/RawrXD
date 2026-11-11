#pragma once
#include "Deep2B41PackedDot.hpp"
#include "Deep2B42AsyncLds.hpp"
#include "Deep2B43MoEWave.hpp"
#include "Deep2B44MlaComputeBalance.hpp"
#include "Deep2B45KernelPlan.hpp"

namespace Deep2 {

struct B41_45BackendOps {
    void* user=nullptr;
    bool (*applyPackedDot)(void*,const B41PackedDotPlan&)=nullptr;
    bool (*applyAsyncLds)(void*,const B42StagePlan&)=nullptr;
    bool (*applyMoEWave)(void*,const B43MoEWavePlan&)=nullptr;
    bool (*applyMlaBalance)(void*,const B44MlaPlan&)=nullptr;
    bool (*applyKernelPlan)(void*,const B45KernelPlan&)=nullptr;
};

inline bool ApplyB41_45(B41_45BackendOps& o,
                        const B41PackedDotPlan& a,
                        const B42StagePlan& b,
                        const B43MoEWavePlan& c,
                        const B44MlaPlan& d,
                        const B45KernelPlan& e) {
    if(o.applyPackedDot && !o.applyPackedDot(o.user,a)) return false;
    if(o.applyAsyncLds && !o.applyAsyncLds(o.user,b)) return false;
    if(o.applyMoEWave && !o.applyMoEWave(o.user,c)) return false;
    if(o.applyMlaBalance && !o.applyMlaBalance(o.user,d)) return false;
    if(o.applyKernelPlan && !o.applyKernelPlan(o.user,e)) return false;
    return true;
}

}
