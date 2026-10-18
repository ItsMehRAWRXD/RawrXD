#pragma once
#include "Deep2B56LayerPhasePlanner.hpp"
#include "Deep2B57ContextKernel.hpp"
#include "Deep2B58RouteSpecializer.hpp"
#include "Deep2B59StabilityGovernor.hpp"
#include "Deep2B60ModelContract.hpp"

namespace Deep2 {

struct B56_60BackendOps {
    void* user=nullptr;
    bool (*applyLayerPlans)(void*,const std::vector<B56LayerPlan>&)=nullptr;
    bool (*applyContextPlan)(void*,const B57ContextPlan&)=nullptr;
    bool (*applyRoutePlan)(void*,const B58RoutePlan&)=nullptr;
    bool (*applyStabilityPlan)(void*,const B59Plan&)=nullptr;
};

inline bool ApplyB56_60(B56_60BackendOps& o,
                        const std::vector<B56LayerPlan>& a,
                        const B57ContextPlan& b,
                        const B58RoutePlan& c,
                        const B59Plan& d) {
    if(o.applyLayerPlans && !o.applyLayerPlans(o.user,a)) return false;
    if(o.applyContextPlan && !o.applyContextPlan(o.user,b)) return false;
    if(o.applyRoutePlan && !o.applyRoutePlan(o.user,c)) return false;
    if(o.applyStabilityPlan && !o.applyStabilityPlan(o.user,d)) return false;
    return true;
}

}
