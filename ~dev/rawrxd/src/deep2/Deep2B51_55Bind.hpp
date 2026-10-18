#pragma once
#include "Deep2B51OwnerDirector.hpp"
#include "Deep2B52MemoryTail.hpp"
#include "Deep2B53ComputeTail.hpp"
#include "Deep2B54DeviceGraph.hpp"
#include "Deep2B55AsymptoticSeal.hpp"

namespace Deep2 {

struct B51_55BackendOps {
    void* user=nullptr;
    bool (*applyOwnerPlan)(void*,const B51Plan&)=nullptr;
    bool (*applyMemoryPlan)(void*,const B52MemoryPlan&)=nullptr;
    bool (*applyComputeVariant)(void*,const B53Variant&)=nullptr;
    bool (*installDeviceGraph)(void*,const B54GraphPlan&)=nullptr;
};

inline bool ApplyB51_55(B51_55BackendOps& o,
                        const B51Plan& a,
                        const B52MemoryPlan& b,
                        const B53Variant& c,
                        const B54GraphPlan& d) {
    if(o.applyOwnerPlan && !o.applyOwnerPlan(o.user,a)) return false;
    if(a.enableMemoryPath && o.applyMemoryPlan && !o.applyMemoryPlan(o.user,b)) return false;
    if(a.enableComputePath && o.applyComputeVariant && !o.applyComputeVariant(o.user,c)) return false;
    if(o.installDeviceGraph && !o.installDeviceGraph(o.user,d)) return false;
    return true;
}

}
