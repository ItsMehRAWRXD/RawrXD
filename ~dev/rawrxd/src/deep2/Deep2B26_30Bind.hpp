#pragma once
#include "Deep2B26AttentionSuperkernel.hpp"
#include "Deep2B27MoESuperkernel.hpp"
#include "Deep2B28DeviceLogits.hpp"
#include "Deep2B29LayerChain.hpp"

namespace Deep2 {

struct B26_30BackendOps {
    void* user = nullptr;
    bool (*applyAttentionPlan)(void*, const B26AttentionPlan&) = nullptr;
    bool (*applyMoEPlan)(void*, const B27MoEPlan&) = nullptr;
    bool (*applyDeviceLogitsPlan)(void*, const B28DeviceLogitsPlan&) = nullptr;
    bool (*applyLayerChain)(void*, const B29ChainPlan&) = nullptr;
};

inline bool ApplyB26_30(B26_30BackendOps& o,
                        const B26AttentionPlan& a,
                        const B27MoEPlan& m,
                        const B28DeviceLogitsPlan& l,
                        const B29ChainPlan& c) {
    if (o.applyAttentionPlan && !o.applyAttentionPlan(o.user, a)) return false;
    if (o.applyMoEPlan && !o.applyMoEPlan(o.user, m)) return false;
    if (o.applyDeviceLogitsPlan && !o.applyDeviceLogitsPlan(o.user, l)) return false;
    if (o.applyLayerChain && !o.applyLayerChain(o.user, c)) return false;
    return true;
}

} // namespace Deep2
