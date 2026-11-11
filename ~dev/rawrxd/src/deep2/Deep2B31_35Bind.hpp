#pragma once
#include "Deep2B31QuantSuperkernel.hpp"
#include "Deep2B32FlashMLA.hpp"
#include "Deep2B33ExpertStriping.hpp"
#include "Deep2B34FusedKvAttention.hpp"
#include "Deep2B35DeviceTokenHandoff.hpp"

namespace Deep2 {

struct B31_35BackendOps {
    void* user = nullptr;
    bool (*applyQuantSuperkernel)(void*, const B31QuantPlan&) = nullptr;
    bool (*applyFlashMla)(void*, const B32FlashMlaPlan&) = nullptr;
    bool (*applyExpertStriping)(void*, const B33StripePlan&) = nullptr;
    bool (*applyFusedKvAttention)(void*, const B34KvAttnPlan&) = nullptr;
    bool (*applyDeviceTokenHandoff)(void*, const B35HandoffPlan&) = nullptr;
};

inline bool ApplyB31_35(B31_35BackendOps& o,
                        const B31QuantPlan& q,
                        const B32FlashMlaPlan& m,
                        const B33StripePlan& e,
                        const B34KvAttnPlan& k,
                        const B35HandoffPlan& h) {
    if (o.applyQuantSuperkernel && !o.applyQuantSuperkernel(o.user, q)) return false;
    if (o.applyFlashMla && !o.applyFlashMla(o.user, m)) return false;
    if (o.applyExpertStriping && !o.applyExpertStriping(o.user, e)) return false;
    if (o.applyFusedKvAttention && !o.applyFusedKvAttention(o.user, k)) return false;
    if (o.applyDeviceTokenHandoff && !o.applyDeviceTokenHandoff(o.user, h)) return false;
    return true;
}

} // namespace Deep2
