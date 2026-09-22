#pragma once
#include "Deep2RooflineTypes.hpp"
#include "Deep2QuantGemvRoofline.hpp"
#include "Deep2WaveOccupancy.hpp"
#include "Deep2KvMlaTraffic.hpp"
#include "Deep2MoEMathPlan.hpp"
#include "Deep2LaunchAmortizer.hpp"
#include "Deep2RooflineRatchet.hpp"

namespace Deep2 {

// No Vulkan headers here. Existing Deep2 Vulkan backend binds these callbacks.
struct RooflineBackendOps {
    void* user = nullptr;
    bool (*applyQuantPlan)(void*, uint32_t device, const QuantGemvPlan&) = nullptr;
    bool (*applyRowSplit)(void*, uint32_t gpu0Rows, uint32_t gpu1Rows) = nullptr;
    bool (*applyKvMlaPlan)(void*, const KvMlaPlan&) = nullptr;
    bool (*applyMoEPlan)(void*, const MoEMathPlan&) = nullptr;
    bool (*applyLaunchBatches)(void*, const std::vector<LaunchBatch>&) = nullptr;
};

inline bool ApplyRooflinePlans(RooflineBackendOps& ops,
                               const QuantGemvPlan& q0,
                               const QuantGemvPlan& q1,
                               const OccupancyPlan& occ,
                               const KvMlaPlan& kv,
                               const MoEMathPlan& moe,
                               const std::vector<LaunchBatch>& batches) {
    if (ops.applyQuantPlan) {
        if (!ops.applyQuantPlan(ops.user, 0, q0)) return false;
        if (!ops.applyQuantPlan(ops.user, 1, q1)) return false;
    }
    if (ops.applyRowSplit && !ops.applyRowSplit(ops.user, occ.gpu0Rows, occ.gpu1Rows))
        return false;
    if (ops.applyKvMlaPlan && !ops.applyKvMlaPlan(ops.user, kv))
        return false;
    if (ops.applyMoEPlan && !ops.applyMoEPlan(ops.user, moe))
        return false;
    if (ops.applyLaunchBatches && !ops.applyLaunchBatches(ops.user, batches))
        return false;
    return true;
}

} // namespace Deep2
