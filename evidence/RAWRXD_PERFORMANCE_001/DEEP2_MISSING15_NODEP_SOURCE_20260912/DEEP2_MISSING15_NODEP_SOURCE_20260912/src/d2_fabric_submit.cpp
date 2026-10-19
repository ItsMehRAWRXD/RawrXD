#include "d2_nodep.h"

extern "C" int d2_submit_same_token(const D2FabricPlan* plan, uint64_t token_id, D2FabricMetrics* out) {
    if (!plan || !out || !d2_validate_local_plan(plan)) return 0;
    D2SsVkBinding bind{};
    if (!d2_get_ssvk(&bind)) return 0;

    D2FabricTicket t0{}, t1{};
    D2LaneReceipt r0{}, r1{};
    D2ReduceReceipt rr{};

    // Critical ordering law: enqueue both independent device-local lanes before collecting either.
    if (!bind.enqueue(bind.ctx, &plan->lane[0], token_id, &t0)) return 0;
    if (!bind.enqueue(bind.ctx, &plan->lane[1], token_id, &t1)) return 0;
    if (!bind.collect(bind.ctx, &t0, &r0)) return 0;
    if (!bind.collect(bind.ctx, &t1, &r1)) return 0;
    if (!bind.reduce(bind.ctx, &t0, &t1, &rr)) return 0;
    return d2_measure_overlap(&r0, &r1, &rr, out);
}
