/* ur_plan.c — adapter emits exact current-op regions; residency physicalizes */
#include "ur_plan.h"
#include <string.h>

void ur_plan_clear(UrOpPlan *p) { if (p) memset(p, 0, sizeof *p); }

int ur_plan_begin(UrOpPlan *p, UrModelId model, UrModelGeneration mgen,
                  UrSessionId session, UrTicket ticket)
{
    if (!p || !model || !ticket) return UR_E_ARG;
    memset(p, 0, sizeof *p);
    p->model = model; p->model_gen = mgen; p->session = session; p->ticket = ticket;
    return UR_OK;
}

int ur_plan_add(UrOpPlan *p, UrRegionId id, uint32_t lane)
{
    if (!p || !id || !p->ticket) return UR_E_ARG;
    if (lane < UR_LANE_META || lane > UR_LANE_GPU_WS) return UR_E_ARG;
    if (p->count >= UR_PLAN_CAP) return UR_E_OOM;
    p->regions[p->count] = id;
    p->lanes[p->count] = lane;
    p->count++;
    return UR_OK;
}

int ur_plan_observe_router(UrOpPlan *p)
{
    if (!p || !p->ticket) return UR_E_ARG;
    p->router_observed = 1;
    return UR_OK;
}

int ur_plan_require(UrRuntime *r, UrOpPlan *p)
{
    uint32_t i;
    const uint8_t *ptr; uint64_t n; UrGeneration g;
    if (!r || !p || !p->ticket || !p->count) return UR_E_ARG;
    for (i = 0; i < p->count; i++) {
        if (p->lanes[i] == UR_LANE_EXPERT && !p->router_observed) {
            r->tel.reject_expert_before_router++;
            return UR_E_ROUTER;
        }
    }
    for (i = 0; i < p->count; i++) {
        int rc = ur_require_region(r, p->ticket, p->regions[i],
                                   UR_REASON_CURRENT_OP, &ptr, &n, &g);
        if (rc) return rc;
    }
    r->tel.plan_batch_ok++;
    return UR_OK;
}
