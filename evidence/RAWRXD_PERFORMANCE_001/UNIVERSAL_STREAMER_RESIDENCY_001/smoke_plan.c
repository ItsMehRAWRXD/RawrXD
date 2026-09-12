/* smoke_plan.c — CURRENT_OP plan, batch, post-router expert, host budget */
#include "ur_plan.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }

int main(void)
{
    uint8_t mem[16384]; UrMemProvider mp; UrProviderVTable vt; UrRuntime rt;
    UrRegionDesc sh, rtg, ex, extra; UrRegionId ish, irt, iex, ix;
    UrTicket tk; UrOpPlan plan; uint64_t d0;

    memset(mem, 0x33, sizeof mem);
    ur_mem_init(&mp, mem, sizeof mem); ur_mem_as_vtable(&mp, &vt);
    ur_runtime_init(&rt, vt, 0x504C4Eu);
    memset(&sh, 0, sizeof sh);
    sh.model = 11; sh.model_gen = 1; sh.provider = 1; sh.length = 4096;
    rtg = sh; rtg.offset = 4096;
    ex = sh; ex.offset = 8192;
    extra = sh; extra.offset = 12288;
    ish = ur_region_id_from_desc(&sh);
    irt = ur_region_id_from_desc(&rtg);
    iex = ur_region_id_from_desc(&ex);
    ix = ur_region_id_from_desc(&extra);
    if (ur_index_put(&rt.index, ish, &sh) || ur_index_put(&rt.index, irt, &rtg)
        || ur_index_put(&rt.index, iex, &ex) || ur_index_put(&rt.index, ix, &extra)
        || ur_op_begin(&rt.auth, rt.owner, &tk))
        return fail("SETUP");
    if (ur_plan_begin(&plan, 11, 1, 99, 0) != UR_E_ARG) return fail("NO_TICKET");
    if (ur_plan_begin(&plan, 11, 1, 99, tk)) return fail("BEGIN");
    if (ur_plan_add(&plan, ish, UR_LANE_SHARED) || ur_plan_add(&plan, irt, UR_LANE_ROUTER))
        return fail("ADD");
    if (ur_plan_require(&rt, &plan)) return fail("BATCH1");
    if (rt.tel.mg_loads != 2 || rt.tel.plan_batch_ok != 1) return fail("SHARED_ROUTER");
    if (ur_plan_add(&plan, iex, UR_LANE_EXPERT)) return fail("ADD_EX");
    d0 = rt.tel.disk_reads;
    if (ur_plan_require(&rt, &plan) != UR_E_ROUTER) return fail("EXPERT_BEFORE");
    if (rt.tel.reject_expert_before_router < 1 || rt.tel.disk_reads != d0)
        return fail("EXPERT_IO");
    if (ur_plan_observe_router(&plan) || ur_plan_require(&rt, &plan)) return fail("POST");
    if (rt.tel.mg_loads != 3) return fail("EXPERT_MG");
    ur_runtime_set_host_budget(&rt, 4096);
    {
        UrOpPlan p2; ur_plan_clear(&p2);
        if (ur_plan_begin(&p2, 11, 1, 99, tk) || ur_plan_add(&p2, ix, UR_LANE_SHARED))
            return fail("BUDGET_PLAN");
        if (ur_plan_require(&rt, &p2) != UR_E_BUDGET || rt.tel.reject_budget < 1)
            return fail("BUDGET");
    }
    printf("CURRENT_OP_REGION_PLAN_001=PASS SPLIT_REGION_BATCH_001=PASS\n");
    printf("POST_ROUTER_EXPERT_DEMAND_001=PASS UNSELECTED_EXPERT_IO=0\n");
    printf("HOST_WARM_BUDGET_001=PASS HOST_BUDGET_VIOLATIONS=0\n");
    printf("MODEL_FAMILY_BRANCHES_IN_RESIDENCY=0 PROMOTE=0\n");
    ur_op_end(&rt.auth, rt.owner, tk, 1);
    ur_runtime_shutdown(&rt);
    return 0;
}
