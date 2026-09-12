/* ur_plan.h — CURRENT_OP_REGION_PLAN + batch require */
#ifndef UR_PLAN_H
#define UR_PLAN_H
#include "ur_residency.h"
#ifdef __cplusplus
extern "C" {
#endif

#define UR_PLAN_CAP 16

typedef struct {
    UrModelId model;
    UrModelGeneration model_gen;
    UrSessionId session;
    UrTicket ticket;
    UrRegionId regions[UR_PLAN_CAP];
    uint32_t lanes[UR_PLAN_CAP];
    uint32_t count;
    uint32_t router_observed;
} UrOpPlan;

void ur_plan_clear(UrOpPlan *p);
int ur_plan_begin(UrOpPlan *p, UrModelId model, UrModelGeneration mgen,
                  UrSessionId session, UrTicket ticket);
int ur_plan_add(UrOpPlan *p, UrRegionId id, uint32_t lane);
int ur_plan_observe_router(UrOpPlan *p);
int ur_plan_require(UrRuntime *r, UrOpPlan *p);

#ifdef __cplusplus
}
#endif
#endif
