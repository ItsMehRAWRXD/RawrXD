/* ss_plan_load.h — load plan tensor bindings from shard files */
#ifndef SS_PLAN_LOAD_H
#define SS_PLAN_LOAD_H
#include "ss_model_plan.h"
int ss_plan_load_ref(const SsModelPlan *plan, const SsTensorRef *ref, void **out, uint64_t *n);
#endif
