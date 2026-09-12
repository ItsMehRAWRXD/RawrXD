/* ss_plan_load_slice.h */
#ifndef SS_PLAN_LOAD_SLICE_H
#define SS_PLAN_LOAD_SLICE_H
#include "ss_model_plan.h"
int ss_plan_load_slice(const SsModelPlan *plan, uint32_t shard, uint64_t off,
                       uint64_t n, void **out);
#endif
