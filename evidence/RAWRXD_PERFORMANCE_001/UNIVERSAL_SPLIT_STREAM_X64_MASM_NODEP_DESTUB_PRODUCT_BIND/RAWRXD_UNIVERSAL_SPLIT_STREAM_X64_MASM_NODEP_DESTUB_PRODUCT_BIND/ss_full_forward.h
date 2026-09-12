/* ss_full_forward.h — all-block forward; authority gated separately */
#ifndef SS_FULL_FORWARD_H
#define SS_FULL_FORWARD_H
#include "ss_model_plan.h"
#include "ss_kv_cache.h"
#include "ss_block_forward.h"
int ss_full_model_forward(const SsModelPlan *model, SsKvCache *kv,
                          uint32_t token, uint32_t position, SsActView *final_act);
#endif
