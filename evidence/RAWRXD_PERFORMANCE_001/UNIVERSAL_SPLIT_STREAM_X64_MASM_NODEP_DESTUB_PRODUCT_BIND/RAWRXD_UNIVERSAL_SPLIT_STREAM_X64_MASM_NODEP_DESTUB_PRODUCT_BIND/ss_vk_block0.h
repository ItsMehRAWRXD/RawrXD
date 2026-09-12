/* ss_vk_block0.h — plan-driven block-0 forward on live SsVk */
#ifndef SS_VK_BLOCK0_H
#define SS_VK_BLOCK0_H
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_block_forward.h"
int ss_vk_block0_forward(SsVk *v, const SsModelPlan *plan, SsBlockForwardResult *r);
#endif
