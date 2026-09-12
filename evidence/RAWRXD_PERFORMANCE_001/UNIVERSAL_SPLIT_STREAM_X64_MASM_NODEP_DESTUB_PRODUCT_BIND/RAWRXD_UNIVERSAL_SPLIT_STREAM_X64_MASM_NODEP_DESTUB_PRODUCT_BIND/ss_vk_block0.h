/* ss_vk_block0.h — plan-driven block-N forward (block0 seal + Phase-1) */
#ifndef SS_VK_BLOCK0_H
#define SS_VK_BLOCK0_H
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_block_forward.h"
#include "ss_block_loop.h"
int ss_vk_block_forward(SsVk *v, const SsModelPlan *plan, uint32_t block,
                        SsBlockForwardResult *r, uint64_t *res_ns, uint64_t *op_ns);
/* chain=1: xin = actb?:outb (continuity). chain=0: blk0 always outb. */
int ss_vk_block_forward_ex(SsVk *v, const SsModelPlan *plan, uint32_t block,
                           SsBlockForwardResult *r, uint64_t *res_ns, uint64_t *op_ns,
                           int chain);
int ss_vk_block0_forward(SsVk *v, const SsModelPlan *plan, SsBlockForwardResult *r);
int ss_vk_phase1_block_loop(SsVk *v, const SsModelPlan *plan, SsPhase1Loop *L);
#endif
