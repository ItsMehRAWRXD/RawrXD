/* ss_block_forward.c — hold: attention/RoPE/MoE not wired; FULL_MODEL_FORWARD=0 */
#include "ss_block_forward.h"
#include <stdio.h>
int ss_forward_block(const SsModelPlan *model, uint32_t block, uint32_t position,
                     SsKvCache *kv, const SsActView *in, SsActView *out)
{
    (void)kv; (void)in; (void)out;
    if (!model || block >= model->blockCount) return 100;
    if (!model->blocks[block].attnNorm.present) return 100;
    printf("BLOCK_FORWARD_STUB block=%u pos=%u ATTENTION_REAL=0 ROPE_REAL=0 MOE_REAL=0\n",
           block, position);
    printf("FULL_MODEL_FORWARD=0 NEXT_GATE=DEEP2_ATTENTION_KERNELS\n");
    return 100; /* NOT_RUN != PASS */
}
