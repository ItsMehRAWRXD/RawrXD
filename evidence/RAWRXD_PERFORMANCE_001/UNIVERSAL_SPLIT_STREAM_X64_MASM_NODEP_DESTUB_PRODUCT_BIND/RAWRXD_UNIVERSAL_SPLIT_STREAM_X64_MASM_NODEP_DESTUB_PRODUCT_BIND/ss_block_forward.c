/* ss_block_forward.c — hold: attention/RoPE/MoE not wired; FULL_MODEL_FORWARD=0 */
#include "ss_block_forward.h"
#include <stdio.h>
int ss_forward_block(const SsModelPlan *model, uint32_t block, uint32_t position,
                     SsKvCache *kv, const SsActView *in, SsActView *out)
{
    SsBlockForwardResult r;
    (void)kv; (void)in; (void)out; (void)position;
    ss_block_fwd_reset(&r, block);
    if (!model || !model->planReal || block >= model->blockCount) {
        r.first_failure_stage = SS_BF_PLAN;
        ss_block_fwd_finalize(&r);
        ss_block_fwd_print(&r);
        return 100;
    }
    if (!model->blocks[block].attnNorm.present) {
        r.first_failure_stage = SS_BF_ATTN_NORM;
        ss_block_fwd_finalize(&r);
        ss_block_fwd_print(&r);
        return 100;
    }
    r.block_plan_resolved = 1;
    r.expected_shard_id = model->blocks[block].attnNorm.shardIndex;
    r.expected_weight_off = model->blocks[block].attnNorm.fileOffset;
    r.real_weight_ranges = 1;
    r.plan_bindings_used = 1;
    printf("BLOCK_FORWARD_STUB block=%u ATTENTION_REAL=0 ROPE_REAL=0 MOE_REAL=0\n", block);
    printf("FULL_MODEL_FORWARD=0 NEXT_GATE=DEEP2_ATTENTION_KERNELS\n");
    r.first_failure_stage = SS_BF_ATTN_NORM;
    ss_block_fwd_finalize(&r);
    ss_block_fwd_print(&r);
    return 100; /* NOT_RUN != PASS */
}
