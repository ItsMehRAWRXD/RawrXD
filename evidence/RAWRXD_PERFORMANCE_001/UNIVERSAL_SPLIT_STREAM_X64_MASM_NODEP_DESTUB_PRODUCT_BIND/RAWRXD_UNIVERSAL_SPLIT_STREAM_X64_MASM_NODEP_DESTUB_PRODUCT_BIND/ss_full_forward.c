/* ss_full_forward.c — refuses PASS until every block executes for real */
#include "ss_full_forward.h"
#include <stdio.h>
int ss_full_model_forward(const SsModelPlan *model, SsKvCache *kv,
                          uint32_t token, uint32_t position, SsActView *final_act)
{
    (void)kv; (void)token; (void)position; (void)final_act;
    if (!model || !model->planReal) return 100;
    printf("FULL_MODEL_FORWARD_ATTEMPT block_count=%u blocks_present=%u\n",
           model->blockCount, model->blocksPresent);
    printf("ALL_BLOCKS_COMPLETED=0 ATTENTION_REAL=0 KV_CACHE_REAL=0\n");
    printf("FULL_MODEL_FORWARD=0 ABBREVIATED_CHAIN=1 PROMOTE=0\n");
    printf("NEXT_GATE=ss_forward_block REAL implementation\n");
    return 100; /* NOT_RUN */
}
