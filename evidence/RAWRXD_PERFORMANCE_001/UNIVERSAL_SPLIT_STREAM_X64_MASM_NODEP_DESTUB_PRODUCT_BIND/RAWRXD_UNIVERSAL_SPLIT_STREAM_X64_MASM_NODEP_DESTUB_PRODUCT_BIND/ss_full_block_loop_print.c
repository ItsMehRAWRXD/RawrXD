/* ss_full_block_loop_print.c — mechanical continuity receipt */
#include "ss_full_block_loop.h"
#include <stdio.h>
void ss_full_block_loop_print(const SsFullBlockLoop *L)
{
    if (!L) return;
    printf("DEEP2_FULL_BLOCK_LOOP_REAL=%s\n", L->pass ? "PASS" : "FAIL");
    printf("DECLARED_BLOCK_COUNT=%u BLOCK_PLAN_COUNT=%u\n", L->declared, L->plan_count);
    printf("BLOCKS_ENTERED=%u BLOCKS_COMPLETED=%u BLOCK_ORDER_VALID=%u\n",
           L->entered, L->completed, L->block_order_valid);
    printf("FIRST_BLOCK=%u LAST_BLOCK=%u\n", L->first_block, L->last_block);
    printf("DENSE_BLOCKS_EXECUTED=%u MOE_BLOCKS_EXECUTED=%u\n",
           L->dense_exec, L->moe_exec);
    printf("FFN_TYPE_FROM_RESOLVED_TENSORS=%u\n", L->ffn_from_tensors);
    printf("CHAIN_CONTINUITY_VALID=%u PREV_OUTPUT_TO_NEXT_INPUT_MATCH=%u/%u\n",
           L->chain_continuity_valid, L->continuity_match, L->continuity_need);
    printf("REPEATED_BLOCK0_ACTIVATION=%u SYNTHETIC_BLOCK_RESET_COUNT=%u\n",
           L->repeated_blk0, L->synthetic_reset);
    printf("ORIGINAL_EMBEDDING_RELOAD_COUNT=%u\n", L->embd_reload);
    printf("BLOCK_LOCAL_TENSOR_BINDING_VALID=%u/%u\n", L->bind_ok, L->plan_count);
    printf("ATTENTION_REAL_BLOCKS=%u/%u FFN_REAL_BLOCKS=%u/%u\n",
           L->attn_ok, L->plan_count, L->ffn_ok, L->plan_count);
    printf("RESIDUAL_REAL_BLOCKS=%u/%u FINAL_BLOCK_OUTPUT_REAL=%u\n",
           L->residual_ok, L->plan_count, L->final_out_real);
    printf("FULL_MODEL_FORWARD=%u ALL_BLOCKS_COMPLETED=%u\n",
           L->full_model_forward, L->all_blocks_completed);
    printf("LM_HEAD_REAL=0 GENERATED_TOKENS=0 FULL_MODEL_DECODE=0\n");
    printf("FULL_MODEL_TPS_AUTHORITY=0 PROMOTE=0\n");
    if (L->pass)
        printf("NEXT_GATE=DEEP2_FINAL_NORM_LM_HEAD_REAL\n");
    else
        printf("FIRST_FAIL_BLOCK=%u NEXT_GATE=DEEP2_FULL_BLOCK_LOOP_REAL\n",
               L->first_fail_block);
}
