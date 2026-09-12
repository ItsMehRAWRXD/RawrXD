/* ss_final_norm_lm_print.c */
#include "ss_final_norm_lm.h"
#include <stdio.h>
void ss_final_norm_lm_print(const SsFinalNormLm *r)
{
    if (!r) return;
    printf("DEEP2_FINAL_NORM_LM_HEAD_REAL=%s\n", r->pass ? "PASS" : "FAIL");
    printf("INPUT_FROM_FULL_BLOCK_LOOP=%d ABBREVIATED_BLK0_SHORTCUT=%d\n",
           r->input_from_full_loop, r->abbreviated_shortcut);
    printf("FINAL_NORM_REAL=%d LM_HEAD_REAL=%d LOGITS_REAL=%d\n",
           r->final_norm_real, r->lm_head_real, r->logits_real);
    printf("LOGITS_COUNT=%u LOGITS_FINITE=%d LOGITS_NONCONSTANT=%d\n",
           r->logits_count, r->logits_finite, r->logits_nonconstant);
    printf("ACT_HASH_IN=0x%llX EMBD=%u\n",
           (unsigned long long)r->act_hash_in, r->embd);
    printf("FULL_MODEL_FORWARD=%d ALL_BLOCKS_COMPLETED=%d\n",
           r->full_model_forward, r->all_blocks_completed);
    printf("GENERATED_TOKENS=%d FULL_MODEL_DECODE=%d\n",
           r->generated_tokens, r->full_model_decode);
    printf("FULL_MODEL_TPS_AUTHORITY=0 PROMOTE=0\n");
    if (r->pass)
        printf("NEXT_GATE=DEEP2_FULL_DECODE_TOKEN_REAL\n");
    else
        printf("FIRST_FAIL=%u NEXT_GATE=DEEP2_FINAL_NORM_LM_HEAD_REAL\n",
               r->first_fail);
}
