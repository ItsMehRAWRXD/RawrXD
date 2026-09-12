/* ss_moe_ffn_print.c */
#include "ss_moe_ffn.h"
#include <stdio.h>
void ss_moe_ffn_print(const SsMoeFfnResult *r)
{
    uint32_t i;
    if (!r) return;
    printf("DEEP2_MOE_OR_FULL_BLOCK_FFN=%s\n", r->pass ? "PASS" : "FAIL");
    printf("MOE_ROUTER_REAL=%d ROUTER_LOGITS_REAL=%d TOPK_SELECTION_REAL=%d\n",
           r->moe_router_real, r->router_logits_real, r->topk_selection_real);
    printf("EXPERT_IDS_VALID=%d EXPERT_WEIGHTS_REAL=%d EXPERT_WEIGHT_SUM_VALID=%d\n",
           r->expert_ids_valid, r->expert_weights_real, r->expert_weight_sum_valid);
    printf("TOPK=%u WEIGHT_SUM=%g SELECTED=", r->topk, (double)r->weight_sum);
    for (i = 0; i < r->topk && i < 8u; ++i) printf("%u%s", r->selected[i], i + 1u < r->topk ? "," : "");
    printf("\n");
    printf("FFN_GATE_REAL=%d FFN_UP_REAL=%d FFN_ACT_REAL=%d FFN_DOWN_REAL=%d\n",
           r->ffn_gate_real, r->ffn_up_real, r->ffn_act_real, r->ffn_down_real);
    printf("MOE_OUT_TO_RESIDUAL=%d BLOCK_OUTPUT_REAL=%d BLOCK_0_FULL_REAL=%d\n",
           r->moe_out_residual, r->block_output_real, r->block0_full_real);
    printf("FIRST_FAIL=%u FULL_MODEL_FORWARD=0 ALL_BLOCKS_COMPLETED=0 PROMOTE=0\n",
           r->first_fail);
    printf("NEXT_GATE=%s\n", r->pass ? "DEEP2_FULL_BLOCK_LOOP_REAL"
                                     : "DEEP2_MOE_OR_FULL_BLOCK_FFN");
}
