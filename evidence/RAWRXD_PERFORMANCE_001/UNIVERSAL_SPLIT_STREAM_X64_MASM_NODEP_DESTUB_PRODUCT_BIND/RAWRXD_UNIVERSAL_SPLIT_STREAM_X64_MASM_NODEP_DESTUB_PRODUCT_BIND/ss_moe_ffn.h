/* ss_moe_ffn.h — DEEP2_MOE_OR_FULL_BLOCK_FFN receipt */
#ifndef SS_MOE_FFN_H
#define SS_MOE_FFN_H
#include <stdint.h>
typedef struct SsMoeFfnResult {
    int moe_router_real, router_logits_real, topk_selection_real;
    int expert_ids_valid, expert_weights_real, expert_weight_sum_valid;
    int ffn_gate_real, ffn_up_real, ffn_act_real, ffn_down_real;
    int moe_out_residual, block_output_real, block0_full_real;
    uint32_t topk, selected[8];
    float weight_sum;
    int pass;
    uint32_t first_fail;
} SsMoeFfnResult;
struct SsVk;
struct SsModelPlan;
void ss_moe_ffn_print(const SsMoeFfnResult *r);
int ss_vk_moe_ffn_witness(struct SsVk *v, const struct SsModelPlan *plan, SsMoeFfnResult *r);
#endif
