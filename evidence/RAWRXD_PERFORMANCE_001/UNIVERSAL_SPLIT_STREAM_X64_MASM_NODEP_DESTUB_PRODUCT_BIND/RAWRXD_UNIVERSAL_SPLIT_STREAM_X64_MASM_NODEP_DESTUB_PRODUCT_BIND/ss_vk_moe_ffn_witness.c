/* ss_vk_moe_ffn_witness.c — block0 attn+dense FFN + block3 MoE */
#include "ss_moe_ffn.h"
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_vk_block0.h"
#include "ss_block_forward.h"
#include <string.h>
int ss_vk_dense_ffn(SsVk *v, const SsModelPlan *plan, uint32_t block, SsMoeFfnResult *r);
int ss_vk_moe_block(SsVk *v, const SsModelPlan *plan, uint32_t block, SsMoeFfnResult *r);
int ss_vk_moe_ffn_witness(SsVk *v, const SsModelPlan *plan, SsMoeFfnResult *r)
{
    SsBlockForwardResult br;
    if (!v || !plan || !r || !plan->planReal) return 100;
    memset(r, 0, sizeof *r);
    if (ss_vk_block_forward(v, plan, 0, &br, 0, 0) || !br.completed) {
        r->first_fail = 1; return 100;
    }
    if (ss_vk_dense_ffn(v, plan, 0, r)) { r->first_fail = 2; return 100; }
    r->block0_full_real = r->ffn_gate_real && r->ffn_up_real && r->ffn_act_real
        && r->ffn_down_real && r->block_output_real && br.completed;
    if (!r->block0_full_real) { r->first_fail = 2; return 100; }
    if (ss_vk_moe_block(v, plan, 3, r)) { r->first_fail = 3; return 100; }
    r->pass = r->block0_full_real && r->moe_router_real && r->router_logits_real
        && r->topk_selection_real && r->expert_ids_valid && r->expert_weights_real
        && r->expert_weight_sum_valid && r->moe_out_residual && r->block_output_real;
    if (!r->pass) r->first_fail = 4;
    return r->pass ? 0 : 100;
}
