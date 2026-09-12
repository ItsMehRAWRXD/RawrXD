/* ss_vk_resolved_block.c — attn + FFN from resolved tensors (no block#) */
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_vk_block0.h"
#include "ss_block_forward.h"
#include "ss_moe_ffn.h"
#include <string.h>
int ss_vk_dense_ffn(SsVk *v, const SsModelPlan *plan, uint32_t block, SsMoeFfnResult *r);
int ss_vk_moe_block(SsVk *v, const SsModelPlan *plan, uint32_t block, SsMoeFfnResult *r);
static int ffn_moe(const SsBlockPlan *b)
{
    return b->router.present && b->expertGate.present
        && b->expertUp.present && b->expertDown.present;
}
static int ffn_dense(const SsBlockPlan *b)
{
    return b->denseGate.present && b->denseUp.present && b->denseDown.present;
}
/* Returns: 0 ok; *was_moe 1/0; *attn*ffn*bind flags via out params. */
int ss_vk_run_resolved_block(SsVk *v, const SsModelPlan *plan, uint32_t i,
                             int *was_moe, int *attn_ok, int *ffn_ok, int *bind_ok)
{
    const SsBlockPlan *b; SsBlockForwardResult br; SsMoeFfnResult fr;
    if (!v || !plan || !was_moe || !attn_ok || !ffn_ok || !bind_ok) return 100;
    *was_moe = *attn_ok = *ffn_ok = *bind_ok = 0;
    if (i >= plan->blockCount) return 100;
    b = &plan->blocks[i];
    if (b->blockIndex != i) return 101;
    if (!b->attnNorm.present || !b->qA.present || !b->qB.present
        || !b->kvA.present || !b->kvB.present || !b->attnOut.present
        || !b->ffnNorm.present) return 102;
    *bind_ok = 1;
    if (ss_vk_block_forward_ex(v, plan, i, &br, 0, 0, 1) || !br.completed)
        return 103;
    *attn_ok = 1;
    memset(&fr, 0, sizeof fr);
    if (ffn_moe(b)) {
        *was_moe = 1;
        if (ss_vk_moe_block(v, plan, i, &fr) || !fr.block_output_real) return 104;
    } else if (ffn_dense(b)) {
        *was_moe = 0;
        if (ss_vk_dense_ffn(v, plan, i, &fr) || !fr.block_output_real) return 105;
    } else {
        return 106;
    }
    *ffn_ok = 1;
    return 0;
}
