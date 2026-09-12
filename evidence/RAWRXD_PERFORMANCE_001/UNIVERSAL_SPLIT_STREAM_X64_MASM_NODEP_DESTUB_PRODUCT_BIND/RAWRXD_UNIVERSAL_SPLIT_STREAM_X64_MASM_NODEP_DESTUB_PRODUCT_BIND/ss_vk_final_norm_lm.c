/* ss_vk_final_norm_lm.c — plan output_norm + Q6_K lmhead on full-loop act */
#include "ss_final_norm_lm.h"
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_plan_load.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include <stdlib.h>
#include <string.h>
uint64_t ss_vk_act_hash(SsVk *v, VkDeviceMemory mem, uint32_t n);
int ss_vk_final_norm_lmhead(SsVk *v, const SsModelPlan *plan, int full_loop_pass,
                            SsFinalNormLm *r)
{
    void *hw = 0; uint64_t hn = 0;
    VkBuffer wn = 0, yn = 0, ww = 0;
    VkDeviceMemory wnm = 0, ynm = 0, wwm = 0;
    uint32_t emb, rows, cols; int ok = 0; void *map = 0; float *f;
    uint32_t i; float first = 0.f; int saw = 0, nonc = 0, fin = 1;
    memset(r, 0, sizeof *r);
    if (!v || !plan || !r) return 100;
    r->abbreviated_shortcut = 0;
    r->full_model_forward = full_loop_pass ? 1 : 0;
    r->all_blocks_completed = full_loop_pass ? 1 : 0;
    if (!full_loop_pass || !v->actb || !v->actmem || !plan->planReal) {
        r->first_fail = 1; return 100;
    }
    if (!plan->outputNorm.present || !plan->outputWeight.present) {
        r->first_fail = 2; return 100;
    }
    emb = plan->embeddingLength; r->embd = emb;
    r->act_hash_in = ss_vk_act_hash(v, v->actmem, emb);
    r->input_from_full_loop = r->act_hash_in != 0;
    if (!r->input_from_full_loop) { r->first_fail = 3; return 100; }
    if (ss_plan_load_ref(plan, &plan->outputNorm, &hw, &hn)
        || ss_vk_upload(v, hw, hn, &wn, &wnm)) { r->first_fail = 4; goto fail; }
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &yn, &ynm, 0)) {
        r->first_fail = 4; goto fail;
    }
    if (ss_vk_op_rms(v, v->actb, wn, hn, yn, emb)) { r->first_fail = 4; goto fail; }
    if (ss_vk_fin_obs(v, ynm, emb, &ok) || !ok) { r->first_fail = 4; goto fail; }
    ss_vk_dropb(v, &v->actb, &v->actmem);
    v->actb = yn; v->actmem = ynm; yn = 0; ynm = 0;
    r->final_norm_real = 1;
    ss_vk_dropb(v, &wn, &wnm);
    rows = plan->vocabSize ? plan->vocabSize : (uint32_t)plan->outputWeight.dims[1];
    cols = emb;
    if (ss_plan_load_ref(plan, &plan->outputWeight, &hw, &hn)
        || ss_vk_upload(v, hw, hn, &ww, &wwm)) { r->first_fail = 5; goto fail; }
    free(hw); hw = 0;
    if (!v->logitsb) {
        if (ss_vk_mkbuf(v, (VkDeviceSize)rows * 4ull, &v->logitsb, &v->logitsmem, 0)) {
            r->first_fail = 5; goto fail;
        }
    }
    if (ss_vk_op_gemv(v, ww, plan->outputWeight.bytes, v->actb, v->logitsb, rows, cols,
                      ss_vk_codec_ty(plan->outputWeight.codec))) {
        r->first_fail = 5; goto fail;
    }
    if (v->a.map(v->dev, v->logitsmem, 0, (VkDeviceSize)rows * 4ull, 0, &map) != VK_SUCCESS) {
        r->first_fail = 5; goto fail;
    }
    f = (float *)map;
    for (i = 0; i < rows; ++i) {
        if (!(f[i] == f[i]) || f[i] > 1e30f || f[i] < -1e30f) { fin = 0; break; }
        if (!saw) { first = f[i]; saw = 1; } else if (f[i] != first) nonc = 1;
    }
    v->a.unmap(v->dev, v->logitsmem);
    r->logits_count = rows; r->logits_finite = fin; r->logits_nonconstant = nonc;
    r->lm_head_real = fin && nonc && rows == plan->vocabSize;
    r->logits_real = r->lm_head_real;
    v->vocab_n = rows; v->logits_op = r->logits_real ? 1 : 0;
    ss_vk_dropb(v, &ww, &wwm);
    r->pass = r->input_from_full_loop && r->final_norm_real && r->lm_head_real
        && r->logits_real && !r->abbreviated_shortcut;
    if (!r->pass) r->first_fail = 6;
    return r->pass ? 0 : 100;
fail:
    free(hw);
    ss_vk_dropb(v, &wn, &wnm); ss_vk_dropb(v, &yn, &ynm); ss_vk_dropb(v, &ww, &wwm);
    return 100;
}
