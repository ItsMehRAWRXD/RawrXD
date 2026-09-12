/* ss_vk_moe_block.c — ffn_norm → router → topk → experts+shared → residual */
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_moe_ffn.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include "ss_plan_load.h"
#include "ss_topk.h"
#include "ss_silu_host.h"
#include <stdlib.h>
#include <string.h>
int ss_vk_moe_one_expert(SsVk *v, const SsModelPlan *plan, const SsBlockPlan *b,
                         uint32_t eid, VkBuffer xn, float *y_out);
static int shared_ffn(SsVk *v, const SsModelPlan *plan, const SsBlockPlan *b,
                      VkBuffer xn, float *y_out)
{
    void *hw = 0; uint64_t hn;
    VkBuffer wg = 0, g = 0, wu = 0, u = 0, wd = 0, y = 0, act = 0;
    VkDeviceMemory wgm = 0, gm = 0, wum = 0, um = 0, wdm = 0, ym = 0, actm = 0;
    uint32_t emb = plan->embeddingLength, ff; float *gf = 0, *uf = 0, *af = 0; void *map = 0;
    if (!b->sharedGate.present || !b->sharedUp.present || !b->sharedDown.present) return 100;
    ff = (uint32_t)b->sharedGate.dims[1];
    if (ss_plan_load_ref(plan, &b->sharedGate, &hw, &hn) || ss_vk_upload(v, hw, hn, &wg, &wgm))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &g, &gm, 0)) goto fail;
    if (ss_vk_op_gemv(v, wg, b->sharedGate.bytes, xn, g, ff, emb, ss_vk_codec_ty(b->sharedGate.codec)))
        goto fail;
    if (ss_plan_load_ref(plan, &b->sharedUp, &hw, &hn) || ss_vk_upload(v, hw, hn, &wu, &wum))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &u, &um, 0)) goto fail;
    if (ss_vk_op_gemv(v, wu, b->sharedUp.bytes, xn, u, ff, emb, ss_vk_codec_ty(b->sharedUp.codec)))
        goto fail;
    gf = (float *)malloc((size_t)ff * 4); uf = (float *)malloc((size_t)ff * 4);
    af = (float *)malloc((size_t)ff * 4);
    if (!gf || !uf || !af) goto fail;
    if (v->a.map(v->dev, gm, 0, (VkDeviceSize)ff * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    memcpy(gf, map, (size_t)ff * 4); v->a.unmap(v->dev, gm);
    if (v->a.map(v->dev, um, 0, (VkDeviceSize)ff * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    memcpy(uf, map, (size_t)ff * 4); v->a.unmap(v->dev, um);
    ss_silu_mul(gf, uf, af, ff);
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &act, &actm, &map)) goto fail;
    memcpy(map, af, (size_t)ff * 4); v->a.unmap(v->dev, actm);
    if (ss_plan_load_ref(plan, &b->sharedDown, &hw, &hn) || ss_vk_upload(v, hw, hn, &wd, &wdm))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &y, &ym, 0)) goto fail;
    if (ss_vk_op_gemv(v, wd, b->sharedDown.bytes, act, y, emb, ff, ss_vk_codec_ty(b->sharedDown.codec)))
        goto fail;
    if (v->a.map(v->dev, ym, 0, (VkDeviceSize)emb * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    memcpy(y_out, map, (size_t)emb * 4); v->a.unmap(v->dev, ym);
    free(gf); free(uf); free(af);
    ss_vk_dropb(v, &wg, &wgm); ss_vk_dropb(v, &g, &gm); ss_vk_dropb(v, &wu, &wum);
    ss_vk_dropb(v, &u, &um); ss_vk_dropb(v, &wd, &wdm); ss_vk_dropb(v, &act, &actm);
    ss_vk_dropb(v, &y, &ym);
    return 0;
fail:
    free(hw); free(gf); free(uf); free(af);
    ss_vk_dropb(v, &wg, &wgm); ss_vk_dropb(v, &g, &gm); ss_vk_dropb(v, &wu, &wum);
    ss_vk_dropb(v, &u, &um); ss_vk_dropb(v, &wd, &wdm); ss_vk_dropb(v, &act, &actm);
    ss_vk_dropb(v, &y, &ym);
    return 100;
}
int ss_vk_moe_block(SsVk *v, const SsModelPlan *plan, uint32_t block, SsMoeFfnResult *r)
{
    const SsBlockPlan *b; void *hw = 0; uint64_t hn = 0;
    VkBuffer xin, wn = 0, xn = 0, wr = 0, logitsb = 0, yb = 0;
    VkDeviceMemory xinm, wnm = 0, xnm = 0, wrm = 0, lm = 0, ym = 0;
    uint32_t emb, ne, k, i, j; float *logits = 0, *acc = 0, *tmp = 0, *sh = 0, wts[8];
    float *inf, *ouf; void *map = 0; int ok = 0;
    if (!v || !plan || !r || block >= plan->blockCount) return 100;
    b = &plan->blocks[block];
    xin = v->actb ? v->actb : v->outb;
    xinm = v->actb ? v->actmem : v->outmem;
    if (!xin || !b->isMoe || !b->ffnNorm.present || !b->router.present) return 100;
    emb = plan->embeddingLength; ne = plan->expertCount ? plan->expertCount : 256;
    k = plan->expertTopK ? plan->expertTopK : 8; if (k > 8u) k = 8;
    r->topk = k;
    if (ss_plan_load_ref(plan, &b->ffnNorm, &hw, &hn) || ss_vk_upload(v, hw, hn, &wn, &wnm))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &xn, &xnm, 0)) goto fail;
    if (ss_vk_op_rms(v, xin, wn, hn, xn, emb)) goto fail;
    if (ss_plan_load_ref(plan, &b->router, &hw, &hn) || ss_vk_upload(v, hw, hn, &wr, &wrm))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ne * 4ull, &logitsb, &lm, 0)) goto fail;
    if (ss_vk_op_gemv(v, wr, b->router.bytes, xn, logitsb, ne, emb, ss_vk_codec_ty(b->router.codec)))
        goto fail;
    r->moe_router_real = 1; r->router_logits_real = 1;
    logits = (float *)malloc((size_t)ne * 4);
    if (!logits || v->a.map(v->dev, lm, 0, (VkDeviceSize)ne * 4ull, 0, &map) != VK_SUCCESS)
        goto fail;
    memcpy(logits, map, (size_t)ne * 4); v->a.unmap(v->dev, lm);
    if (b->expProbsB.present && b->expProbsB.codec == SS_CODEC_F32
        && b->expProbsB.bytes >= (uint64_t)ne * 4ull) {
        if (ss_plan_load_ref(plan, &b->expProbsB, &hw, &hn) == 0) {
            for (i = 0; i < ne; ++i) logits[i] += ((float *)hw)[i];
            free(hw); hw = 0;
        }
    }
    if (ss_topk_softmax(logits, ne, k, r->selected, wts, &r->weight_sum)) goto fail;
    r->topk_selection_real = 1; r->expert_weights_real = 1;
    r->expert_ids_valid = 1; r->expert_weight_sum_valid = (r->weight_sum > 0.99f && r->weight_sum < 1.01f);
    for (i = 0; i < k; ++i) if (r->selected[i] >= ne) r->expert_ids_valid = 0;
    acc = (float *)calloc(emb, sizeof(float)); tmp = (float *)malloc((size_t)emb * 4);
    sh = (float *)malloc((size_t)emb * 4);
    if (!acc || !tmp || !sh) goto fail;
    for (i = 0; i < k; ++i) {
        if (ss_vk_moe_one_expert(v, plan, b, r->selected[i], xn, tmp)) goto fail;
        for (j = 0; j < emb; ++j) acc[j] += wts[i] * tmp[j];
    }
    if (shared_ffn(v, plan, b, xn, sh)) goto fail;
    for (j = 0; j < emb; ++j) acc[j] += sh[j];
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &yb, &ym, &map)) goto fail;
    memcpy(map, acc, (size_t)emb * 4); v->a.unmap(v->dev, ym);
    if (v->a.map(v->dev, xinm, 0, (VkDeviceSize)emb * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    inf = (float *)map;
    if (v->a.map(v->dev, ym, 0, (VkDeviceSize)emb * 4ull, 0, (void **)&ouf) != VK_SUCCESS) {
        v->a.unmap(v->dev, xinm); goto fail;
    }
    for (j = 0; j < emb; ++j) ouf[j] = inf[j] + ouf[j];
    v->a.unmap(v->dev, ym); v->a.unmap(v->dev, xinm);
    if (ss_vk_fin_obs(v, ym, emb, &ok) || !ok) goto fail;
    r->moe_out_residual = 1; r->block_output_real = 1;
    ss_vk_dropb(v, &v->actb, &v->actmem);
    v->actb = yb; v->actmem = ym; yb = 0; ym = 0;
    free(logits); free(acc); free(tmp); free(sh);
    ss_vk_dropb(v, &wn, &wnm); ss_vk_dropb(v, &xn, &xnm); ss_vk_dropb(v, &wr, &wrm);
    ss_vk_dropb(v, &logitsb, &lm);
    return 0;
fail:
    free(hw); free(logits); free(acc); free(tmp); free(sh);
    ss_vk_dropb(v, &wn, &wnm); ss_vk_dropb(v, &xn, &xnm); ss_vk_dropb(v, &wr, &wrm);
    ss_vk_dropb(v, &logitsb, &lm); ss_vk_dropb(v, &yb, &ym);
    return 100;
}
