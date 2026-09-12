/* ss_vk_dense_ffn.c — blk dense ffn_norm → gate/up/SiLU → down → residual */
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_moe_ffn.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include "ss_plan_load.h"
#include "ss_silu_host.h"
#include <stdlib.h>
#include <string.h>
int ss_vk_dense_ffn(SsVk *v, const SsModelPlan *plan, uint32_t block, SsMoeFfnResult *r)
{
    const SsBlockPlan *b; void *hw = 0; uint64_t hn = 0;
    VkBuffer xin, wn = 0, xn = 0, wg = 0, g = 0, wu = 0, u = 0, wd = 0, y = 0, act = 0;
    VkDeviceMemory xinm, wnm = 0, xnm = 0, wgm = 0, gm = 0, wum = 0, um = 0, wdm = 0, ym = 0, actm = 0;
    uint32_t emb, ff, i; float *gf = 0, *uf = 0, *af = 0, *inf = 0, *ouf = 0; void *map = 0; int ok = 0;
    if (!v || !plan || !r || block >= plan->blockCount) return 100;
    b = &plan->blocks[block];
    xin = v->actb ? v->actb : v->outb;
    xinm = v->actb ? v->actmem : v->outmem;
    if (!xin || !xinm || !b->ffnNorm.present || !b->denseGate.present
        || !b->denseUp.present || !b->denseDown.present) return 100;
    emb = plan->embeddingLength;
    ff = (uint32_t)b->denseGate.dims[1];
    if (ss_plan_load_ref(plan, &b->ffnNorm, &hw, &hn) || ss_vk_upload(v, hw, hn, &wn, &wnm))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &xn, &xnm, 0)) goto fail;
    if (ss_vk_op_rms(v, xin, wn, hn, xn, emb)) goto fail;
    if (ss_plan_load_ref(plan, &b->denseGate, &hw, &hn) || ss_vk_upload(v, hw, hn, &wg, &wgm))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &g, &gm, 0)) goto fail;
    if (ss_vk_op_gemv(v, wg, b->denseGate.bytes, xn, g, ff, emb, ss_vk_codec_ty(b->denseGate.codec)))
        goto fail;
    r->ffn_gate_real = 1;
    if (ss_plan_load_ref(plan, &b->denseUp, &hw, &hn) || ss_vk_upload(v, hw, hn, &wu, &wum))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &u, &um, 0)) goto fail;
    if (ss_vk_op_gemv(v, wu, b->denseUp.bytes, xn, u, ff, emb, ss_vk_codec_ty(b->denseUp.codec)))
        goto fail;
    r->ffn_up_real = 1;
    if (v->a.map(v->dev, gm, 0, (VkDeviceSize)ff * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    gf = (float *)malloc((size_t)ff * 4ull); uf = (float *)malloc((size_t)ff * 4ull);
    af = (float *)malloc((size_t)ff * 4ull);
    if (!gf || !uf || !af) { v->a.unmap(v->dev, gm); goto fail; }
    memcpy(gf, map, (size_t)ff * 4ull); v->a.unmap(v->dev, gm);
    if (v->a.map(v->dev, um, 0, (VkDeviceSize)ff * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    memcpy(uf, map, (size_t)ff * 4ull); v->a.unmap(v->dev, um);
    ss_silu_mul(gf, uf, af, ff); r->ffn_act_real = 1;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &act, &actm, &map)) goto fail;
    memcpy(map, af, (size_t)ff * 4ull); v->a.unmap(v->dev, actm);
    if (ss_plan_load_ref(plan, &b->denseDown, &hw, &hn) || ss_vk_upload(v, hw, hn, &wd, &wdm))
        goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &y, &ym, 0)) goto fail;
    if (ss_vk_op_gemv(v, wd, b->denseDown.bytes, act, y, emb, ff, ss_vk_codec_ty(b->denseDown.codec)))
        goto fail;
    r->ffn_down_real = 1;
    if (v->a.map(v->dev, xinm, 0, (VkDeviceSize)emb * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    inf = (float *)map;
    if (v->a.map(v->dev, ym, 0, (VkDeviceSize)emb * 4ull, 0, (void **)&ouf) != VK_SUCCESS) {
        v->a.unmap(v->dev, xinm); goto fail;
    }
    for (i = 0; i < emb; ++i) ouf[i] = inf[i] + ouf[i];
    v->a.unmap(v->dev, ym); v->a.unmap(v->dev, xinm);
    if (ss_vk_fin_obs(v, ym, emb, &ok) || !ok) goto fail;
    r->block_output_real = 1;
    ss_vk_dropb(v, &v->actb, &v->actmem);
    v->actb = y; v->actmem = ym; y = 0; ym = 0;
    free(gf); free(uf); free(af);
    ss_vk_dropb(v, &wn, &wnm); ss_vk_dropb(v, &xn, &xnm); ss_vk_dropb(v, &wg, &wgm);
    ss_vk_dropb(v, &g, &gm); ss_vk_dropb(v, &wu, &wum); ss_vk_dropb(v, &u, &um);
    ss_vk_dropb(v, &wd, &wdm); ss_vk_dropb(v, &act, &actm);
    return 0;
fail:
    free(hw); free(gf); free(uf); free(af);
    ss_vk_dropb(v, &wn, &wnm); ss_vk_dropb(v, &xn, &xnm); ss_vk_dropb(v, &wg, &wgm);
    ss_vk_dropb(v, &g, &gm); ss_vk_dropb(v, &wu, &wum); ss_vk_dropb(v, &u, &um);
    ss_vk_dropb(v, &wd, &wdm); ss_vk_dropb(v, &act, &actm); ss_vk_dropb(v, &y, &ym);
    return 100;
}
