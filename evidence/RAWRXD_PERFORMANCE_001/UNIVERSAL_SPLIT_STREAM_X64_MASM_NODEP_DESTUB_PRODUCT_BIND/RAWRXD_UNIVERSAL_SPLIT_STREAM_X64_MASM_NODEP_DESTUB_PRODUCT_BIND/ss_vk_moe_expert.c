/* ss_vk_moe_expert.c — one Q4_K expert gate/up/act/down → embd out */
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include "ss_plan_load_slice.h"
#include "ss_silu_host.h"
#include <stdlib.h>
#include <string.h>
int ss_vk_moe_one_expert(SsVk *v, const SsModelPlan *plan, const SsBlockPlan *b,
                         uint32_t eid, VkBuffer xn, float *y_out)
{
    void *hw = 0; uint64_t per_g, per_u, per_d, off;
    VkBuffer wg = 0, g = 0, wu = 0, u = 0, wd = 0, y = 0, act = 0;
    VkDeviceMemory wgm = 0, gm = 0, wum = 0, um = 0, wdm = 0, ym = 0, actm = 0;
    uint32_t emb, ff, ne; float *gf = 0, *uf = 0, *af = 0; void *map = 0;
    emb = plan->embeddingLength; ne = plan->expertCount ? plan->expertCount : 256;
    ff = (uint32_t)b->expertGate.dims[1];
    if (!b->expertGate.present || !b->expertUp.present || !b->expertDown.present || eid >= ne)
        return 100;
    per_g = b->expertGate.bytes / ne; per_u = b->expertUp.bytes / ne;
    per_d = b->expertDown.bytes / ne;
    off = b->expertGate.fileOffset + (uint64_t)eid * per_g;
    if (ss_plan_load_slice(plan, b->expertGate.shardIndex, off, per_g, &hw)
        || ss_vk_upload(v, hw, per_g, &wg, &wgm)) goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &g, &gm, 0)) goto fail;
    if (ss_vk_op_gemv(v, wg, per_g, xn, g, ff, emb, ss_vk_codec_ty(b->expertGate.codec)))
        goto fail;
    off = b->expertUp.fileOffset + (uint64_t)eid * per_u;
    if (ss_plan_load_slice(plan, b->expertUp.shardIndex, off, per_u, &hw)
        || ss_vk_upload(v, hw, per_u, &wu, &wum)) goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)ff * 4ull, &u, &um, 0)) goto fail;
    if (ss_vk_op_gemv(v, wu, per_u, xn, u, ff, emb, ss_vk_codec_ty(b->expertUp.codec)))
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
    off = b->expertDown.fileOffset + (uint64_t)eid * per_d;
    if (ss_plan_load_slice(plan, b->expertDown.shardIndex, off, per_d, &hw)
        || ss_vk_upload(v, hw, per_d, &wd, &wdm)) goto fail;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &y, &ym, 0)) goto fail;
    if (ss_vk_op_gemv(v, wd, per_d, act, y, emb, ff, ss_vk_codec_ty(b->expertDown.codec)))
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
