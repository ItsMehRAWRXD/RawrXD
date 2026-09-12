/* ss_vk_mla_qkv.c — block MLA → host Q and KV vectors */
#include "ss_vk_mla_qkv.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include "ss_plan_load.h"
#include <stdlib.h>
#include <string.h>
static int map_f(SsVk *v, VkDeviceMemory m, uint32_t n, float **out)
{
    void *map = 0; float *h;
    *out = 0;
    if (v->a.map(v->dev, m, 0, (VkDeviceSize)n * 4ull, 0, &map) != VK_SUCCESS) return 100;
    h = (float *)malloc((size_t)n * sizeof(float));
    if (!h) { v->a.unmap(v->dev, m); return 100; }
    memcpy(h, map, (size_t)n * sizeof(float));
    v->a.unmap(v->dev, m); *out = h; return 0;
}
int ss_vk_mla_qkv_host(SsVk *v, const SsModelPlan *plan, uint32_t block,
                       float **q_out, uint32_t *q_n,
                       float **kv_out, uint32_t *kv_n)
{
    const SsBlockPlan *b; void *hw = 0; uint64_t hn = 0;
    VkBuffer wn = 0, xn = 0, wqa = 0, qa = 0, wqan = 0, qan = 0, wqb = 0, q = 0;
    VkBuffer wkva = 0, kva = 0, wkvan = 0, kvan = 0, wkvb = 0, kv = 0;
    VkDeviceMemory wnm = 0, xnm = 0, wqam = 0, qam = 0, wqanm = 0, qanm = 0, wqbm = 0, qm = 0;
    VkDeviceMemory wkvam = 0, kvam = 0, wkvanm = 0, kvanm = 0, wkvbm = 0, kvm = 0;
    uint32_t emb, q_a_r, q_b_r, kv_a_r, kv_b_r, lr; void *map = 0;
    VkBuffer xin; int rc = 100;
    if (!v || !plan || !q_out || !kv_out || !q_n || !kv_n || block >= plan->blockCount)
        return 100;
    *q_out = 0; *kv_out = 0; *q_n = 0; *kv_n = 0;
    b = &plan->blocks[block];
    xin = v->actb ? v->actb : v->outb;
    if (!xin || !b->attnNorm.present || !b->qA.present || !b->qB.present
        || !b->kvA.present || !b->kvB.present) return 100;
    emb = plan->embeddingLength;
    q_a_r = (uint32_t)b->qA.dims[1]; q_b_r = (uint32_t)b->qB.dims[1];
    kv_a_r = (uint32_t)b->kvA.dims[1]; kv_b_r = (uint32_t)b->kvB.dims[1];
    lr = plan->kvLoraRank ? plan->kvLoraRank : 512;
    if (ss_plan_load_ref(plan, &b->attnNorm, &hw, &hn) || ss_vk_upload(v, hw, hn, &wn, &wnm))
        goto done;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &xn, &xnm, 0)) goto done;
    if (ss_vk_op_rms(v, xin, wn, hn, xn, emb)) goto done;
    if (ss_plan_load_ref(plan, &b->qA, &hw, &hn) || ss_vk_upload(v, hw, hn, &wqa, &wqam))
        goto done;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)q_a_r * 4ull, &qa, &qam, 0)) goto done;
    if (ss_vk_op_gemv(v, wqa, b->qA.bytes, xn, qa, q_a_r, emb, ss_vk_codec_ty(b->qA.codec)))
        goto done;
    if (ss_plan_load_ref(plan, &b->qANorm, &hw, &hn) || ss_vk_upload(v, hw, hn, &wqan, &wqanm))
        goto done;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)q_a_r * 4ull, &qan, &qanm, 0)) goto done;
    if (ss_vk_op_rms(v, qa, wqan, hn, qan, q_a_r)) goto done;
    if (ss_plan_load_ref(plan, &b->qB, &hw, &hn) || ss_vk_upload(v, hw, hn, &wqb, &wqbm))
        goto done;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)q_b_r * 4ull, &q, &qm, 0)) goto done;
    if (ss_vk_op_gemv(v, wqb, b->qB.bytes, qan, q, q_b_r, q_a_r, ss_vk_codec_ty(b->qB.codec)))
        goto done;
    if (ss_plan_load_ref(plan, &b->kvA, &hw, &hn) || ss_vk_upload(v, hw, hn, &wkva, &wkvam))
        goto done;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)kv_a_r * 4ull, &kva, &kvam, 0)) goto done;
    if (ss_vk_op_gemv(v, wkva, b->kvA.bytes, xn, kva, kv_a_r, emb, ss_vk_codec_ty(b->kvA.codec)))
        goto done;
    if (ss_plan_load_ref(plan, &b->kvANorm, &hw, &hn) || ss_vk_upload(v, hw, hn, &wkvan, &wkvanm))
        goto done;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)kv_a_r * 4ull, &kvan, &kvanm, 0)) goto done;
    if (lr > kv_a_r) lr = kv_a_r;
    if (ss_vk_op_rms(v, kva, wkvan, b->kvANorm.bytes, kvan, lr)) goto done;
    if (v->a.map(v->dev, kvam, 0, (VkDeviceSize)kv_a_r * 4ull, 0, &map) == VK_SUCCESS) {
        void *map2 = 0;
        if (v->a.map(v->dev, kvanm, 0, (VkDeviceSize)kv_a_r * 4ull, 0, &map2) == VK_SUCCESS) {
            memcpy((char *)map2 + lr * 4ull, (char *)map + lr * 4ull, (kv_a_r - lr) * 4ull);
            v->a.unmap(v->dev, kvanm);
        }
        v->a.unmap(v->dev, kvam);
    }
    if (ss_plan_load_ref(plan, &b->kvB, &hw, &hn) || ss_vk_upload(v, hw, hn, &wkvb, &wkvbm))
        goto done;
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)kv_b_r * 4ull, &kv, &kvm, 0)) goto done;
    if (ss_vk_op_gemv(v, wkvb, b->kvB.bytes, kvan, kv, kv_b_r, lr, ss_vk_codec_ty(b->kvB.codec)))
        goto done;
    if (map_f(v, qm, q_b_r, q_out) || map_f(v, kvm, kv_b_r, kv_out)) goto done;
    *q_n = q_b_r; *kv_n = kv_b_r; rc = 0;
done:
    free(hw);
    ss_vk_dropb(v, &wn, &wnm); ss_vk_dropb(v, &xn, &xnm); ss_vk_dropb(v, &wqa, &wqam);
    ss_vk_dropb(v, &qa, &qam); ss_vk_dropb(v, &wqan, &wqanm); ss_vk_dropb(v, &qan, &qanm);
    ss_vk_dropb(v, &wqb, &wqbm); ss_vk_dropb(v, &q, &qm); ss_vk_dropb(v, &wkva, &wkvam);
    ss_vk_dropb(v, &kva, &kvam); ss_vk_dropb(v, &wkvan, &wkvanm); ss_vk_dropb(v, &kvan, &kvanm);
    ss_vk_dropb(v, &wkvb, &wkvbm); ss_vk_dropb(v, &kv, &kvm);
    return rc;
}
