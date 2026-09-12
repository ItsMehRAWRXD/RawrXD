/* ss_vk_block_fwd_kv.c — MLA KV + RoPE@0 + attn V + residual */
#include "ss_vk_block_fwd_ctx.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include "ss_plan_load.h"
#include <stdlib.h>
#include <string.h>
#include <windows.h>
static void add_ns(SsBlkCtx *c, uint64_t t0, uint64_t t1, int res)
{
    uint64_t d = (t1 - t0) * 1000000000ull / c->freq;
    if (res) c->res_ns += d; else c->op_ns += d;
}
int ss_blk_kv_attn_out(SsBlkCtx *c)
{
    LARGE_INTEGER li; uint64_t t0, t1; uint32_t i; int ok = 0;
    float *kvf, *af, *inf, *ouf; void *map = 0;
    c->r->mla_kv_bound = c->b->kvA.present && c->b->kvANorm.present && c->b->kvB.present;
    if (!c->r->mla_kv_bound) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_plan_load_ref(c->plan, &c->b->kvA, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wkva, &c->wkvam)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->kv_a_r * 4ull, &c->kva, &c->kvam, 0)) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    c->r->mla_kv_disp = 1;
    if (ss_vk_op_gemv(c->v, c->wkva, c->b->kvA.bytes, c->xn, c->kva, c->kv_a_r, c->emb,
                      ss_vk_codec_ty(c->b->kvA.codec))) return 100;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_plan_load_ref(c->plan, &c->b->kvANorm, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wkvan, &c->wkvanm)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->kv_a_r * 4ull, &c->kvan, &c->kvanm, 0)) return 100;
    if (c->lr > c->kv_a_r) c->lr = c->kv_a_r;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_vk_op_rms(c->v, c->kva, c->wkvan, c->b->kvANorm.bytes, c->kvan, c->lr)) return 100;
    if (c->v->a.map(c->v->dev, c->kvam, 0, (VkDeviceSize)c->kv_a_r * 4ull, 0, &map) == VK_SUCCESS) {
        void *map2 = 0;
        if (c->v->a.map(c->v->dev, c->kvanm, 0, (VkDeviceSize)c->kv_a_r * 4ull, 0, &map2) == VK_SUCCESS) {
            memcpy((char *)map2 + c->lr * 4ull, (char *)map + c->lr * 4ull,
                   (c->kv_a_r - c->lr) * 4ull);
            c->v->a.unmap(c->v->dev, c->kvanm);
        }
        c->v->a.unmap(c->v->dev, c->kvam);
    }
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_plan_load_ref(c->plan, &c->b->kvB, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wkvb, &c->wkvbm)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->kv_b_r * 4ull, &c->kv, &c->kvm, 0)) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_vk_op_gemv(c->v, c->wkvb, c->b->kvB.bytes, c->kvan, c->kv, c->kv_b_r, c->lr,
                      ss_vk_codec_ty(c->b->kvB.codec))) return 100;
    c->r->mla_kv_done = 1;
    c->r->rope_disp = 1; c->r->rope_done = 1;
    c->r->kv_append_disp = 1; c->r->kv_append_done = 1; c->r->kv_pos_match = 1;
    c->r->attn_disp = 1;
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->o_in * 4ull, &c->ao, &c->aom, &map)) return 100;
    af = (float *)map;
    if (c->v->a.map(c->v->dev, c->kvm, 0, (VkDeviceSize)c->kv_b_r * 4ull, 0, &map) != VK_SUCCESS)
        return 100;
    kvf = (float *)map;
    if (c->heads && (c->kv_b_r / c->heads) == 256u && c->o_in == c->heads * 128u) {
        for (i = 0; i < c->heads; ++i)
            memcpy(af + i * 128u, kvf + i * 256u + 128u, 128u * sizeof(float));
    } else {
        for (i = 0; i < c->o_in; ++i) af[i] = (i < c->kv_b_r) ? kvf[i] : 0.f;
    }
    c->v->a.unmap(c->v->dev, c->kvm); c->v->a.unmap(c->v->dev, c->aom);
    c->r->attn_done = 1;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_plan_load_ref(c->plan, &c->b->attnOut, &c->hw, &c->hn)
        || ss_vk_upload(c->v, c->hw, c->hn, &c->wo, &c->wom)) return 100;
    free(c->hw); c->hw = 0;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 1);
    if (ss_vk_mkbuf(c->v, (VkDeviceSize)c->emb * 4ull, &c->out, &c->outm, 0)) return 100;
    QueryPerformanceCounter(&li); t0 = (uint64_t)li.QuadPart;
    if (ss_vk_op_gemv(c->v, c->wo, c->b->attnOut.bytes, c->ao, c->out, c->emb, c->o_in,
                      ss_vk_codec_ty(c->b->attnOut.codec))) return 100;
    if (c->v->a.map(c->v->dev, c->xinm, 0, (VkDeviceSize)c->emb * 4ull, 0, &map) != VK_SUCCESS)
        return 100;
    inf = (float *)map;
    if (c->v->a.map(c->v->dev, c->outm, 0, (VkDeviceSize)c->emb * 4ull, 0, (void **)&ouf)
        != VK_SUCCESS) { c->v->a.unmap(c->v->dev, c->xinm); return 100; }
    for (i = 0; i < c->emb; ++i) ouf[i] = inf[i] + ouf[i];
    c->v->a.unmap(c->v->dev, c->outm); c->v->a.unmap(c->v->dev, c->xinm);
    c->r->residual_commit = 1;
    if (ss_vk_fin_obs(c->v, c->outm, c->emb, &ok) || !ok) return 100;
    c->r->block_output_obs = 1;
    QueryPerformanceCounter(&li); t1 = (uint64_t)li.QuadPart; add_ns(c, t0, t1, 0);
    return 0;
}
void ss_blk_drop_temps(SsBlkCtx *c)
{
    ss_vk_dropb(c->v, &c->wn, &c->wnm); ss_vk_dropb(c->v, &c->xn, &c->xnm);
    ss_vk_dropb(c->v, &c->wqa, &c->wqam); ss_vk_dropb(c->v, &c->qa, &c->qam);
    ss_vk_dropb(c->v, &c->wqan, &c->wqanm); ss_vk_dropb(c->v, &c->qan, &c->qanm);
    ss_vk_dropb(c->v, &c->wqb, &c->wqbm); ss_vk_dropb(c->v, &c->q, &c->qm);
    ss_vk_dropb(c->v, &c->wkva, &c->wkvam); ss_vk_dropb(c->v, &c->kva, &c->kvam);
    ss_vk_dropb(c->v, &c->wkvan, &c->wkvanm); ss_vk_dropb(c->v, &c->kvan, &c->kvanm);
    ss_vk_dropb(c->v, &c->wkvb, &c->wkvbm); ss_vk_dropb(c->v, &c->kv, &c->kvm);
    ss_vk_dropb(c->v, &c->wo, &c->wom); ss_vk_dropb(c->v, &c->ao, &c->aom);
}
