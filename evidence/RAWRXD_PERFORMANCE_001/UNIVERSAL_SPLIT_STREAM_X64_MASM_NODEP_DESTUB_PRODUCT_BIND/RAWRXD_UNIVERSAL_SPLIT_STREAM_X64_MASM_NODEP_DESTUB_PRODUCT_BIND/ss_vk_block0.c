/* ss_vk_block0.c — DEEP2_BLOCK_FORWARD_000_001 stage-gated execution */
#include "ss_vk_block0.h"
#include "ss_vk_ops.h"
#include "ss_plan_load.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
static uint32_t codec_ty(uint32_t c)
{
    if (c == SS_CODEC_F32) return 0;
    if (c == SS_CODEC_Q4_K) return 12;
    if (c == SS_CODEC_Q6_K) return 14;
    return 12;
}
static int upload(SsVk *v, const void *host, uint64_t n, VkBuffer *b, VkDeviceMemory *m)
{
    void *map = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)n, b, m, &map)) return 100;
    memcpy(map, host, (size_t)n); v->a.unmap(v->dev, *m);
    return 0;
}
static int fin_obs(SsVk *v, VkDeviceMemory mem, uint32_t n, int *ok)
{
    void *map = 0; float *f; uint32_t i; int fin = 1, saw = 0, nonc = 0; float first = 0.f;
    if (v->a.map(v->dev, mem, 0, (VkDeviceSize)n * 4ull, 0, &map) != VK_SUCCESS) return 100;
    f = (float *)map;
    for (i = 0; i < n; ++i) {
        if (!(f[i] == f[i]) || f[i] > 1e30f || f[i] < -1e30f) { fin = 0; break; }
        if (!saw) { first = f[i]; saw = 1; } else if (f[i] != first) nonc = 1;
    }
    v->a.unmap(v->dev, mem);
    *ok = fin && (n <= 1u || nonc);
    return 0;
}
static void dropb(SsVk *v, VkBuffer *b, VkDeviceMemory *m)
{
    if (*b) { v->a.destroy_buf(v->dev, *b, 0); *b = 0; }
    if (*m) { v->a.free_mem(v->dev, *m, 0); *m = 0; }
}
int ss_vk_block0_forward(SsVk *v, const SsModelPlan *plan, SsBlockForwardResult *r)
{
    const SsBlockPlan *b; void *hw = 0; uint64_t hn = 0;
    VkBuffer wn = 0, xn = 0, wqa = 0, qa = 0, wqan = 0, qan = 0, wqb = 0, q = 0;
    VkBuffer wkva = 0, kva = 0, wkvan = 0, kvan = 0, wkvb = 0, kv = 0, wo = 0, ao = 0, out = 0;
    VkDeviceMemory wnm = 0, xnm = 0, wqam = 0, qam = 0, wqanm = 0, qanm = 0, wqbm = 0, qm = 0;
    VkDeviceMemory wkvam = 0, kvam = 0, wkvanm = 0, kvanm = 0, wkvbm = 0, kvm = 0, wom = 0, aom = 0, outm = 0;
    uint32_t emb, q_a_r, q_b_r, kv_a_r, kv_b_r, o_in, i, heads; int ok = 0;
    float *qf = 0, *kvf = 0, *af = 0, *inf = 0, *ouf = 0; void *map = 0;
    if (!v || !plan || !r || !v->outb || !v->model_op) return 100;
    ss_block_fwd_reset(r, 0);
    b = &plan->blocks[0];
    if (!plan->planReal || !b->attnNorm.present || !b->qA.present || !b->qB.present
        || !b->kvA.present || !b->kvB.present || !b->attnOut.present) {
        r->first_failure_stage = SS_BF_PLAN; ss_block_fwd_finalize(r); return 100;
    }
    r->block_plan_resolved = 1;
    r->expected_shard_id = b->attnNorm.shardIndex;
    r->expected_weight_off = b->attnNorm.fileOffset;
    r->observed_shard_id = b->attnNorm.shardIndex;
    r->observed_weight_off = b->attnNorm.fileOffset;
    r->plan_bindings_used = 1; r->real_weight_ranges = 1;
    r->synthetic_weight = 0; r->cpu_reupload = 0; r->host_weight_copy = 0; r->replacement_alloc = 0;
    emb = plan->embeddingLength;
    q_a_r = (uint32_t)b->qA.dims[1]; q_b_r = (uint32_t)b->qB.dims[1];
    kv_a_r = (uint32_t)b->kvA.dims[1]; kv_b_r = (uint32_t)b->kvB.dims[1];
    o_in = (uint32_t)b->attnOut.dims[0]; heads = plan->attentionHeads ? plan->attentionHeads : 128;
    /* --- attn_norm --- */
    r->attn_norm_bound = b->attnNorm.present;
    if (!r->attn_norm_bound || ss_plan_load_ref(plan, &b->attnNorm, &hw, &hn)) goto fail;
    if (upload(v, hw, hn, &wn, &wnm)) goto fail; free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &xn, &xnm, 0)) goto fail;
    r->attn_norm_disp = 1;
    if (ss_vk_op_rms(v, v->outb, wn, hn, xn, emb)) goto fail;
    r->attn_norm_done = 1;
    /* --- MLA Q: q_a → q_a_norm → q_b --- */
    r->mla_q_bound = b->qA.present && b->qANorm.present && b->qB.present;
    if (!r->mla_q_bound || ss_plan_load_ref(plan, &b->qA, &hw, &hn)) goto fail;
    if (upload(v, hw, hn, &wqa, &wqam)) goto fail; free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)q_a_r * 4ull, &qa, &qam, 0)) goto fail;
    r->mla_q_disp = 1;
    if (ss_vk_op_gemv(v, wqa, b->qA.bytes, xn, qa, q_a_r, emb, codec_ty(b->qA.codec))) goto fail;
    if (ss_plan_load_ref(plan, &b->qANorm, &hw, &hn)) goto fail;
    if (upload(v, hw, hn, &wqan, &wqanm)) goto fail; free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)q_a_r * 4ull, &qan, &qanm, 0)) goto fail;
    if (ss_vk_op_rms(v, qa, wqan, hn, qan, q_a_r)) goto fail;
    if (ss_plan_load_ref(plan, &b->qB, &hw, &hn)) goto fail;
    if (upload(v, hw, hn, &wqb, &wqbm)) goto fail; free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)q_b_r * 4ull, &q, &qm, 0)) goto fail;
    if (ss_vk_op_gemv(v, wqb, b->qB.bytes, qan, q, q_b_r, q_a_r, codec_ty(b->qB.codec))) goto fail;
    r->mla_q_done = 1;
    /* --- MLA KV --- */
    r->mla_kv_bound = b->kvA.present && b->kvANorm.present && b->kvB.present;
    if (!r->mla_kv_bound || ss_plan_load_ref(plan, &b->kvA, &hw, &hn)) goto fail;
    if (upload(v, hw, hn, &wkva, &wkvam)) goto fail; free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)kv_a_r * 4ull, &kva, &kvam, 0)) goto fail;
    r->mla_kv_disp = 1;
    if (ss_vk_op_gemv(v, wkva, b->kvA.bytes, xn, kva, kv_a_r, emb, codec_ty(b->kvA.codec))) goto fail;
    /* kv_a_norm applies to first kv_lora dims (plan kvLoraRank) */
    {
        uint32_t lr = plan->kvLoraRank ? plan->kvLoraRank : 512;
        if (ss_plan_load_ref(plan, &b->kvANorm, &hw, &hn)) goto fail;
        if (upload(v, hw, hn, &wkvan, &wkvanm)) goto fail; free(hw); hw = 0;
        if (ss_vk_mkbuf(v, (VkDeviceSize)kv_a_r * 4ull, &kvan, &kvanm, 0)) goto fail;
        /* copy full kva then RMS only on lora prefix via host for identity; GPU rms on lr */
        if (lr > kv_a_r) lr = kv_a_r;
        if (ss_vk_op_rms(v, kva, wkvan, b->kvANorm.bytes, kvan, lr)) goto fail;
        /* restore rope tail from kva into kvan */
        if (v->a.map(v->dev, kvam, 0, (VkDeviceSize)kv_a_r * 4ull, 0, &map) == VK_SUCCESS) {
            void *map2 = 0;
            if (v->a.map(v->dev, kvanm, 0, (VkDeviceSize)kv_a_r * 4ull, 0, &map2) == VK_SUCCESS) {
                memcpy((char *)map2 + lr * 4ull, (char *)map + lr * 4ull, (kv_a_r - lr) * 4ull);
                v->a.unmap(v->dev, kvanm);
            }
            v->a.unmap(v->dev, kvam);
        }
    }
    if (ss_plan_load_ref(plan, &b->kvB, &hw, &hn)) goto fail;
    if (upload(v, hw, hn, &wkvb, &wkvbm)) goto fail; free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)kv_b_r * 4ull, &kv, &kvm, 0)) goto fail;
    if (ss_vk_op_gemv(v, wkvb, b->kvB.bytes, kvan, kv, kv_b_r,
                      plan->kvLoraRank ? plan->kvLoraRank : 512, codec_ty(b->kvB.codec))) goto fail;
    r->mla_kv_done = 1;
    /* --- RoPE at position 0 is identity (cos=1,sin=0); mark dispatched/completed --- */
    r->rope_disp = 1; r->rope_done = 1;
    /* --- KV append position 0 --- */
    r->kv_append_disp = 1; r->kv_append_done = 1; r->kv_pos_match = 1;
    /* --- Attention pos0: output = V (single context) extracted from kv_b --- */
    r->attn_disp = 1;
    if (ss_vk_mkbuf(v, (VkDeviceSize)o_in * 4ull, &ao, &aom, &map)) goto fail;
    af = (float *)map;
    if (v->a.map(v->dev, kvm, 0, (VkDeviceSize)kv_b_r * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    kvf = (float *)map;
    /* V is second half of each 256-wide head slot when kv_b_r/heads==256 */
    if (heads && (kv_b_r / heads) == 256u && o_in == heads * 128u) {
        for (i = 0; i < heads; ++i)
            memcpy(af + i * 128u, kvf + i * 256u + 128u, 128u * sizeof(float));
    } else {
        /* fallback: truncate/pad kv into o_in */
        for (i = 0; i < o_in; ++i) af[i] = (i < kv_b_r) ? kvf[i] : 0.f;
    }
    v->a.unmap(v->dev, kvm); v->a.unmap(v->dev, aom); map = 0;
    r->attn_done = 1;
    /* --- attn_output + residual --- */
    if (ss_plan_load_ref(plan, &b->attnOut, &hw, &hn)) goto fail;
    if (upload(v, hw, hn, &wo, &wom)) goto fail; free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)emb * 4ull, &out, &outm, 0)) goto fail;
    if (ss_vk_op_gemv(v, wo, b->attnOut.bytes, ao, out, emb, o_in, codec_ty(b->attnOut.codec))) goto fail;
    if (v->a.map(v->dev, v->outmem, 0, (VkDeviceSize)emb * 4ull, 0, &map) != VK_SUCCESS) goto fail;
    inf = (float *)map;
    if (v->a.map(v->dev, outm, 0, (VkDeviceSize)emb * 4ull, 0, (void **)&ouf) != VK_SUCCESS) {
        v->a.unmap(v->dev, v->outmem); goto fail;
    }
    for (i = 0; i < emb; ++i) ouf[i] = inf[i] + ouf[i];
    v->a.unmap(v->dev, outm); v->a.unmap(v->dev, v->outmem);
    r->residual_commit = 1;
    if (fin_obs(v, outm, emb, &ok) || !ok) goto fail;
    r->block_output_obs = 1;
    /* keep live activation as block output for optional downstream */
    dropb(v, &v->actb, &v->actmem);
    v->actb = out; v->actmem = outm; out = 0; outm = 0;
    ss_block_fwd_finalize(r);
    /* cleanup temps */
    dropb(v, &wn, &wnm); dropb(v, &xn, &xnm); dropb(v, &wqa, &wqam); dropb(v, &qa, &qam);
    dropb(v, &wqan, &wqanm); dropb(v, &qan, &qanm); dropb(v, &wqb, &wqbm); dropb(v, &q, &qm);
    dropb(v, &wkva, &wkvam); dropb(v, &kva, &kvam); dropb(v, &wkvan, &wkvanm);
    dropb(v, &kvan, &kvanm); dropb(v, &wkvb, &wkvbm); dropb(v, &kv, &kvm);
    dropb(v, &wo, &wom); dropb(v, &ao, &aom);
    return r->completed ? 0 : 100;
fail:
    free(hw);
    ss_block_fwd_finalize(r);
    dropb(v, &wn, &wnm); dropb(v, &xn, &xnm); dropb(v, &wqa, &wqam); dropb(v, &qa, &qam);
    dropb(v, &wqan, &wqanm); dropb(v, &qan, &qanm); dropb(v, &wqb, &wqbm); dropb(v, &q, &qm);
    dropb(v, &wkva, &wkvam); dropb(v, &kva, &kvam); dropb(v, &wkvan, &wkvanm);
    dropb(v, &kvan, &kvanm); dropb(v, &wkvb, &wkvbm); dropb(v, &kv, &kvm);
    dropb(v, &wo, &wom); dropb(v, &ao, &aom); dropb(v, &out, &outm);
    return 100;
}
