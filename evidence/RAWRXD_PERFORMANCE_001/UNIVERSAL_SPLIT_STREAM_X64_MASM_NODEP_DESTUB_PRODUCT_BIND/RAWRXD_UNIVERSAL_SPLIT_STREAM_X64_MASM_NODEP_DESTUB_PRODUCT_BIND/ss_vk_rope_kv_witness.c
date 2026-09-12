/* ss_vk_rope_kv_witness.c — multi-pos RoPE + KV + causal attn on block 0 */
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include "ss_rope_kv_attn.h"
#include "ss_vk_mla_qkv.h"
#include "ss_rope.h"
#include "ss_kv_cache.h"
#include "ss_attn_causal.h"
#include "ss_vk_ops.h"
#include "ss_vk_block_util.h"
#include "ss_plan_load.h"
#include <stdlib.h>
#include <string.h>
int ss_vk_rope_kv_attn_real(SsVk *v, const SsModelPlan *plan, uint32_t steps,
                            SsRopeKvAttnResult *r)
{
    SsKvCache kv; const SsBlockPlan *b;
    float *q = 0, *kvb = 0, *k = 0, *val = 0, *q0 = 0, *attn = 0, *kr = 0, *vr = 0;
    uint32_t qn = 0, kn = 0, heads, kd, pos, i, rope_dim;
    float freq; void *hw = 0; uint64_t hn = 0;
    VkBuffer wo = 0, ao = 0, out = 0; VkDeviceMemory wom = 0, aom = 0, outm = 0;
    float *af, *inf, *ouf; void *map = 0; int ok = 0;
    memset(r, 0, sizeof *r);
    if (!v || !plan || !r || !plan->planReal || steps < 2u) return 100;
    b = &plan->blocks[0];
    heads = plan->attentionHeads ? plan->attentionHeads : 128;
    rope_dim = plan->ropeDim ? plan->ropeDim : 64;
    freq = plan->ropeFreqBase > 0.f ? plan->ropeFreqBase : 10000.f;
    r->steps = steps; r->rope_dim = rope_dim; r->rope_freq_base = freq; r->heads = heads;
    if (ss_vk_mla_qkv_host(v, plan, 0, &q, &qn, &kvb, &kn)) { r->first_fail = 1; return 100; }
    if (!heads || (qn % heads) || (kn % heads) || (kn / heads) != 256u) {
        free(q); free(kvb); r->first_fail = 1; return 100;
    }
    kd = 128u; r->k_width = heads * kd; r->v_width = heads * kd;
    if (ss_kv_cache_alloc(&kv, 1, r->k_width, r->v_width, steps)) {
        free(q); free(kvb); r->first_fail = 2; return 100;
    }
    k = (float *)malloc(r->k_width * sizeof(float));
    val = (float *)malloc(r->v_width * sizeof(float));
    attn = (float *)malloc(r->v_width * sizeof(float));
    q0 = (float *)malloc(r->k_width * sizeof(float));
    kr = (float *)malloc(r->k_width * sizeof(float));
    vr = (float *)malloc(r->v_width * sizeof(float));
    if (!k || !val || !attn || !q0 || !kr || !vr) goto fail;
    for (pos = 0; pos < steps; ++pos) {
        if (pos > 0) { free(q); free(kvb); q = kvb = 0;
            if (ss_vk_mla_qkv_host(v, plan, 0, &q, &qn, &kvb, &kn)) { r->first_fail = 1; goto fail; }
        }
        for (i = 0; i < heads; ++i) {
            memcpy(k + i * kd, kvb + i * 256u, kd * sizeof(float));
            memcpy(val + i * kd, kvb + i * 256u + 128u, kd * sizeof(float));
            memcpy(q0 + i * kd, q + i * (qn / heads), kd * sizeof(float));
        }
        if (pos == 1u) {
            float *k_before = (float *)malloc(r->k_width * sizeof(float));
            memcpy(k_before, k, r->k_width * sizeof(float));
            ss_rope_apply(k, heads, kd, rope_dim, pos, freq);
            ss_rope_apply(q0, heads, kd, rope_dim, pos, freq);
            r->rope_nonid_gt0 = ss_rope_changed(k_before, k, r->k_width);
            free(k_before);
            r->rope_real = r->rope_nonid_gt0;
        } else {
            ss_rope_apply(k, heads, kd, rope_dim, pos, freq);
            ss_rope_apply(q0, heads, kd, rope_dim, pos, freq);
            if (pos == 0u) r->rope_real = 1;
        }
        if (ss_kv_append(&kv, 0, pos, k, val)) { r->first_fail = 2; goto fail; }
        if (ss_kv_read(&kv, 0, pos, kr, vr)) { r->first_fail = 2; goto fail; }
        if (memcmp(kr, k, r->k_width * sizeof(float))
            || memcmp(vr, val, r->v_width * sizeof(float))) {
            r->first_fail = 2; goto fail;
        }
        r->kv_read_match = 1; r->kv_append_ok = 1;
        if (ss_attn_causal(&kv, 0, pos, q0, heads, kd, attn)) {
            r->first_fail = 3; goto fail;
        }
        r->attention_causal = 1; r->attention_real = 1;
    }
    r->kv_cache_real = kv.real; r->kv_committed = kv.committedTokens;
    if (!b->attnOut.present || ss_plan_load_ref(plan, &b->attnOut, &hw, &hn)
        || ss_vk_upload(v, hw, hn, &wo, &wom)) { r->first_fail = 4; goto fail; }
    free(hw); hw = 0;
    if (ss_vk_mkbuf(v, (VkDeviceSize)r->v_width * 4ull, &ao, &aom, &map)) {
        r->first_fail = 4; goto fail;
    }
    memcpy(map, attn, r->v_width * sizeof(float)); v->a.unmap(v->dev, aom);
    if (ss_vk_mkbuf(v, (VkDeviceSize)plan->embeddingLength * 4ull, &out, &outm, 0)) {
        r->first_fail = 4; goto fail;
    }
    if (ss_vk_op_gemv(v, wo, b->attnOut.bytes, ao, out, plan->embeddingLength, r->v_width,
                      ss_vk_codec_ty(b->attnOut.codec))) { r->first_fail = 4; goto fail; }
    if (v->a.map(v->dev, v->outmem, 0, (VkDeviceSize)plan->embeddingLength * 4ull, 0, &map)
        != VK_SUCCESS) { r->first_fail = 4; goto fail; }
    inf = (float *)map;
    if (v->a.map(v->dev, outm, 0, (VkDeviceSize)plan->embeddingLength * 4ull, 0, (void **)&ouf)
        != VK_SUCCESS) { v->a.unmap(v->dev, v->outmem); r->first_fail = 4; goto fail; }
    for (i = 0; i < plan->embeddingLength; ++i) ouf[i] = inf[i] + ouf[i];
    v->a.unmap(v->dev, outm); v->a.unmap(v->dev, v->outmem);
    if (ss_vk_fin_obs(v, outm, plan->embeddingLength, &ok) || !ok) {
        r->first_fail = 4; goto fail;
    }
    r->attn_out_residual = 1;
    ss_vk_dropb(v, &v->actb, &v->actmem);
    v->actb = out; v->actmem = outm; out = 0; outm = 0;
    r->pass = r->rope_real && r->rope_nonid_gt0 && r->kv_cache_real && r->kv_append_ok
        && r->kv_read_match && r->attention_real && r->attention_causal
        && r->attn_out_residual && r->kv_committed == steps;
    ss_vk_dropb(v, &wo, &wom); ss_vk_dropb(v, &ao, &aom);
    free(q); free(kvb); free(k); free(val); free(attn); free(q0); free(kr); free(vr);
    ss_kv_cache_free(&kv);
    return r->pass ? 0 : 100;
fail:
    free(hw); free(q); free(kvb); free(k); free(val); free(attn); free(q0); free(kr); free(vr);
    ss_vk_dropb(v, &wo, &wom); ss_vk_dropb(v, &ao, &aom); ss_vk_dropb(v, &out, &outm);
    ss_kv_cache_free(&kv);
    return 100;
}
