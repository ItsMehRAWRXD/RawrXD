/* ss_attn_causal.c — host causal softmax attention over KV cache */
#include "ss_kv_cache.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
int ss_attn_causal(const SsKvCache *kv, uint32_t layer, uint32_t pos,
                   const float *q, uint32_t heads, uint32_t head_dim,
                   float *out)
{
    uint32_t h, t, d, T; float *scores, scale, m, s, a, *kk, *vv;
    if (!kv || !kv->real || !q || !out || !heads || !head_dim) return 1;
    if (layer >= kv->layers || pos >= kv->committedTokens) return 1;
    if (kv->kWidth != heads * head_dim || kv->vWidth != heads * head_dim) return 1;
    T = pos + 1u;
    scores = (float *)malloc((size_t)T * sizeof(float));
    if (!scores) return 1;
    scale = 1.f / sqrtf((float)head_dim);
    memset(out, 0, (size_t)heads * head_dim * sizeof(float));
    for (h = 0; h < heads; ++h) {
        m = -1e30f; s = 0.f;
        for (t = 0; t < T; ++t) {
            kk = kv->key + ((size_t)layer * kv->capacityTokens + t) * kv->kWidth
                + h * head_dim;
            a = 0.f;
            for (d = 0; d < head_dim; ++d) a += q[h * head_dim + d] * kk[d];
            scores[t] = a * scale;
            if (scores[t] > m) m = scores[t];
        }
        for (t = 0; t < T; ++t) { scores[t] = expf(scores[t] - m); s += scores[t]; }
        if (s <= 0.f) { free(scores); return 1; }
        for (t = 0; t < T; ++t) {
            vv = kv->value + ((size_t)layer * kv->capacityTokens + t) * kv->vWidth
                + h * head_dim;
            a = scores[t] / s;
            for (d = 0; d < head_dim; ++d) out[h * head_dim + d] += a * vv[d];
        }
    }
    free(scores);
    return 0;
}
