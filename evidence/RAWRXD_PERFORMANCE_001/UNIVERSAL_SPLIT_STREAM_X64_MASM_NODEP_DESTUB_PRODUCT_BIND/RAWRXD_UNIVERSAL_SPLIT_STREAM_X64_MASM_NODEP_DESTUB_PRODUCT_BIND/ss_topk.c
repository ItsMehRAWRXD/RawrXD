/* ss_topk.c — select top-k indices + softmax-renormalized weights */
#include <math.h>
#include <stdint.h>
#include <string.h>
int ss_topk_softmax(const float *logits, uint32_t n, uint32_t k,
                    uint32_t *ids, float *wts, float *sum_out)
{
    uint32_t i, j, bi, t; float best, m, s;
    if (!logits || !ids || !wts || !n || !k || k > n || k > 8u) return 1;
    memset(ids, 0xff, k * sizeof(uint32_t));
    for (i = 0; i < k; ++i) {
        best = -1e30f; bi = 0;
        for (j = 0; j < n; ++j) {
            for (t = 0; t < i; ++t) if (ids[t] == j) break;
            if (t < i) continue;
            if (logits[j] > best) { best = logits[j]; bi = j; }
        }
        ids[i] = bi; wts[i] = best;
    }
    m = wts[0];
    for (i = 1; i < k; ++i) if (wts[i] > m) m = wts[i];
    s = 0.f;
    for (i = 0; i < k; ++i) { wts[i] = expf(wts[i] - m); s += wts[i]; }
    if (s <= 0.f) return 1;
    for (i = 0; i < k; ++i) wts[i] /= s;
    if (sum_out) *sum_out = 1.f;
    return 0;
}
