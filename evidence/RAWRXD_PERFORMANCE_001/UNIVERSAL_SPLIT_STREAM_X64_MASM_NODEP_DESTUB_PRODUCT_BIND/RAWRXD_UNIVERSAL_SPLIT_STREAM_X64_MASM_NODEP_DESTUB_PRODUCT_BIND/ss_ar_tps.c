/* ss_ar_tps.c — QPC per-token full-forward timing; mint only on observation */
#include "ss_ar_tps.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static uint64_t now(const D2Tps *t)
{
    LARGE_INTEGER li; uint64_t c, f;
    if (!t || !t->freq) return 0;
    QueryPerformanceCounter(&li);
    c = (uint64_t)li.QuadPart; f = t->freq;
    /* avoid QuadPart*1e9 overflow */
    return (c / f) * 1000000000ull + ((c % f) * 1000000000ull) / f;
}
void d2_tps_begin(D2Tps *t)
{
    LARGE_INTEGER f;
    if (!t) return;
    memset(t, 0, sizeof *t);
    QueryPerformanceFrequency(&f); t->freq = (uint64_t)f.QuadPart;
    t->wall0 = now(t);
}
void d2_tps_token_enter(D2Tps *t) { if (t) t->t0 = now(t); }
void d2_tps_token_leave(D2Tps *t)
{
    uint64_t t1;
    if (!t || t->n >= D2_TPS_MAX) return;
    t1 = now(t);
    t->sample[t->n++] = (t1 >= t->t0) ? (t1 - t->t0) : 0;
}
void d2_tps_end(D2Tps *t) { if (t) t->wall1 = now(t); }
static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
void d2_tps_print(const D2Tps *t, uint64_t gen, int decode_pass,
                  uint32_t sealed, uint32_t device_lost)
{
    uint64_t wall, tok0 = 0, mn = 0, mx = 0, sum = 0, p50 = 0, p95 = 0;
    uint64_t tmp[D2_TPS_MAX]; uint32_t i, warm_n = 0; double tps = 0.0;
    int auth = 0;
    if (!t) return;
    wall = (t->wall1 >= t->wall0) ? (t->wall1 - t->wall0) : 0;
    if (t->n) {
        tok0 = t->sample[0]; mn = mx = t->sample[0];
        for (i = 0; i < t->n; ++i) {
            if (t->sample[i] < mn) mn = t->sample[i];
            if (t->sample[i] > mx) mx = t->sample[i];
            sum += t->sample[i];
        }
        /* WARMUP_EXCLUDED: sustained stats exclude token 0 */
        warm_n = (t->n > 1) ? (t->n - 1u) : t->n;
        memcpy(tmp, t->sample + ((t->n > 1) ? 1 : 0), warm_n * sizeof(uint64_t));
        {
            uint64_t wsum = 0;
            for (i = 0; i < warm_n; ++i) wsum += tmp[i];
            /* primary sustained = warm-excluded sample sum; wall also reported */
            if (wsum) tps = (double)warm_n * 1e9 / (double)wsum;
        }
        qsort(tmp, warm_n, sizeof(uint64_t), cmp_u64);
        p50 = tmp[warm_n / 2u];
        p95 = tmp[(warm_n * 95u) / 100u];
    }
    /* mint requires positive wall (QPC integrity) + decode predicates */
    auth = decode_pass && gen >= 64 && t->n >= 64 && !sealed && !device_lost
        && wall > 0 && mn > 0;
    printf("GATE=DEEP2_FULL_MODEL_TPS_AUTHORITY_001\n");
    printf("FULL_MODEL_FORWARD=1 SEALED_LOGITS_REUSE=%u DEVICE_LOST=%u\n",
           sealed, device_lost);
    printf("GENERATED_TOKENS=%llu TOKEN_SAMPLES=%u WARMUP_EXCLUDED=1\n",
           (unsigned long long)gen, t->n);
    printf("TOKEN_0_NS=%llu TOKEN_MIN_NS=%llu TOKEN_MAX_NS=%llu\n",
           (unsigned long long)tok0, (unsigned long long)mn, (unsigned long long)mx);
    printf("TOKEN_MEAN_NS=%llu TOKEN_P50_NS=%llu TOKEN_P95_NS=%llu\n",
           (unsigned long long)(t->n ? (sum / t->n) : 0),
           (unsigned long long)p50, (unsigned long long)p95);
    printf("GENERATION_WALL_NS=%llu SUSTAINED_TPS=%.6f\n",
           (unsigned long long)wall, tps);
    if (wall && gen)
        printf("WALL_TPS=%.6f\n", (double)gen * 1e9 / (double)wall);
    printf("TPS_SCOPE=FULL_MODEL_DECODE\n");
    printf("FULL_MODEL_TPS_AUTHORITY=%d PROMOTE=0\n", auth ? 1 : 0);
    fflush(stdout);
}
