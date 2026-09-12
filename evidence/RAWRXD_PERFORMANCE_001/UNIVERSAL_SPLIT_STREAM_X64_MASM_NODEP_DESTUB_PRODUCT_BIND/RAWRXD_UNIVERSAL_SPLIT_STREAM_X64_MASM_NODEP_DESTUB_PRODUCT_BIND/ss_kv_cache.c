/* ss_kv_cache.c — stub until attention kernels; KV_CACHE_REAL=0 */
#include "ss_kv_cache.h"
#include <string.h>
#include <stdio.h>
int ss_kv_cache_alloc(SsKvCache *kv, uint32_t layers, uint32_t kv_width, uint64_t cap)
{
    if (!kv || !layers || !kv_width || !cap) return 1;
    memset(kv, 0, sizeof *kv);
    kv->layers = layers; kv->kvWidth = kv_width; kv->capacityTokens = cap;
    kv->real = 0;
    printf("KV_CACHE_ALLOC layers=%u width=%u cap=%llu KV_CACHE_REAL=0\n",
           layers, kv_width, (unsigned long long)cap);
    return 0;
}
void ss_kv_cache_free(SsKvCache *kv) { if (kv) memset(kv, 0, sizeof *kv); }
int ss_kv_append_stub(SsKvCache *kv, uint32_t block, uint32_t position)
{
    (void)block;
    if (!kv || position >= kv->capacityTokens) return 1;
    if (position + 1ull > kv->committedTokens) kv->committedTokens = position + 1ull;
    return 100; /* NOT_RUN: no real K/V write yet */
}
