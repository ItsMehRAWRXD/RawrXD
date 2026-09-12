/* ss_kv_cache.c — host-persistent K/V; KV_CACHE_REAL when append+read match */
#include "ss_kv_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int ss_kv_cache_alloc(SsKvCache *kv, uint32_t layers, uint32_t k_width,
                      uint32_t v_width, uint64_t cap)
{
    size_t nk, nv;
    if (!kv || !layers || !k_width || !v_width || !cap) return 1;
    memset(kv, 0, sizeof *kv);
    nk = (size_t)layers * (size_t)cap * (size_t)k_width;
    nv = (size_t)layers * (size_t)cap * (size_t)v_width;
    kv->key = (float *)calloc(nk, sizeof(float));
    kv->value = (float *)calloc(nv, sizeof(float));
    if (!kv->key || !kv->value) { ss_kv_cache_free(kv); return 1; }
    kv->layers = layers; kv->kWidth = k_width; kv->vWidth = v_width;
    kv->kvWidth = k_width; kv->capacityTokens = cap; kv->real = 1;
    printf("KV_CACHE_ALLOC layers=%u k=%u v=%u cap=%llu KV_CACHE_REAL=1\n",
           layers, k_width, v_width, (unsigned long long)cap);
    return 0;
}
void ss_kv_cache_free(SsKvCache *kv)
{
    if (!kv) return;
    free(kv->key); free(kv->value); memset(kv, 0, sizeof *kv);
}
static float *slot(float *base, uint32_t layer, uint32_t pos, uint32_t width,
                   uint64_t cap)
{
    return base + ((size_t)layer * (size_t)cap + (size_t)pos) * (size_t)width;
}
int ss_kv_append(SsKvCache *kv, uint32_t layer, uint32_t position,
                 const float *k, const float *v)
{
    if (!kv || !kv->real || !k || !v || layer >= kv->layers) return 1;
    if (position >= kv->capacityTokens) return 1;
    memcpy(slot(kv->key, layer, position, kv->kWidth, kv->capacityTokens),
           k, (size_t)kv->kWidth * sizeof(float));
    memcpy(slot(kv->value, layer, position, kv->vWidth, kv->capacityTokens),
           v, (size_t)kv->vWidth * sizeof(float));
    if ((uint64_t)position + 1ull > kv->committedTokens)
        kv->committedTokens = (uint64_t)position + 1ull;
    kv->generation++;
    return 0;
}
int ss_kv_read(const SsKvCache *kv, uint32_t layer, uint32_t position,
               float *k_out, float *v_out)
{
    if (!kv || !kv->real || !k_out || !v_out || layer >= kv->layers) return 1;
    if (position >= kv->committedTokens) return 1;
    memcpy(k_out, slot(kv->key, layer, position, kv->kWidth, kv->capacityTokens),
           (size_t)kv->kWidth * sizeof(float));
    memcpy(v_out, slot(kv->value, layer, position, kv->vWidth, kv->capacityTokens),
           (size_t)kv->vWidth * sizeof(float));
    return 0;
}
