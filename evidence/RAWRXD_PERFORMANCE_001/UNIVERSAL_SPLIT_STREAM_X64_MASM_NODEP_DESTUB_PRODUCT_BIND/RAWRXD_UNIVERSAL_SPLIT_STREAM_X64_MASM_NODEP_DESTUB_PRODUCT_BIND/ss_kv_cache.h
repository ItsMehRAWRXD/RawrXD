/* ss_kv_cache.h — persistent host KV; append per token */
#ifndef SS_KV_CACHE_H
#define SS_KV_CACHE_H
#include <stdint.h>
typedef struct SsKvCache {
    float *key;   /* [layers][cap][k_width] */
    float *value; /* [layers][cap][v_width] */
    void *keyMemory;
    void *valueMemory;
    uint64_t capacityTokens;
    uint64_t committedTokens;
    uint32_t layers;
    uint32_t kWidth;
    uint32_t vWidth;
    uint32_t kvWidth; /* legacy alias = kWidth */
    uint64_t generation;
    int real;
} SsKvCache;
int ss_kv_cache_alloc(SsKvCache *kv, uint32_t layers, uint32_t k_width,
                      uint32_t v_width, uint64_t cap);
void ss_kv_cache_free(SsKvCache *kv);
int ss_kv_append(SsKvCache *kv, uint32_t layer, uint32_t position,
                 const float *k, const float *v);
int ss_kv_read(const SsKvCache *kv, uint32_t layer, uint32_t position,
               float *k_out, float *v_out);
#endif
