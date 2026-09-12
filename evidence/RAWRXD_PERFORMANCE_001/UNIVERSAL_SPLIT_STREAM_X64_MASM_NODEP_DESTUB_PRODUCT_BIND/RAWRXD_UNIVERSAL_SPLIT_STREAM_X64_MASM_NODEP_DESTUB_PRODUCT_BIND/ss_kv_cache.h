/* ss_kv_cache.h — persistent KV; append per token, never rebuild history */
#ifndef SS_KV_CACHE_H
#define SS_KV_CACHE_H
#include <stdint.h>
typedef struct SsKvCache {
    void *key;   /* VkBuffer placeholder until attention lands */
    void *value;
    void *keyMemory;
    void *valueMemory;
    uint64_t capacityTokens;
    uint64_t committedTokens;
    uint32_t layers;
    uint32_t kvWidth;
    uint64_t generation;
    int real;
} SsKvCache;
int ss_kv_cache_alloc(SsKvCache *kv, uint32_t layers, uint32_t kv_width, uint64_t cap);
void ss_kv_cache_free(SsKvCache *kv);
int ss_kv_append_stub(SsKvCache *kv, uint32_t block, uint32_t position);
#endif
