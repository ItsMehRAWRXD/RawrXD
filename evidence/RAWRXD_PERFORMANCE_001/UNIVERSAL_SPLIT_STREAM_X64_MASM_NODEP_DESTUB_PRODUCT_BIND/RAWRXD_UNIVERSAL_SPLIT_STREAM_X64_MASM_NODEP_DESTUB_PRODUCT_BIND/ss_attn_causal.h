/* ss_attn_causal.h */
#ifndef SS_ATTN_CAUSAL_H
#define SS_ATTN_CAUSAL_H
#include "ss_kv_cache.h"
int ss_attn_causal(const SsKvCache *kv, uint32_t layer, uint32_t pos,
                   const float *q, uint32_t heads, uint32_t head_dim, float *out);
#endif
