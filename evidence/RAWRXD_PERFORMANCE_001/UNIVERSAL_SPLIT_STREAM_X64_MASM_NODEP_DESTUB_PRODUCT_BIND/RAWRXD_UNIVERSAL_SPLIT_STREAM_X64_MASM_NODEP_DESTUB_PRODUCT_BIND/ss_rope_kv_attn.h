/* ss_rope_kv_attn.h — DEEP2_ROPE_KV_ATTN_REAL stage receipt */
#ifndef SS_ROPE_KV_ATTN_H
#define SS_ROPE_KV_ATTN_H
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include <stdint.h>
typedef struct SsRopeKvAttnResult {
    uint32_t steps, rope_dim;
    float rope_freq_base;
    int rope_real, rope_nonid_gt0;
    int kv_cache_real, kv_append_ok, kv_read_match;
    int attention_real, attention_causal, attn_out_residual;
    uint64_t kv_committed;
    uint32_t heads, k_width, v_width;
    int pass;
    uint32_t first_fail;
} SsRopeKvAttnResult;
void ss_rope_kv_print(const SsRopeKvAttnResult *r);
int ss_vk_rope_kv_attn_real(SsVk *v, const SsModelPlan *plan, uint32_t steps,
                            SsRopeKvAttnResult *r);
#endif
