/* ss_rope_kv_attn_print.c */
#include "ss_rope_kv_attn.h"
#include <stdio.h>
void ss_rope_kv_print(const SsRopeKvAttnResult *r)
{
    if (!r) return;
    printf("DEEP2_ROPE_KV_ATTN_REAL=%s\n", r->pass ? "PASS" : "FAIL");
    printf("ROPE_REAL=%d ROPE_DIM=%u ROPE_FREQ_BASE=%g ROPE_NONIDENTITY_AT_POS_GT0=%d\n",
           r->rope_real, r->rope_dim, (double)r->rope_freq_base, r->rope_nonid_gt0);
    printf("KV_CACHE_REAL=%d KV_APPEND_OK=%d KV_READ_MATCH=%d KV_COMMITTED=%llu\n",
           r->kv_cache_real, r->kv_append_ok, r->kv_read_match,
           (unsigned long long)r->kv_committed);
    printf("ATTENTION_REAL=%d ATTENTION_CAUSAL=%d ATTN_OUT_TO_RESIDUAL=%d\n",
           r->attention_real, r->attention_causal, r->attn_out_residual);
    printf("DECODE_STEPS=%u HEADS=%u K_WIDTH=%u V_WIDTH=%u FIRST_FAIL=%u\n",
           r->steps, r->heads, r->k_width, r->v_width, r->first_fail);
    printf("FULL_MODEL_FORWARD=0 ALL_BLOCKS_COMPLETED=0 MOE_ROUTER_REAL=0 PROMOTE=0\n");
    printf("NEXT_GATE=%s\n", r->pass ? "DEEP2_MOE_OR_FULL_BLOCK_FFN" : "DEEP2_ROPE_KV_ATTN_REAL");
}
