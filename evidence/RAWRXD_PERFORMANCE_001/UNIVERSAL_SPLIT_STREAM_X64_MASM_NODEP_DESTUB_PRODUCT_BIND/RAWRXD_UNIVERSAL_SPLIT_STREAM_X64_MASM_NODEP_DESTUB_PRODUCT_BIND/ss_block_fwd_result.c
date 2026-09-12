/* ss_block_fwd_result.c — completion conjunction + receipt print */
#include "ss_block_forward.h"
#include <stdio.h>
#include <string.h>
void ss_block_fwd_reset(SsBlockForwardResult *r, uint32_t block)
{
    if (!r) return;
    memset(r, 0, sizeof *r);
    r->block_index = block;
    r->first_failure_stage = SS_BF_NONE;
}
void ss_block_fwd_finalize(SsBlockForwardResult *r)
{
    if (!r) return;
    r->completed =
        r->attn_norm_done && r->mla_q_done && r->mla_kv_done && r->rope_done
        && r->kv_append_done && r->attn_done && r->residual_commit
        && r->block_output_obs && r->block_plan_resolved;
    if (!r->completed && r->first_failure_stage == SS_BF_NONE) {
        if (!r->block_plan_resolved) r->first_failure_stage = SS_BF_PLAN;
        else if (!r->attn_norm_done) r->first_failure_stage = SS_BF_ATTN_NORM;
        else if (!r->mla_q_done) r->first_failure_stage = SS_BF_MLA_Q;
        else if (!r->mla_kv_done) r->first_failure_stage = SS_BF_MLA_KV;
        else if (!r->rope_done) r->first_failure_stage = SS_BF_ROPE;
        else if (!r->kv_append_done) r->first_failure_stage = SS_BF_KV_APPEND;
        else if (!r->attn_done) r->first_failure_stage = SS_BF_ATTENTION;
        else if (!r->residual_commit) r->first_failure_stage = SS_BF_RESIDUAL;
        else r->first_failure_stage = SS_BF_OUTPUT;
    }
}
void ss_block_fwd_print(const SsBlockForwardResult *r)
{
    if (!r) return;
    printf("DEEP2_BLOCK_FORWARD_000_001 BLOCK_INDEX=%u BLOCK_PLAN_RESOLVED=%d\n",
           r->block_index, r->block_plan_resolved);
    printf("EXPECTED_BLOCK_INDEX=%u OBSERVED_BLOCK_INDEX=%u\n",
           r->block_index, r->block_index);
    printf("EXPECTED_SHARD_ID=%u OBSERVED_SHARD_ID=%u\n",
           r->expected_shard_id, r->observed_shard_id);
    printf("EXPECTED_WEIGHT_RANGE=%llu OBSERVED_WEIGHT_RANGE=%llu\n",
           (unsigned long long)r->expected_weight_off,
           (unsigned long long)r->observed_weight_off);
    printf("ATTN_NORM_INPUT_BOUND=%d ATTN_NORM_DISPATCHED=%d ATTN_NORM_COMPLETED=%d\n",
           r->attn_norm_bound, r->attn_norm_disp, r->attn_norm_done);
    printf("MLA_Q_INPUT_BOUND=%d MLA_Q_DISPATCHED=%d MLA_Q_COMPLETED=%d\n",
           r->mla_q_bound, r->mla_q_disp, r->mla_q_done);
    printf("MLA_KV_INPUT_BOUND=%d MLA_KV_DISPATCHED=%d MLA_KV_COMPLETED=%d\n",
           r->mla_kv_bound, r->mla_kv_disp, r->mla_kv_done);
    printf("ROPE_DISPATCHED=%d ROPE_COMPLETED=%d\n", r->rope_disp, r->rope_done);
    printf("KV_APPEND_DISPATCHED=%d KV_APPEND_COMPLETED=%d KV_POSITION_MATCH=%d\n",
           r->kv_append_disp, r->kv_append_done, r->kv_pos_match);
    printf("ATTENTION_DISPATCHED=%d ATTENTION_COMPLETED=%d\n", r->attn_disp, r->attn_done);
    printf("RESIDUAL_COMMIT=%d BLOCK_OUTPUT_OBSERVED=%d BLOCK_FORWARD_COMPLETED=%d\n",
           r->residual_commit, r->block_output_obs, r->completed);
    printf("REAL_WEIGHT_RANGES_USED=%d PLAN_BINDINGS_USED=%d SYNTHETIC_WEIGHT=%d\n",
           r->real_weight_ranges, r->plan_bindings_used, r->synthetic_weight);
    printf("CPU_WEIGHT_REUPLOAD=%d HOST_WEIGHT_COPY=%d REPLACEMENT_WEIGHT_ALLOCATION=%d\n",
           r->cpu_reupload, r->host_weight_copy, r->replacement_alloc);
    printf("FIRST_FAILURE_STAGE=%u FULL_MODEL_FORWARD=0 ALL_BLOCKS_COMPLETED=0\n",
           r->first_failure_stage);
    printf("TOKEN_COMMIT=0 PROMOTE=0\n");
}
