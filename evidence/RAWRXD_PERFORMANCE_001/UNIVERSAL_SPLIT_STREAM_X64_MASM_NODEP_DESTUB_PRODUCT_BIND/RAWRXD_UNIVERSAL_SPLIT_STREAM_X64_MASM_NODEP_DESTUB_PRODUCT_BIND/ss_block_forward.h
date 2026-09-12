/* ss_block_forward.h — stage-gated block forward; partial ≠ completed */
#ifndef SS_BLOCK_FORWARD_H
#define SS_BLOCK_FORWARD_H
#include "ss_model_plan.h"
#include "ss_kv_cache.h"
#include <stdint.h>
typedef enum SsBlockFail {
    SS_BF_NONE = 0,
    SS_BF_PLAN,
    SS_BF_ATTN_NORM,
    SS_BF_MLA_Q,
    SS_BF_MLA_KV,
    SS_BF_ROPE,
    SS_BF_KV_APPEND,
    SS_BF_ATTENTION,
    SS_BF_RESIDUAL,
    SS_BF_OUTPUT
} SsBlockFail;
typedef struct SsBlockForwardResult {
    uint32_t block_index;
    uint32_t expected_shard_id;
    uint32_t observed_shard_id;
    uint64_t expected_weight_off;
    uint64_t observed_weight_off;
    int block_plan_resolved;
    int attn_norm_bound, attn_norm_disp, attn_norm_done;
    int mla_q_bound, mla_q_disp, mla_q_done;
    int mla_kv_bound, mla_kv_disp, mla_kv_done;
    int rope_disp, rope_done;
    int kv_append_disp, kv_append_done, kv_pos_match;
    int attn_disp, attn_done;
    int residual_commit, block_output_obs;
    int completed;
    uint32_t first_failure_stage;
    int plan_bindings_used, real_weight_ranges;
    int synthetic_weight, cpu_reupload, host_weight_copy, replacement_alloc;
} SsBlockForwardResult;
typedef struct SsActView {
    void *buffer; void *memory;
    uint64_t bytes; uint32_t elements;
    uint32_t producerBlock; uint32_t producerOp;
} SsActView;
void ss_block_fwd_reset(SsBlockForwardResult *r, uint32_t block);
void ss_block_fwd_finalize(SsBlockForwardResult *r);
void ss_block_fwd_print(const SsBlockForwardResult *r);
int ss_forward_block(const SsModelPlan *model, uint32_t block, uint32_t position,
                     SsKvCache *kv, const SsActView *in, SsActView *out);
#endif
