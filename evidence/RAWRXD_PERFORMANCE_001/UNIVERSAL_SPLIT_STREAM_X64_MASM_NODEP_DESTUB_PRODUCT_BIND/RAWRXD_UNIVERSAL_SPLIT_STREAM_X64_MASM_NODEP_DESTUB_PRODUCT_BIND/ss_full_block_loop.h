/* ss_full_block_loop.h — DEEP2_FULL_BLOCK_LOOP_REAL continuity receipt */
#ifndef SS_FULL_BLOCK_LOOP_H
#define SS_FULL_BLOCK_LOOP_H
#include <stdint.h>
typedef struct SsFullBlockLoop {
    uint32_t declared, plan_count, entered, completed;
    uint32_t dense_exec, moe_exec;
    uint32_t bind_ok, attn_ok, ffn_ok, residual_ok;
    uint32_t continuity_match, continuity_need;
    uint32_t repeated_blk0, synthetic_reset, embd_reload;
    uint32_t first_block, last_block;
    uint32_t block_order_valid, ffn_from_tensors;
    uint32_t chain_continuity_valid, final_out_real;
    uint32_t all_blocks_completed, full_model_forward;
    uint32_t first_fail_block;
    int pass;
} SsFullBlockLoop;
struct SsVk;
struct SsModelPlan;
void ss_full_block_loop_print(const SsFullBlockLoop *L);
int ss_vk_full_block_loop(struct SsVk *v, const struct SsModelPlan *plan,
                          SsFullBlockLoop *L);
#endif
