/* ss_final_norm_lm.h — DEEP2_FINAL_NORM_LM_HEAD_REAL on full-loop act */
#ifndef SS_FINAL_NORM_LM_H
#define SS_FINAL_NORM_LM_H
#include <stdint.h>
typedef struct SsFinalNormLm {
    int input_from_full_loop;
    int final_norm_real, lm_head_real, logits_real;
    int logits_finite, logits_nonconstant;
    int abbreviated_shortcut;
    uint32_t logits_count, embd;
    uint64_t act_hash_in;
    int full_model_forward, all_blocks_completed;
    int generated_tokens, full_model_decode;
    int pass;
    uint32_t first_fail;
} SsFinalNormLm;
struct SsVk;
struct SsModelPlan;
void ss_final_norm_lm_print(const SsFinalNormLm *r);
int ss_vk_final_norm_lmhead(struct SsVk *v, const struct SsModelPlan *plan,
                            int full_loop_pass, SsFinalNormLm *r);
#endif
