/* ss_ar_decode.h — generic N-token AR; sealed reuse forbidden */
#ifndef SS_AR_DECODE_H
#define SS_AR_DECODE_H
#include <stdint.h>
typedef struct SsArResult {
    uint64_t generated, forward_calls, commit_calls, advance_calls;
    uint64_t target, last_token, runtime_flags;
    uint32_t error_code;
    int full_decode_observed;
    int auth_token_select, auth_ar_commit;
    int pass;
    uint32_t sealed0, sealed1, full_block_fwd, embd_after_adv, embd_calls;
    uint32_t tok0_embd, tok0_loop, tok0_rms, tok0_lm, tok0_rows;
    uint32_t tok1_embd, tok1_loop, tok1_rms, tok1_lm, tok1_rows, tok1_tile;
    uint32_t pos0, pos1, last_pos, real_fwd, post_tok1_alive, post_last_alive;
    uint32_t device_lost;
    const char *stop;
} SsArResult;
struct SsVk;
struct SsModelPlan;
void ss_ar_decode_print(const SsArResult *r);
int ss_ar_decode_run(struct SsVk *v, const struct SsModelPlan *plan,
                     uint64_t target_tokens, SsArResult *out);
#endif
