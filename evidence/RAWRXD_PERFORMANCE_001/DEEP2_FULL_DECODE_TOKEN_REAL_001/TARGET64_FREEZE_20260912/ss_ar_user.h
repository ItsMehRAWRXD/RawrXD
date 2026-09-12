/* ss_ar_user.h — shared AR user; one generic decode executor */
#ifndef SS_AR_USER_H
#define SS_AR_USER_H
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include <stdint.h>
typedef struct {
    SsVk *v;
    const SsModelPlan *plan;
    float *host_logits;
    uint32_t vocab, next_tok, model_gen, decode_gen, ticket;
    uint32_t sealed0, sealed1, full_block_fwd, embd_after_adv, embd_calls;
    uint32_t tok0_embd, tok0_loop, tok0_rms, tok0_lm, tok0_rows;
    uint32_t tok1_embd, tok1_loop, tok1_rms, tok1_lm, tok1_rows, tok1_tile;
    uint32_t pos0, pos1, last_pos, real_fwd, post_tok1_alive, post_last_alive;
    uint32_t device_lost;
    char stop_buf[48];
    const char *stop;
} ArUser;
int ar_forward(void *user, uint64_t pos, uint64_t *out_logits, uint64_t *out_vocab);
int ar_commit(void *user, uint64_t tok, uint64_t pos, uint64_t z);
int ar_advance(void *user, uint64_t tok, uint64_t next_pos, uint64_t z);
#endif
