/* ss_ar_decode_print.c — generic TARGET=N receipt; sealed reuse must be 0 */
#include "ss_ar_decode.h"
#include <stdio.h>
void ss_ar_decode_print(const SsArResult *r)
{
    if (!r) return;
    printf("DEEP2_FULL_DECODE_TOKEN_REAL=%s\n", r->pass ? "PASS" : "FAIL");
    printf("GENERATED=%llu TARGET_TOKENS=%llu\n",
           (unsigned long long)r->generated, (unsigned long long)r->target);
    printf("FORWARD_CALLS=%llu COMMIT_CALLS=%llu ADVANCE_CALLS=%llu\n",
           (unsigned long long)r->forward_calls,
           (unsigned long long)r->commit_calls,
           (unsigned long long)r->advance_calls);
    printf("FULL_BLOCK_FORWARD_CALLS=%u REAL_REENTRY_FORWARDS=%u EMBD_CALLS=%u\n",
           r->full_block_fwd, r->real_fwd, r->embd_calls);
    printf("POSITION_0=%u POSITION_1=%u LAST_POSITION=%u\n",
           r->pos0, r->pos1, r->last_pos);
    printf("SEALED_LOGITS_REUSE_TOKEN0=%u SEALED_LOGITS_REUSE_TOKEN1=%u\n",
           r->sealed0, r->sealed1);
    printf("SEALED_LOGITS_REUSE_COUNT=%u\n", r->sealed0 + r->sealed1);
    printf("TOKEN0_FULL_FORWARD_REAL=%u TOKEN1_PLUS_FULL_FORWARD_REAL=%u\n",
           (r->tok0_embd && r->tok0_loop && r->tok0_rms && r->tok0_lm) ? 1u : 0u,
           (r->tok1_embd && r->tok1_loop && r->tok1_rms && r->tok1_lm) ? 1u : 0u);
    printf("TOKEN0_EMBD_REAL=%u TOKEN0_BLOCK_LOOP_REAL=%u TOKEN0_LM_HEAD=%u\n",
           r->tok0_embd, r->tok0_loop, r->tok0_lm);
    printf("TOKEN1_EMBD_REAL=%u TOKEN1_BLOCK_LOOP_REAL=%u\n",
           r->tok1_embd, r->tok1_loop);
    printf("TOKEN1_FINAL_RMS_REAL=%u LM_HEAD_TILED_TOKEN1=%u\n",
           r->tok1_rms, r->tok1_lm);
    printf("LM_HEAD_ROWS_TOKEN0=%u LM_HEAD_ROWS_TOKEN1=%u TILE=%u\n",
           r->tok0_rows, r->tok1_rows, r->tok1_tile);
    printf("POST_TOKEN1_DEVICE_ALIVE=%u POST_LAST_DEVICE_ALIVE=%u DEVICE_LOST=%u\n",
           r->post_tok1_alive, r->post_last_alive, r->device_lost);
    printf("RUNTIME_FLAGS=0x%llX ERROR_CODE=%u LAST_TOKEN=%llu\n",
           (unsigned long long)r->runtime_flags, r->error_code,
           (unsigned long long)r->last_token);
    printf("FULL_DECODE_OBSERVED=%d\n", r->full_decode_observed);
    printf("AUTH_GPU_TOKEN_SELECT=%s\n",
           r->auth_token_select ? "GRANTED" : "UNPROVEN");
    printf("AUTH_AUTOREGRESSIVE_COMMIT=%s\n",
           r->auth_ar_commit ? "GRANTED" : "UNPROVEN");
    if (!r->pass && r->stop)
        printf("AUTHORIZATION_STOP_REASON=%s\n", r->stop);
    printf("FULL_MODEL_DECODE=%d GENERATED_TOKENS=%llu\n",
           r->pass ? 1 : 0, (unsigned long long)r->generated);
    printf("FULL_MODEL_TPS_AUTHORITY=0 PROMOTE=0\n");
    printf("ENDURANCE_TOP15_PRODUCT_PATH=1\n");
    if (r->pass && r->target >= 64)
        printf("NEXT_GATE=FULL_MODEL_TPS_AUTHORITY_CANDIDATE\n");
    else if (r->pass && r->target >= 16)
        printf("NEXT_GATE=DEEP2_FULL_DECODE_TOKEN_REAL TARGET=64\n");
    else if (r->pass && r->target >= 4)
        printf("NEXT_GATE=DEEP2_FULL_DECODE_TOKEN_REAL TARGET=16\n");
    else if (r->pass && r->target >= 2)
        printf("NEXT_GATE=DEEP2_FULL_DECODE_TOKEN_REAL TARGET=4\n");
    else
        printf("NEXT_GATE=DEEP2_FULL_DECODE_TOKEN_REAL\n");
}
