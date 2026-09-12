/* ss_ar_decode_fwd.c — one real path: embd→61→tiled LM (no sealed reuse) */
#include "ss_ar_user.h"
#include "ss_ar_endurance.h"
#include "ss_full_block_loop.h"
#include "ss_final_norm_lm.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static int copy_logits(ArUser *u)
{
    void *map = 0; size_t n;
    if (!u->v->logitsb || !u->v->logitsmem || !u->v->vocab_n) return 0;
    n = (size_t)u->v->vocab_n * 4ull;
    free(u->host_logits); u->host_logits = (float *)malloc(n);
    if (!u->host_logits) return 0;
    if (u->v->a.map(u->v->dev, u->v->logitsmem, 0, n, 0, &map) != VK_SUCCESS)
        return 0;
    memcpy(u->host_logits, map, n); u->v->a.unmap(u->v->dev, u->v->logitsmem);
    u->vocab = u->v->vocab_n;
    return 1;
}
static int fail_pos(ArUser *u, uint64_t pos, const char *tag)
{
    sprintf(u->stop_buf, "TOKEN%llu_%s", (unsigned long long)pos, tag);
    u->stop = u->stop_buf;
    printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
    fflush(stdout);
    return 0;
}
int ar_forward(void *user, uint64_t pos, uint64_t *out_logits, uint64_t *out_vocab)
{
    ArUser *u = (ArUser *)user; SsFullBlockLoop FL; SsFinalNormLm FN; int rc;
    if (!u || !u->v || !u->plan || !out_logits || !out_vocab) {
        if (u) return fail_pos(u, 0, "EMBD_FAILED");
        return 0;
    }
    u->v->logits_op = 0; u->sealed0 = 0; u->sealed1 = 0;
    d2_tps_token_enter(&u->tps);
    if (!d2_inv_begin_fwd(&u->inv, pos, 0)) {
        d2_tps_token_leave(&u->tps);
        u->stop = u->inv.fail ? u->inv.fail : "INVARIANT_BEGIN_FAIL";
        printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
        return 0;
    }
    if (pos == 0) u->pos0 = 0;
    if (pos == 1) u->pos1 = 1;
    u->last_pos = (uint32_t)pos;
    u->v->token_id = u->next_tok;
    ss_vk_cmd_reclaim(u->v); ss_vk_embd_pipe_reset(u->v);
    rc = ss_vk_embd(u->v);
    printf("AR_FWD_STAGE embd_rc=%d token_in=%u pos=%llu\n",
           rc, u->next_tok, (unsigned long long)pos); fflush(stdout);
    if (rc) { d2_tps_token_leave(&u->tps); return fail_pos(u, pos, "EMBD_FAILED"); }
    u->embd_calls++;
    if (pos >= 1) u->embd_after_adv++;
    if (pos == 0) u->tok0_embd = 1;
    if (pos == 1) u->tok1_embd = 1;
    rc = ss_vk_full_block_loop(u->v, u->plan, &FL);
    printf("AR_FWD_STAGE loop_rc=%d pass=%d completed=%u\n",
           rc, FL.pass, FL.completed); fflush(stdout);
    if (rc || !FL.pass) {
        d2_tps_token_leave(&u->tps); return fail_pos(u, pos, "BLOCK_LOOP_FAILED");
    }
    if (pos == 0) u->tok0_loop = 1;
    if (pos == 1) u->tok1_loop = 1;
    rc = ss_vk_final_norm_lmhead(u->v, u->plan, 1, &FN);
    printf("AR_FWD_STAGE norm_rc=%d pass=%d lm=%d rows=%u\n",
           rc, FN.pass, FN.lm_head_real, FN.logits_count); fflush(stdout);
    if (rc || !FN.final_norm_real) {
        d2_tps_token_leave(&u->tps); return fail_pos(u, pos, "FINAL_RMS_FAILED");
    }
    if (pos == 0) u->tok0_rms = 1;
    if (pos == 1) u->tok1_rms = 1;
    if (!FN.lm_head_real || !FN.logits_real) {
        d2_tps_token_leave(&u->tps); return fail_pos(u, pos, "LM_HEAD_FAILED");
    }
    if (pos == 0) { u->tok0_lm = 1; u->tok0_rows = FN.logits_count; }
    if (pos == 1) {
        u->tok1_lm = 1; u->tok1_rows = FN.logits_count; u->tok1_tile = 16384u;
    }
    u->real_fwd++; u->full_block_fwd++;
    if (!copy_logits(u)) {
        d2_tps_token_leave(&u->tps); return fail_pos(u, pos, "LM_HEAD_FAILED");
    }
    *out_logits = (uint64_t)(uintptr_t)u->host_logits;
    *out_vocab = u->vocab;
    if (!ar_endurance_end_fwd(u, pos)) { d2_tps_token_leave(&u->tps); return 0; }
    d2_tps_token_leave(&u->tps);
    printf("AR_FORWARD pos=%llu sealed_logits_reuse=0 token_in=%u vocab=%u\n",
           (unsigned long long)pos, u->next_tok, u->vocab);
    printf("LM_HEAD_TILED_REAL=1 LM_HEAD_ROWS=%u LM_HEAD_TILE_ROWS=16384\n",
           FN.logits_count);
    fflush(stdout);
    return 1;
}
