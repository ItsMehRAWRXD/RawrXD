/* ss_ar_decode_wire.c — Commit/Advance + Deep2RunFullDecode + AttemptGrant */
#include "ss_ar_decode.h"
#include "ss_ar_user.h"
#include "ss_ar_endurance.h"
#include "ss_vk_api.h"
#include "ss_model_plan.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#pragma pack(push, 8)
typedef struct { void *user; void *fwd; void *commit; void *adv; } D2Bind;
typedef struct {
    uint64_t magic; uint32_t ver, size; void *user;
    void *fwd, *commit, *adv; uint64_t pos, gen, fwd_n, commit_n, adv_n;
    uint64_t last_tok, last_logits, last_vocab, flags; uint32_t err, r0;
    uint64_t target, r1;
} D2Ctx;
typedef struct {
    uint64_t granted; uint32_t model_gen, decode_gen, ticket, last_status;
    uint32_t r[2];
} D2Auth;
typedef struct {
    uint64_t bit; uint32_t executed, completed, error, synthetic, fallback;
    uint32_t model_gen, decode_gen, cur_model, cur_decode, ticket, cur_ticket;
    uint32_t obs, exp, flags, req; uint32_t pad;
} D2Wit;
#pragma pack(pop)
int Deep2DecodeInit(D2Ctx *c, const D2Bind *b);
int Deep2RunFullDecode(D2Ctx *c, uint64_t n);
int Deep2DecodeValidateWitness(D2Ctx *c);
int Deep2AuthInit(D2Auth *s, uint32_t mg, uint32_t dg, uint32_t t);
int Deep2AttemptGrantAuthority(D2Auth *s, const D2Wit *w);
int Deep2AuthQuery(D2Auth *s, uint64_t bit);
int ar_commit(void *user, uint64_t tok, uint64_t pos, uint64_t z)
{
    ArUser *u = (ArUser *)user; (void)z;
    if (!u || tok >= u->vocab) {
        if (u) {
            sprintf(u->stop_buf, "TOKEN%llu_COMMIT_FAILED",
                    (unsigned long long)(pos ? pos : 1));
            u->stop = u->stop_buf;
            printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
        }
        return 0;
    }
    u->v->next_token = (uint32_t)tok;
    if (!d2_inv_commit(&u->inv, pos)) {
        u->stop = u->inv.fail ? u->inv.fail : "INVARIANT_COMMIT_FAIL";
        printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
        return 0;
    }
    printf("AR_COMMIT token=%llu pos=%llu\n", (unsigned long long)tok,
           (unsigned long long)pos);
    return 1;
}
int ar_advance(void *user, uint64_t tok, uint64_t next_pos, uint64_t z)
{
    ArUser *u = (ArUser *)user; (void)z;
    if (!u) return 0;
    u->next_tok = (uint32_t)tok;
    printf("AR_ADVANCE next_token=%u next_pos=%llu\n", u->next_tok,
           (unsigned long long)next_pos);
    if (next_pos > 0 && u->last_pos + 1u != (uint32_t)next_pos && u->real_fwd) {
        sprintf(u->stop_buf, "TOKEN%llu_ADVANCE_FAILED",
                (unsigned long long)next_pos);
        u->stop = u->stop_buf;
        printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
        return 0;
    }
    if (!d2_inv_advance(&u->inv, next_pos)) {
        u->stop = u->inv.fail ? u->inv.fail : "INVARIANT_ADVANCE_FAIL";
        printf("AUTHORIZATION_STOP_REASON=%s\n", u->stop);
        return 0;
    }
    return 1;
}
static void fill_wit(D2Wit *w, uint64_t bit, const D2Ctx *c, const ArUser *u,
                     uint32_t flags, uint32_t req)
{
    memset(w, 0, sizeof *w);
    w->bit = bit; w->executed = 1; w->completed = 1; w->error = c->err;
    w->model_gen = w->cur_model = u->model_gen;
    w->decode_gen = w->cur_decode = u->decode_gen;
    w->ticket = w->cur_ticket = u->ticket;
    w->obs = (uint32_t)c->gen; w->exp = (uint32_t)c->target;
    w->flags = flags; w->req = req;
}
static void copy_telem(SsArResult *o, const ArUser *u)
{
    o->sealed0 = u->sealed0; o->sealed1 = u->sealed1;
    o->full_block_fwd = u->full_block_fwd;
    o->embd_after_adv = u->embd_after_adv; o->embd_calls = u->embd_calls;
    o->tok0_embd = u->tok0_embd; o->tok0_loop = u->tok0_loop;
    o->tok0_rms = u->tok0_rms; o->tok0_lm = u->tok0_lm; o->tok0_rows = u->tok0_rows;
    o->tok1_embd = u->tok1_embd; o->tok1_loop = u->tok1_loop;
    o->tok1_rms = u->tok1_rms; o->tok1_lm = u->tok1_lm;
    o->tok1_rows = u->tok1_rows; o->tok1_tile = u->tok1_tile;
    o->pos0 = u->pos0; o->pos1 = u->pos1;
    o->last_pos = u->last_pos; o->real_fwd = u->real_fwd;
    o->post_tok1_alive = u->post_tok1_alive;
    o->post_last_alive = u->post_last_alive;
    o->device_lost = u->device_lost;
    o->stop = u->stop;
}
int ss_ar_decode_run(SsVk *v, const SsModelPlan *plan, uint64_t target, SsArResult *out)
{
    ArUser u; D2Bind b; D2Ctx ctx; D2Auth auth; D2Wit wit;
    memset(out, 0, sizeof *out); memset(&u, 0, sizeof u); memset(&ctx, 0, sizeof ctx);
    if (!v || !plan || !out || !target || !plan->planReal) return 100;
    u.v = v; u.plan = plan; u.next_tok = 0;
    u.model_gen = 1; u.decode_gen = 1; u.ticket = 1;
    ar_endurance_begin(&u);
    d2_tps_begin(&u.tps);
    b.user = &u; b.fwd = (void *)ar_forward; b.commit = (void *)ar_commit;
    b.adv = (void *)ar_advance;
    if (!Deep2DecodeInit(&ctx, &b)) return 100;
    if (!Deep2RunFullDecode(&ctx, target)) {
        out->error_code = ctx.err; out->generated = ctx.gen;
        out->forward_calls = ctx.fwd_n; out->commit_calls = ctx.commit_n;
        out->advance_calls = ctx.adv_n; out->runtime_flags = ctx.flags;
        out->target = target; copy_telem(out, &u);
        d2_tps_end(&u.tps);
        ar_endurance_print(&u, target);
        d2_tps_print(&u.tps, out->generated, 0, out->sealed0 + out->sealed1,
                     out->device_lost);
        free(u.host_logits); return 100;
    }
    if (!Deep2DecodeValidateWitness(&ctx)) {
        copy_telem(out, &u);
        d2_tps_end(&u.tps);
        ar_endurance_print(&u, target);
        d2_tps_print(&u.tps, out->generated, 0, out->sealed0 + out->sealed1,
                     out->device_lost);
        free(u.host_logits); return 100;
    }
    out->generated = ctx.gen; out->forward_calls = ctx.fwd_n;
    out->commit_calls = ctx.commit_n; out->advance_calls = ctx.adv_n;
    out->target = ctx.target; out->last_token = ctx.last_tok;
    out->runtime_flags = ctx.flags; out->error_code = ctx.err;
    out->full_decode_observed = (ctx.flags & 0x1Full) == 0x1Full;
    copy_telem(out, &u);
    Deep2AuthInit(&auth, u.model_gen, u.decode_gen, u.ticket);
    fill_wit(&wit, 0x2ull, &ctx, &u, (uint32_t)ctx.flags, 0x3u);
    if (Deep2AttemptGrantAuthority(&auth, &wit))
        out->auth_token_select = Deep2AuthQuery(&auth, 0x2ull);
    fill_wit(&wit, 0x4ull, &ctx, &u, (uint32_t)ctx.flags, 0x1Fu);
    if (Deep2AttemptGrantAuthority(&auth, &wit))
        out->auth_ar_commit = Deep2AuthQuery(&auth, 0x4ull);
    if (target >= 1) {
        uint32_t need = (uint32_t)target;
        uint32_t vrows = plan->vocabSize ? plan->vocabSize : 129280u;
        /* #1+#2: one executor; sealed reuse forbidden at every position. */
        out->pass = out->full_decode_observed && out->auth_ar_commit
            && out->generated == target && out->error_code == 0
            && out->sealed0 == 0 && out->sealed1 == 0
            && out->full_block_fwd >= need && out->real_fwd >= need
            && out->embd_calls >= need
            && out->tok0_embd && out->tok0_loop && out->tok0_rms && out->tok0_lm
            && out->tok0_rows == vrows
            && (need < 2 || (out->tok1_embd && out->tok1_loop && out->tok1_rms
                && out->tok1_lm && out->tok1_rows == vrows
                && out->tok1_tile == 16384u && out->pos1 == 1
                && out->post_tok1_alive))
            && out->last_pos == need - 1u
            && out->post_last_alive && !out->device_lost
            && out->forward_calls == target && out->commit_calls == target
            && out->advance_calls == target
            && ar_endurance_finish(&u, target);
        if (!out->pass && !out->stop)
            out->stop = "TOKEN0_COMMIT_FAILED";
        if (!out->pass && (out->sealed0 || out->sealed1))
            out->stop = "SEALED_LOGITS_REUSE_FORBIDDEN";
        if (!out->pass && out->device_lost)
            out->stop = "TOKEN_DEVICE_LOST";
        if (!out->pass && !ar_endurance_finish(&u, target) && !out->stop)
            out->stop = "ENDURANCE_INVARIANT_FAIL";
    } else {
        out->pass = 0;
    }
    ar_endurance_print(&u, target);
    d2_tps_end(&u.tps);
    d2_tps_print(&u.tps, out->generated, out->pass,
                 out->sealed0 + out->sealed1, out->device_lost);
    free(u.host_logits);
    return out->pass ? 0 : 100;
}
