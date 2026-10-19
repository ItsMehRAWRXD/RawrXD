#include "d2u.h"
#include <string.h>

int d2u_authority_init(d2u_authority *a, uint64_t owner_cookie) {
    if (!a || !owner_cookie) return D2U_E_ARG;
    memset(a, 0, sizeof(*a));
    a->owner_cookie = owner_cookie;
    a->next_ticket = 1;
    return D2U_OK;
}

int d2u_scheduler_claim(d2u_authority *a, uint64_t owner_cookie) {
    if (!a || !owner_cookie || owner_cookie != a->owner_cookie) return D2U_E_AUTH;
    if (a->failed || a->op_open) return D2U_E_STATE;
    a->scheduler_authority = 1;
    return D2U_OK;
}

int d2u_op_begin(d2u_authority *a, uint64_t owner_cookie, uint32_t token, uint32_t layer,
                 d2u_op_kind op, d2u_io_reason reason, uint64_t *ticket) {
    if (!a || !ticket || !a->scheduler_authority || owner_cookie != a->owner_cookie)
        return D2U_E_AUTH;
    if (a->failed || a->op_open || op == D2U_OP_NONE || reason == D2U_IO_NONE)
        return D2U_E_STATE;
    a->active_ticket = a->next_ticket++;
    a->token_index = token;
    a->layer_index = layer;
    a->op = op;
    a->reason = reason;
    a->op_open = 1;
    *ticket = a->active_ticket;
    return D2U_OK;
}

int d2u_op_end(d2u_authority *a, uint64_t owner_cookie, uint64_t ticket, int success) {
    if (!a || owner_cookie != a->owner_cookie || !a->op_open || ticket != a->active_ticket)
        return D2U_E_AUTH;
    if (!success) a->failed = 1;
    a->op_open = 0;
    a->active_ticket = 0;
    a->op = D2U_OP_NONE;
    a->reason = D2U_IO_NONE;
    return success ? D2U_OK : D2U_E_STATE;
}

int d2u_tensor_read(const d2u_model *m, d2u_authority *a, uint64_t ticket,
                    const d2u_tensor *t, uint64_t off, void *dst, size_t n,
                    d2u_io_reason required_reason) {
    if (!m || !a || !t || !dst || !n) return D2U_E_ARG;
    if (!a->scheduler_authority || !a->op_open || ticket != a->active_ticket ||
        a->reason != required_reason || a->failed) {
        a->rejected_io++;
        return D2U_E_AUTH;
    }
    if (t->shard >= m->shard_count || off > t->size_bytes || n > t->size_bytes - off) {
        a->rejected_io++;
        return D2U_E_RANGE;
    }
    d2u_shard *s = (d2u_shard *)&m->shards[t->shard];
    if (!s->fp) return D2U_E_IO;
#if defined(_WIN32)
    if (_fseeki64(s->fp, (__int64)(t->data_offset + off), SEEK_SET) != 0) return D2U_E_IO;
#else
    if (fseek(s->fp, (long)(t->data_offset + off), SEEK_SET) != 0) return D2U_E_IO;
#endif
    if (fread(dst, 1, n, s->fp) != n) return D2U_E_IO;
    a->io_reads++;
    a->io_bytes += (uint64_t)n;
    return D2U_OK;
}

int d2u_note_layer_complete(d2u_authority *a, uint32_t layer, uint32_t expected_layers) {
    if (!a || a->failed || layer >= expected_layers) return D2U_E_STATE;
    if (a->completed_layers != layer) return D2U_E_STATE; /* strict sequential authority */
    a->completed_layers++;
    return D2U_OK;
}

int d2u_mint_decode_authority(d2u_authority *a, uint32_t expected_layers, int kv_commit_ok, int logits_ok) {
    if (!a || a->failed || a->op_open || !a->scheduler_authority) return D2U_E_STATE;
    if (a->completed_layers != expected_layers || !kv_commit_ok || !logits_ok) return D2U_E_AUTH;
    if (a->background_submits || a->predictive_loads) return D2U_E_AUTH;
    a->decode_authority = 1;
    return D2U_OK;
}

int d2u_commit_token(d2u_authority *a, uint64_t owner_cookie, uint32_t token_id) {
    (void)token_id;
    if (!a || owner_cookie != a->owner_cookie || !a->decode_authority || a->failed || a->op_open)
        return D2U_E_AUTH;
    a->token_commit_pass = 1;
    a->generated_tokens++;
    return D2U_OK;
}

int d2u_try_promote(d2u_authority *a, int model_valid) {
    if (!a) return D2U_E_ARG;
    a->promoted = (uint8_t)(model_valid && a->product_open_pass && a->session_enter_pass &&
                            a->generated_tokens > 0 && a->token_commit_pass &&
                            a->scheduler_authority && a->decode_authority && !a->failed &&
                            a->background_submits == 0 && a->predictive_loads == 0);
    return a->promoted ? D2U_OK : D2U_E_AUTH;
}
