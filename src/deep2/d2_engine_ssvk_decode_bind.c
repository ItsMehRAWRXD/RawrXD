#include "d2_engine_ssvk_decode_bind.h"
#include <string.h>

int d2_decode_bind_open(D2DecodeBind* b, const D2DecodeBindOps* ops) {
    int rc;
    if (!b || !ops || !ops->prepare_persistent || !ops->begin_token ||
        !ops->run_full_forward || !ops->final_norm_lm_head ||
        !ops->sample_commit || !ops->kv_advance)
        return D2X_EINVAL;

    memset(b, 0, sizeof(*b));
    b->ops = *ops;
    rc = b->ops.prepare_persistent(b->ops.user);
    if (rc) return D2X_ECALL;
    b->persistent_prepares = 1;
    b->prepared = 1;
    b->active = 1;

    if (b->ops.prefetch_next) {
        if (!b->ops.prefetch_next(b->ops.user, 0))
            b->prefetch_enqueues++;
    }
    return D2X_OK;
}

int d2_decode_bind_one(
    D2DecodeBind* b,
    uint32_t* out_token_id,
    const char** out_utf8,
    size_t* out_utf8_bytes,
    D2DecodeReceipt* out_receipt)
{
    D2DecodeReceipt r;
    uint32_t token = 0;
    const char* utf8 = 0;
    size_t utf8n = 0;
    int rc;
    uint64_t idx;

    if (!b || !b->active || !b->prepared || !out_token_id || !out_receipt)
        return D2X_ESTATE;

    idx = b->next_token_index;
    memset(&r, 0, sizeof(r));
    r.token_index = idx;

    rc = b->ops.begin_token(b->ops.user, idx);
    if (rc) goto call_fail;

    rc = b->ops.run_full_forward(b->ops.user, idx, &r);
    if (rc) goto call_fail;

    rc = b->ops.final_norm_lm_head(b->ops.user, idx, &r);
    if (rc) goto call_fail;

    rc = b->ops.sample_commit(
        b->ops.user, idx, &token, &utf8, &utf8n, &r);
    if (rc) goto call_fail;

    r.token_id_valid = 1;
    r.utf8_valid = (utf8 && utf8n) ? 1u : 0u;

    /*
      IMPORTANT: do not advance KV until full forward + logits + sampler commit
      for this exact token have completed. This is the decode transaction commit.
    */
    rc = b->ops.kv_advance(b->ops.user, idx, token, &r);
    if (rc) goto call_fail;

    if (!d2_decode_receipt_authoritative(&r)) {
        b->rejected_tokens++;
        *out_receipt = r;
        return D2X_EAUTH;
    }

    *out_token_id = token;
    if (out_utf8) *out_utf8 = utf8;
    if (out_utf8_bytes) *out_utf8_bytes = utf8n;
    *out_receipt = r;

    b->tokens_committed++;
    b->next_token_index++;

    if (b->ops.prefetch_next) {
        if (!b->ops.prefetch_next(b->ops.user, b->next_token_index))
            b->prefetch_enqueues++;
    }
    return D2X_OK;

call_fail:
    b->rejected_tokens++;
    *out_receipt = r;
    return D2X_ECALL;
}

int d2_decode_bind_reset(D2DecodeBind* b) {
    if (!b || !b->active) return D2X_ESTATE;
    if (b->ops.reset_context && b->ops.reset_context(b->ops.user))
        return D2X_ECALL;
    b->next_token_index = 0;
    if (b->ops.prefetch_next) {
        if (!b->ops.prefetch_next(b->ops.user, 0))
            b->prefetch_enqueues++;
    }
    return D2X_OK;
}

void d2_decode_bind_close(D2DecodeBind* b) {
    if (!b) return;
    b->active = 0;
    b->prepared = 0;
}
