#include "d2_daily_streamer_live.h"
#include <string.h>

int d2_daily_init(D2DailyStreamer* s, D2DecodeBind* bind, const D2DailyOps* ops) {
    if (!s || !bind || !ops || !ops->open_model || !ops->close_model ||
        !ops->tokenize_prefill || !ops->emit)
        return D2X_EINVAL;
    memset(s, 0, sizeof(*s));
    s->bind = bind;
    s->ops = *ops;
    return D2X_OK;
}

int d2_daily_open_model(D2DailyStreamer* s, const char* path) {
    if (!s || !path || s->model_open) return D2X_ESTATE;
    if (s->ops.open_model(s->ops.user, path)) return D2X_ECALL;
    s->model_open = 1;
    s->opens++;
    return D2X_OK;
}

int d2_daily_generate(
    D2DailyStreamer* s,
    const char* prompt, size_t prompt_bytes,
    uint64_t max_new_tokens)
{
    uint64_t i;
    if (!s || !s->model_open || !prompt || !max_new_tokens) return D2X_ESTATE;
    if (s->ops.tokenize_prefill(s->ops.user, prompt, prompt_bytes))
        return D2X_ECALL;

    s->cancel_requested = 0;
    for (i = 0; i < max_new_tokens; ++i) {
        uint32_t token = 0;
        const char* utf8 = 0;
        size_t utf8n = 0;
        D2DecodeReceipt r;
        int rc;

        if (s->cancel_requested) return D2X_ECANCEL;

        rc = d2_decode_bind_one(
            s->bind, &token, &utf8, &utf8n, &r);
        if (rc) {
            s->authority_failures++;
            return rc;
        }

        if (s->ops.emit(s->ops.user, token, utf8, utf8n))
            return D2X_ECALL;
        s->generated_tokens++;
    }
    s->generations++;
    return D2X_OK;
}

void d2_daily_cancel(D2DailyStreamer* s) {
    if (s) s->cancel_requested = 1;
}

int d2_daily_reset_context(D2DailyStreamer* s) {
    if (!s || !s->model_open) return D2X_ESTATE;
    if (d2_decode_bind_reset(s->bind) != D2X_OK) return D2X_ECALL;
    s->resets++;
    return D2X_OK;
}

int d2_daily_close_model(D2DailyStreamer* s) {
    if (!s || !s->model_open) return D2X_ESTATE;
    if (s->ops.close_model(s->ops.user)) return D2X_ECALL;
    s->model_open = 0;
    s->closes++;
    return D2X_OK;
}
