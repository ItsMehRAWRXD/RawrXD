#include "deep2_streamer_live.h"

int d2_streamer_init(D2Streamer* s, const D2StreamerOps* ops) {
    if (!s || !ops || !ops->open_model || !ops->close_model ||
        !ops->reset_context || !ops->prefill || !ops->decode_one || !ops->emit)
        return D2_EINVAL;
    *s = (D2Streamer){0};
    s->ops = *ops;
    return D2_OK;
}

int d2_streamer_open(D2Streamer* s, const char* model_path) {
    if (!s || !model_path || s->model_open) return D2_ESTATE;
    if (s->ops.open_model(s->ops.user, model_path)) return D2_ECALLBACK;
    s->model_open = 1;
    return D2_OK;
}

int d2_streamer_generate(
    D2Streamer* s,
    const char* prompt,
    size_t prompt_bytes,
    uint64_t max_new_tokens)
{
    uint64_t i;
    int rc;
    if (!s || !s->model_open || s->generating || !prompt || !max_new_tokens)
        return D2_ESTATE;

    s->generating = 1;
    s->cancel_requested = 0;
    s->generated_tokens = 0;
    s->generation_id++;

    rc = s->ops.prefill(s->ops.user, prompt, prompt_bytes);
    if (rc) {
        s->generating = 0;
        return D2_ECALLBACK;
    }

    for (i = 0; i < max_new_tokens; ++i) {
        uint32_t token_id = 0;
        const char* utf8 = 0;
        size_t utf8_bytes = 0;
        D2TokenTiming timing = {0};

        if (s->cancel_requested) {
            s->generating = 0;
            return D2_ECANCEL;
        }

        rc = s->ops.decode_one(
            s->ops.user, i, &token_id, &utf8, &utf8_bytes, &timing);
        if (rc) {
            s->generating = 0;
            return D2_ECALLBACK;
        }

        d2_finalize_timing(&timing);
        if (timing.device_lost) s->device_lost_seen = 1;
        s->external_runtime_calls += timing.external_runtime_calls;

        if (!d2_token_authority_safe(&timing)) {
            s->rejected_tokens++;
            s->generating = 0;
            return D2_EAUTH;
        }

        if (utf8 && utf8_bytes) {
            rc = s->ops.emit(s->ops.user, utf8, utf8_bytes);
            if (rc) {
                s->generating = 0;
                return D2_ECALLBACK;
            }
        }

        (void)token_id;
        s->generated_tokens++;
        s->total_generated_tokens++;
    }

    s->generating = 0;
    return D2_OK;
}

void d2_streamer_cancel(D2Streamer* s) {
    if (!s) return;
    s->cancel_requested = 1;
}

int d2_streamer_reset(D2Streamer* s) {
    if (!s || !s->model_open || s->generating) return D2_ESTATE;
    if (s->ops.reset_context(s->ops.user)) return D2_ECALLBACK;
    s->context_reused = 1;
    s->cancel_requested = 0;
    return D2_OK;
}

int d2_streamer_close(D2Streamer* s) {
    if (!s || !s->model_open || s->generating) return D2_ESTATE;
    if (s->ops.close_model(s->ops.user)) return D2_ECALLBACK;
    s->model_open = 0;
    s->cancel_requested = 0;
    return D2_OK;
}

int d2_streamer_e2e_ready(const D2Streamer* s) {
    if (!s) return 0;
    return
        s->generation_id >= 2 &&
        s->total_generated_tokens >= 32 &&
        s->rejected_tokens == 0 &&
        s->external_runtime_calls == 0 &&
        s->device_lost_seen == 0 &&
        s->context_reused;
}
