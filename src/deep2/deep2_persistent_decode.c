#include "deep2_persistent_decode.h"

int d2_pd_open(
    D2PersistentDecode* s,
    const D2PersistentDecodeOps* ops,
    uint64_t max_context_tokens)
{
    int rc;
    if (!s || !ops || !max_context_tokens ||
        !ops->prepare_persistent_commands ||
        !ops->ensure_persistent_kv ||
        !ops->execute_token ||
        !ops->advance_kv)
        return D2_EINVAL;

    *s = (D2PersistentDecode){0};
    s->ops = *ops;
    s->max_context_tokens = max_context_tokens;

    rc = s->ops.prepare_persistent_commands(s->ops.user);
    if (rc) return D2_ECALLBACK;
    s->commands_ready = 1;

    rc = s->ops.ensure_persistent_kv(s->ops.user, max_context_tokens);
    if (rc) return D2_ECALLBACK;
    s->kv_ready = 1;
    s->active = 1;

    if (s->ops.prefetch_token) {
        rc = s->ops.prefetch_token(s->ops.user, 0);
        if (!rc) {
            s->prefetched_token_index = 0;
            s->has_prefetch = 1;
        }
    }

    return D2_OK;
}

int d2_pd_step(
    D2PersistentDecode* s,
    D2TokenTiming* out_timing)
{
    int rc;
    uint64_t token;
    if (!s || !out_timing || !s->active ||
        !s->commands_ready || !s->kv_ready)
        return D2_ESTATE;

    token = s->next_token_index;
    if (token >= s->max_context_tokens) return D2_ENOSPACE;

    *out_timing = (D2TokenTiming){0};
    out_timing->token_index = token;

    if (s->ops.prefetch_token &&
        (!s->has_prefetch || s->prefetched_token_index != token))
    {
        rc = s->ops.prefetch_token(s->ops.user, token);
        if (rc) return D2_ECALLBACK;
        s->prefetched_token_index = token;
        s->has_prefetch = 1;
    }

    rc = s->ops.execute_token(s->ops.user, token, out_timing);
    if (rc) {
        s->rejected_tokens++;
        return D2_ECALLBACK;
    }

    d2_finalize_timing(out_timing);

    s->command_rebuilds_after_warmup += out_timing->command_rebuilds_this_token;
    s->kv_host_roundtrips += out_timing->kv_host_roundtrips;
    s->critical_path_nvme_reads += out_timing->critical_path_nvme_reads;

    if (!d2_token_authority_safe(out_timing)) {
        s->rejected_tokens++;
        return D2_EAUTH;
    }

    rc = s->ops.advance_kv(s->ops.user, token);
    if (rc) {
        s->rejected_tokens++;
        return D2_ECALLBACK;
    }

    s->tokens_executed++;
    s->next_token_index++;

    /* Enqueue N+1 only after token N is committed. Backend may overlap it
       with sampling/streaming or next-token setup. */
    if (s->ops.prefetch_token && s->next_token_index < s->max_context_tokens) {
        rc = s->ops.prefetch_token(s->ops.user, s->next_token_index);
        if (!rc) {
            s->prefetched_token_index = s->next_token_index;
            s->has_prefetch = 1;
        } else {
            s->has_prefetch = 0;
        }
    }

    return D2_OK;
}

int d2_pd_reset(D2PersistentDecode* s) {
    int rc;
    if (!s || !s->active) return D2_ESTATE;
    if (s->ops.reset) {
        rc = s->ops.reset(s->ops.user);
        if (rc) return D2_ECALLBACK;
    }
    s->next_token_index = 0;
    s->prefetched_token_index = 0;
    s->has_prefetch = 0;
    if (s->ops.prefetch_token && !s->ops.prefetch_token(s->ops.user, 0)) {
        s->has_prefetch = 1;
    }
    return D2_OK;
}

void d2_pd_close(D2PersistentDecode* s) {
    if (!s) return;
    if (s->active && s->ops.reset) s->ops.reset(s->ops.user);
    s->active = 0;
    s->commands_ready = 0;
    s->kv_ready = 0;
    s->has_prefetch = 0;
}

int d2_pd_authority_ready(const D2PersistentDecode* s) {
    if (!s || !s->active) return 0;
    return
        s->commands_ready &&
        s->kv_ready &&
        s->tokens_executed >= 16 &&
        s->rejected_tokens == 0 &&
        s->command_rebuilds_after_warmup == 0 &&
        s->kv_host_roundtrips == 0 &&
        s->critical_path_nvme_reads == 0;
}
