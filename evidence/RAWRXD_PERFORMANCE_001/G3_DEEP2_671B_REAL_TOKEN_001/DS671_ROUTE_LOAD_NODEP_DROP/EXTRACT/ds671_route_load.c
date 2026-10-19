#include "ds671_route_load.h"

static int ds671_mul_overflow_size(size_t a, size_t b, size_t *out) {
    if (!out) return 1;
    if (a != 0 && b > ((size_t)-1) / a) return 1;
    *out = a * b;
    return 0;
}

size_t ds671_arena_bytes(uint32_t layers, uint32_t experts) {
    size_t n, bytes;
    if (!layers || !experts) return 0;
    if (ds671_mul_overflow_size((size_t)layers, (size_t)experts, &n)) return 0;
    if (ds671_mul_overflow_size(n, sizeof(ds671_expert_state), &bytes)) return 0;
    return bytes;
}

static void ds671_zero_states(ds671_expert_state *p, uint64_t n) {
    uint64_t i;
    for (i = 0; i < n; ++i) {
        p[i].handle = 0; p[i].bytes = 0; p[i].hits = 0; p[i].last_token = 0;
        p[i].resident = 0; p[i].prompt_seen = 0;
        p[i].reserved0 = 0; p[i].reserved1 = 0;
    }
}

int ds671_init(ds671_ctx *ctx, const ds671_config *cfg,
               const ds671_callbacks *cb, void *arena, size_t arena_bytes) {
    size_t need;
    uint64_t count;
    if (!ctx || !cfg || !cb || !arena || !cb->measure || !cb->load || !cb->release)
        return DS671_E_ARG;
    if (!cfg->moe_layers || !cfg->experts_per_layer || !cfg->top_k ||
        cfg->top_k > 16 || cfg->top_k > cfg->experts_per_layer ||
        !cfg->routed_expert_budget_bytes)
        return DS671_E_ARG;
    if (cfg->mode != DS671_MODE_STRICT_PROMPT_ONLY &&
        cfg->mode != DS671_MODE_GROW_NO_EVICT)
        return DS671_E_ARG;

    need = ds671_arena_bytes(cfg->moe_layers, cfg->experts_per_layer);
    if (!need || arena_bytes < need) return DS671_E_ARENA;

    count = (uint64_t)cfg->moe_layers * (uint64_t)cfg->experts_per_layer;
    ctx->cfg = *cfg; ctx->cb = *cb; ctx->states = (ds671_expert_state *)arena;
    ctx->state_count = count; ctx->resident_bytes = 0; ctx->loads = 0;
    ctx->hits = 0; ctx->misses = 0; ctx->prompt_unique = 0; ctx->decode_unique = 0;
    ctx->phase = DS671_PHASE_PROMPT; ctx->sealed_prompt_tokens = 0;
    ds671_zero_states(ctx->states, count);
    return DS671_OK;
}

static ds671_expert_state *ds671_state(ds671_ctx *ctx, uint32_t layer, uint32_t expert) {
    uint64_t idx = (uint64_t)layer * ctx->cfg.experts_per_layer + expert;
    return &ctx->states[idx];
}

static int ds671_ensure(ds671_ctx *ctx, uint32_t token, uint32_t layer,
                        uint32_t expert, uint64_t *handle_out, uint32_t *loaded_now) {
    ds671_expert_state *s;
    uint64_t expected = 0, actual = 0, handle = 0;
    int rc;

    if (layer >= ctx->cfg.moe_layers || expert >= ctx->cfg.experts_per_layer)
        return DS671_E_RANGE;
    s = ds671_state(ctx, layer, expert);
    s->hits += 1; s->last_token = token;

    if (s->resident) {
        ctx->hits += 1;
        *handle_out = s->handle;
        return DS671_OK;
    }

    ctx->misses += 1;
    if (ctx->phase == DS671_PHASE_DECODE &&
        ctx->cfg.mode == DS671_MODE_STRICT_PROMPT_ONLY &&
        !s->prompt_seen)
        return DS671_E_DECODE_MISS;

    rc = ctx->cb.measure(ctx->cb.user, layer, expert, &expected);
    if (rc != 0 || expected == 0) return DS671_E_LOAD;
    if (expected > ctx->cfg.routed_expert_budget_bytes - ctx->resident_bytes)
        return DS671_E_BUDGET;

    rc = ctx->cb.load(ctx->cb.user, layer, expert, expected, &handle, &actual);
    if (rc != 0 || handle == 0) return DS671_E_LOAD;
    if (actual != expected) {
        ctx->cb.release(ctx->cb.user, layer, expert, handle);
        return DS671_E_SIZE_MISMATCH;
    }

    s->handle = handle; s->bytes = actual; s->resident = 1;
    if (ctx->phase == DS671_PHASE_PROMPT) {
        if (!s->prompt_seen) ctx->prompt_unique += 1;
        s->prompt_seen = 1;
    } else {
        ctx->decode_unique += 1;
    }
    ctx->resident_bytes += actual; ctx->loads += 1; *loaded_now += 1;
    *handle_out = handle;
    return DS671_OK;
}

int ds671_require_route(ds671_ctx *ctx, uint32_t token_index, uint32_t moe_layer,
                        const uint32_t *expert_ids, uint32_t count,
                        ds671_route_result *out) {
    uint32_t i, j, loaded_now = 0;
    int rc;
    if (!ctx || !expert_ids || !out) return DS671_E_ARG;
    if (ctx->phase != DS671_PHASE_PROMPT && ctx->phase != DS671_PHASE_DECODE)
        return DS671_E_STATE;
    if (count != ctx->cfg.top_k || count > 16) return DS671_E_ARG;
    if (moe_layer >= ctx->cfg.moe_layers) return DS671_E_RANGE;

    out->count = 0; out->loaded_now = 0;
    for (i = 0; i < count; ++i) {
        if (expert_ids[i] >= ctx->cfg.experts_per_layer) return DS671_E_RANGE;
        for (j = 0; j < i; ++j)
            if (expert_ids[j] == expert_ids[i]) return DS671_E_DUPLICATE;
    }

    for (i = 0; i < count; ++i) {
        rc = ds671_ensure(ctx, token_index, moe_layer, expert_ids[i],
                          &out->handles[i], &loaded_now);
        if (rc != DS671_OK) {
            ctx->phase = DS671_PHASE_FAILED;
            return rc;
        }
        out->count += 1;
    }
    out->loaded_now = loaded_now;
    return DS671_OK;
}

int ds671_seal_prompt(ds671_ctx *ctx, uint32_t prompt_tokens) {
    if (!ctx || ctx->phase != DS671_PHASE_PROMPT || prompt_tokens == 0)
        return DS671_E_STATE;
    ctx->sealed_prompt_tokens = prompt_tokens;
    ctx->phase = DS671_PHASE_DECODE;
    return DS671_OK;
}

int ds671_get_handle(const ds671_ctx *ctx, uint32_t layer, uint32_t expert,
                     uint64_t *handle_out) {
    uint64_t idx;
    const ds671_expert_state *s;
    if (!ctx || !handle_out || layer >= ctx->cfg.moe_layers ||
        expert >= ctx->cfg.experts_per_layer) return DS671_E_ARG;
    idx = (uint64_t)layer * ctx->cfg.experts_per_layer + expert;
    s = &ctx->states[idx];
    if (!s->resident || !s->handle) return DS671_E_DECODE_MISS;
    *handle_out = s->handle;
    return DS671_OK;
}

void ds671_release_all(ds671_ctx *ctx) {
    uint64_t i;
    if (!ctx || !ctx->states || !ctx->cb.release) return;
    for (i = 0; i < ctx->state_count; ++i) {
        ds671_expert_state *s = &ctx->states[i];
        if (s->resident && s->handle) {
            uint32_t layer = (uint32_t)(i / ctx->cfg.experts_per_layer);
            uint32_t expert = (uint32_t)(i % ctx->cfg.experts_per_layer);
            ctx->cb.release(ctx->cb.user, layer, expert, s->handle);
            s->resident = 0; s->handle = 0; s->bytes = 0;
        }
    }
    ctx->resident_bytes = 0;
}
