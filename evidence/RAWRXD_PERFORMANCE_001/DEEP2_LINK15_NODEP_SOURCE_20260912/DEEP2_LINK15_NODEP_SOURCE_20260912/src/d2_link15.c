#include "d2_link15.h"

#define LINKBIT(n) (1ull << (unsigned)(n))

static const D2LinkDescriptor kPlan[D2_LINK15_COUNT] = {
    { D2_LINK_01_TPS_AUTHORITY,       "FULL_MODEL_TPS_AUTHORITY",       0, D2_PROOF_TARGET64_SEALED | D2_PROOF_FULL_MODEL_DECODE | D2_PROOF_SEALED_LOGITS_ZERO | D2_PROOF_SYNTHETIC_LOGITS_ZERO | D2_PROOF_DEVICE_SURVIVED | D2_PROOF_WARMUP_EXCLUDED },
    { D2_LINK_02_UNIVERSAL_TILED_QUANT,"UNIVERSAL_TILED_QUANT",        LINKBIT(D2_LINK_01_TPS_AUTHORITY), 0 },
    { D2_LINK_03_DIRECT_PACKED_Q2K,    "DIRECT_PACKED_Q2K",            LINKBIT(D2_LINK_02_UNIVERSAL_TILED_QUANT), 0 },
    { D2_LINK_04_PERSISTENT_RESIDENCY, "PERSISTENT_DEVICE_RESIDENCY",  LINKBIT(D2_LINK_03_DIRECT_PACKED_Q2K), 0 },
    { D2_LINK_05_DEVICEIO_SSVK,        "D2DEVICEIO_TO_SSVK",           LINKBIT(D2_LINK_04_PERSISTENT_RESIDENCY), 0 },
    { D2_LINK_06_EXACT_RANGE_BIND,     "EXACT_RANGE_PRODUCT_BIND",     LINKBIT(D2_LINK_05_DEVICEIO_SSVK), 0 },
    { D2_LINK_07_DEVICE_KV,            "DEVICE_KV",                    LINKBIT(D2_LINK_06_EXACT_RANGE_BIND), 0 },
    { D2_LINK_08_FUSED_ATTN,           "FUSED_ATTN_PATH",              LINKBIT(D2_LINK_07_DEVICE_KV), 0 },
    { D2_LINK_09_FUSED_FFN,            "FUSED_FFN_PATH",               LINKBIT(D2_LINK_08_FUSED_ATTN), 0 },
    { D2_LINK_10_LMHEAD_REDUCE,        "TILED_LMHEAD_DEVICE_REDUCE",   LINKBIT(D2_LINK_09_FUSED_FFN), 0 },
    { D2_LINK_11_SAMPLER_COMMIT,       "NATIVE_SAMPLER_COMMIT",        LINKBIT(D2_LINK_10_LMHEAD_REDUCE), 0 },
    { D2_LINK_12_PERSISTENT_EXEC_GRAPH,"PERSISTENT_EXEC_GRAPH",        LINKBIT(D2_LINK_11_SAMPLER_COMMIT), 0 },
    { D2_LINK_13_REAL_DUAL_GPU,        "REAL_DUAL_GPU_ARITHMETIC",     LINKBIT(D2_LINK_12_PERSISTENT_EXEC_GRAPH), 0 },
    { D2_LINK_14_BOUNDED_64GB_STREAM,  "BOUNDED_64GB_STREAMING",       LINKBIT(D2_LINK_13_REAL_DUAL_GPU), 0 },
    { D2_LINK_15_UNIFIED_EXECUTOR,     "UNIFIED_EXECUTOR",             LINKBIT(D2_LINK_14_BOUNDED_64GB_STREAM), 0 }
};

static int valid_id(D2LinkId id) {
    return (unsigned)id < D2_LINK15_COUNT;
}

void d2_link15_init(D2LinkContext *ctx) {
    unsigned i;
    if (!ctx) return;
    ctx->abi_version = D2_LINK15_ABI_VERSION;
    ctx->external_proofs = 0;
    ctx->passed_links = 0;
    ctx->authority_bits = 0;
    ctx->failed_links = 0;
    ctx->baseline.generated_tokens = 0;
    ctx->baseline.generation_wall_ns = 0;
    ctx->baseline.token_mean_ns = 0;
    ctx->baseline.token_p50_ns = 0;
    ctx->baseline.token_p95_ns = 0;
    ctx->baseline.full_model_decode = 0;
    ctx->baseline.sealed_logits_reuse_count = 0;
    ctx->baseline.synthetic_logits_count = 0;
    ctx->baseline.device_lost = 0;
    ctx->baseline.warmup_excluded = 0;
    for (i = 0; i < D2_LINK15_COUNT; ++i) {
        ctx->binding[i].fn = 0;
        ctx->binding[i].user = 0;
        ctx->evidence[i].observed_bits = 0;
        ctx->evidence[i].metric0 = 0;
        ctx->evidence[i].metric1 = 0;
        ctx->evidence[i].metric2 = 0;
        ctx->evidence[i].rc = 0;
    }
}

int d2_link15_bind(D2LinkContext *ctx, D2LinkId id, D2LinkFn fn, void *user) {
    if (!ctx || !valid_id(id) || !fn) return 0;
    ctx->binding[(unsigned)id].fn = fn;
    ctx->binding[(unsigned)id].user = user;
    return 1;
}

int d2_link15_set_external(D2LinkContext *ctx, uint64_t proof_bits) {
    if (!ctx) return 0;
    ctx->external_proofs = proof_bits;
    return 1;
}

int d2_link15_set_baseline(D2LinkContext *ctx, const D2FullModelTiming *t) {
    if (!ctx || !t) return 0;
    ctx->baseline = *t;
    return 1;
}

static int baseline_is_authoritative(const D2LinkContext *ctx) {
    const D2FullModelTiming *t = &ctx->baseline;
    if (t->full_model_decode != 1u) return 0;
    if (t->generated_tokens < 64u) return 0;
    if (t->generation_wall_ns == 0u) return 0;
    if (t->sealed_logits_reuse_count != 0u) return 0;
    if (t->synthetic_logits_count != 0u) return 0;
    if (t->device_lost != 0u) return 0;
    if (t->warmup_excluded != 1u) return 0;
    return 1;
}

int d2_link15_run(D2LinkContext *ctx, D2LinkId id) {
    const D2LinkDescriptor *d;
    D2Binding *b;
    D2LinkEvidence ev;
    uint64_t bit;
    int rc;

    if (!ctx || ctx->abi_version != D2_LINK15_ABI_VERSION || !valid_id(id)) return 0;
    d = &kPlan[(unsigned)id];
    bit = LINKBIT(id);

    if ((ctx->passed_links & bit) != 0) return 1;
    if ((ctx->passed_links & d->requires_links) != d->requires_links) return 0;
    if ((ctx->external_proofs & d->requires_external) != d->requires_external) return 0;
    if (id == D2_LINK_01_TPS_AUTHORITY && !baseline_is_authoritative(ctx)) return 0;

    b = &ctx->binding[(unsigned)id];
    if (!b->fn) return 0;

    ev.observed_bits = 0;
    ev.metric0 = ev.metric1 = ev.metric2 = 0;
    ev.rc = 0;
    rc = b->fn(b->user, ctx, &ev);
    ev.rc = rc;
    ctx->evidence[(unsigned)id] = ev;

    if (rc != 1) {
        ctx->failed_links |= bit;
        return 0;
    }

    ctx->passed_links |= bit;
    if (id == D2_LINK_01_TPS_AUTHORITY) {
        ctx->authority_bits |= D2_AUTH_FULL_MODEL_TPS;
    }
    return 1;
}

int d2_link15_run_all(D2LinkContext *ctx) {
    unsigned i;
    if (!ctx) return 0;
    for (i = 0; i < D2_LINK15_COUNT; ++i) {
        if (!d2_link15_run(ctx, (D2LinkId)i)) return 0;
    }
    return 1;
}

int d2_link15_validate(const D2LinkContext *ctx) {
    uint64_t full = (1ull << D2_LINK15_COUNT) - 1ull;
    if (!ctx || ctx->abi_version != D2_LINK15_ABI_VERSION) return 0;
    if ((ctx->authority_bits & D2_AUTH_PROMOTE) != 0) return 0; /* this drop never mints promotion */
    if ((ctx->passed_links & ~full) != 0) return 0;
    if ((ctx->failed_links & ctx->passed_links) != 0) return 0;
    if ((ctx->authority_bits & D2_AUTH_FULL_MODEL_TPS) != 0 && !baseline_is_authoritative(ctx)) return 0;
    return 1;
}

int d2_link15_all_passed(const D2LinkContext *ctx) {
    uint64_t full = (1ull << D2_LINK15_COUNT) - 1ull;
    return ctx && (ctx->passed_links & full) == full;
}

const D2LinkDescriptor *d2_link15_descriptor(D2LinkId id) {
    return valid_id(id) ? &kPlan[(unsigned)id] : 0;
}

const char *d2_link15_name(D2LinkId id) {
    const D2LinkDescriptor *d = d2_link15_descriptor(id);
    return d ? d->name : "INVALID_LINK";
}
