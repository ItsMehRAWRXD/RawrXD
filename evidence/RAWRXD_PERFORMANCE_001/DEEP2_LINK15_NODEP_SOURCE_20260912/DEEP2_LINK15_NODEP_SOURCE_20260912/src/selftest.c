#include "d2_link15.h"
#include <stdio.h>

static int mock_link(void *user, D2LinkContext *ctx, D2LinkEvidence *out) {
    uintptr_t id = (uintptr_t)user;
    (void)ctx;
    if (!out || id >= D2_LINK15_COUNT) return 0;
    out->observed_bits = 1ull << id;
    out->metric0 = 1000u + (uint64_t)id;
    out->metric1 = 2000u + (uint64_t)id;
    out->metric2 = 3000u + (uint64_t)id;
    return 1;
}

int main(void) {
    D2LinkContext ctx;
    D2FullModelTiming t;
    unsigned i;
    uint64_t proofs =
        D2_PROOF_TARGET64_SEALED |
        D2_PROOF_FULL_MODEL_DECODE |
        D2_PROOF_SEALED_LOGITS_ZERO |
        D2_PROOF_SYNTHETIC_LOGITS_ZERO |
        D2_PROOF_DEVICE_SURVIVED |
        D2_PROOF_WARMUP_EXCLUDED;

    d2_link15_init(&ctx);

    /* Out-of-order execution must fail. */
    d2_link15_bind(&ctx, D2_LINK_02_UNIVERSAL_TILED_QUANT, mock_link, (void *)(uintptr_t)D2_LINK_02_UNIVERSAL_TILED_QUANT);
    if (d2_link15_run(&ctx, D2_LINK_02_UNIVERSAL_TILED_QUANT)) {
        puts("ORDER_GUARD=FAIL");
        return 2;
    }

    for (i = 0; i < D2_LINK15_COUNT; ++i) {
        if (!d2_link15_bind(&ctx, (D2LinkId)i, mock_link, (void *)(uintptr_t)i)) {
            puts("BIND=FAIL");
            return 3;
        }
    }

    d2_link15_set_external(&ctx, proofs);

    t.generated_tokens = 64;
    t.generation_wall_ns = 6400000000ull;
    t.token_mean_ns = 100000000ull;
    t.token_p50_ns = 99000000ull;
    t.token_p95_ns = 108000000ull;
    t.full_model_decode = 1;
    t.sealed_logits_reuse_count = 0;
    t.synthetic_logits_count = 0;
    t.device_lost = 0;
    t.warmup_excluded = 1;
    d2_link15_set_baseline(&ctx, &t);

    if (!d2_link15_run_all(&ctx)) {
        puts("RUN_ALL=FAIL");
        return 4;
    }
    if (!d2_link15_validate(&ctx) || !d2_link15_all_passed(&ctx)) {
        puts("VALIDATE=FAIL");
        return 5;
    }
    if ((ctx.authority_bits & D2_AUTH_FULL_MODEL_TPS) == 0) {
        puts("TPS_AUTHORITY=FAIL");
        return 6;
    }
    if ((ctx.authority_bits & D2_AUTH_PROMOTE) != 0) {
        puts("PROMOTE_BOUNDARY=FAIL");
        return 7;
    }

    puts("D2_LINK15_SELFTEST=PASS");
    printf("PASSED_LINK_MASK=0x%llx\n", (unsigned long long)ctx.passed_links);
    printf("FULL_MODEL_TPS_AUTHORITY=%u\n", (unsigned)((ctx.authority_bits & D2_AUTH_FULL_MODEL_TPS) != 0));
    printf("PROMOTE=%u\n", (unsigned)((ctx.authority_bits & D2_AUTH_PROMOTE) != 0));
    for (i = 0; i < D2_LINK15_COUNT; ++i) {
        printf("%02u %s PASS\n", i + 1u, d2_link15_name((D2LinkId)i));
    }
    return 0;
}
