#ifndef D2_LINK15_H
#define D2_LINK15_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define D2_LINK15_ABI_VERSION 0x20260912u
#define D2_LINK15_COUNT 15u

/* External proof bits supplied by the already-sealed runtime. */
enum D2ExternalProofBits {
    D2_PROOF_TARGET64_SEALED       = 1ull << 0,
    D2_PROOF_FULL_MODEL_DECODE     = 1ull << 1,
    D2_PROOF_SEALED_LOGITS_ZERO    = 1ull << 2,
    D2_PROOF_SYNTHETIC_LOGITS_ZERO = 1ull << 3,
    D2_PROOF_DEVICE_SURVIVED       = 1ull << 4,
    D2_PROOF_WARMUP_EXCLUDED       = 1ull << 5
};

enum D2AuthorityBits {
    D2_AUTH_FULL_MODEL_TPS = 1ull << 0,
    D2_AUTH_PROMOTE        = 1ull << 1
};

typedef enum D2LinkId {
    D2_LINK_01_TPS_AUTHORITY = 0,
    D2_LINK_02_UNIVERSAL_TILED_QUANT,
    D2_LINK_03_DIRECT_PACKED_Q2K,
    D2_LINK_04_PERSISTENT_RESIDENCY,
    D2_LINK_05_DEVICEIO_SSVK,
    D2_LINK_06_EXACT_RANGE_BIND,
    D2_LINK_07_DEVICE_KV,
    D2_LINK_08_FUSED_ATTN,
    D2_LINK_09_FUSED_FFN,
    D2_LINK_10_LMHEAD_REDUCE,
    D2_LINK_11_SAMPLER_COMMIT,
    D2_LINK_12_PERSISTENT_EXEC_GRAPH,
    D2_LINK_13_REAL_DUAL_GPU,
    D2_LINK_14_BOUNDED_64GB_STREAM,
    D2_LINK_15_UNIFIED_EXECUTOR
} D2LinkId;

typedef struct D2FullModelTiming {
    uint64_t generated_tokens;
    uint64_t generation_wall_ns;
    uint64_t token_mean_ns;
    uint64_t token_p50_ns;
    uint64_t token_p95_ns;
    uint32_t full_model_decode;
    uint32_t sealed_logits_reuse_count;
    uint32_t synthetic_logits_count;
    uint32_t device_lost;
    uint32_t warmup_excluded;
} D2FullModelTiming;

typedef struct D2LinkEvidence {
    uint64_t observed_bits;
    uint64_t metric0;
    uint64_t metric1;
    uint64_t metric2;
    int32_t  rc;
} D2LinkEvidence;

struct D2LinkContext;
typedef int (*D2LinkFn)(void *user, struct D2LinkContext *ctx, D2LinkEvidence *out);

typedef struct D2Binding {
    D2LinkFn fn;
    void *user;
} D2Binding;

typedef struct D2LinkContext {
    uint32_t abi_version;
    uint64_t external_proofs;
    uint64_t passed_links;
    uint64_t authority_bits;
    uint64_t failed_links;
    D2FullModelTiming baseline;
    D2Binding binding[D2_LINK15_COUNT];
    D2LinkEvidence evidence[D2_LINK15_COUNT];
} D2LinkContext;

typedef struct D2LinkDescriptor {
    D2LinkId id;
    const char *name;
    uint64_t requires_links;
    uint64_t requires_external;
} D2LinkDescriptor;

void d2_link15_init(D2LinkContext *ctx);
int  d2_link15_bind(D2LinkContext *ctx, D2LinkId id, D2LinkFn fn, void *user);
int  d2_link15_set_external(D2LinkContext *ctx, uint64_t proof_bits);
int  d2_link15_set_baseline(D2LinkContext *ctx, const D2FullModelTiming *timing);
int  d2_link15_run(D2LinkContext *ctx, D2LinkId id);
int  d2_link15_run_all(D2LinkContext *ctx);
int  d2_link15_validate(const D2LinkContext *ctx);
int  d2_link15_all_passed(const D2LinkContext *ctx);
const D2LinkDescriptor *d2_link15_descriptor(D2LinkId id);
const char *d2_link15_name(D2LinkId id);

#ifdef __cplusplus
}
#endif

#endif
