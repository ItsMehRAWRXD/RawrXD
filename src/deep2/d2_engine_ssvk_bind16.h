/* DEEP2_ENGINE_SSVK_DECODE_BIND16_NODEP_20260912 — C ABI
 * Governing 16-token decode bind. PROMOTE=0. 84-byte Q2_K only. */
#ifndef D2_ENGINE_SSVK_BIND16_H
#define D2_ENGINE_SSVK_BIND16_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    D2_Q2K_BLOCK_BYTES = 84,
    D2_Q2K_BLOCK_ELEMENTS = 256,
    D2_BIND16_REQUIRED_TOKENS = 16,
    D2_BIND16_MIN_SHORTER_PM = 700,
    D2_BIND16_MIN_CRITICAL_PM = 500
};

typedef struct D2PackedProductRequest {
    const void* packed_weights;
    const float* input;
    float* output;
    uint64_t rows;
    uint64_t cols;
    uint64_t weight_bytes;
    uint64_t token_ordinal;
    uint64_t operator_ordinal;
    const char* tensor_name;
} D2PackedProductRequest;

typedef struct D2PackedProductProof {
    uint64_t gpu0_start_ns, gpu0_end_ns;
    uint64_t gpu1_start_ns, gpu1_end_ns;
    uint64_t gpu0_packed_bytes, gpu1_packed_bytes;
    uint64_t overlap_ns, critical_path_ns;
    uint32_t overlap_shorter_pm;
    uint32_t overlap_critical_pm;
    uint32_t product_linked;
    uint32_t packed_q2k_live;
    uint32_t material_same_token_overlap;
    uint32_t aggregate_bw_authority;
    uint32_t gpu0_real_forwards;
    uint32_t gpu1_real_forwards;
    uint32_t compact_merge_real;
    uint32_t output_parity;
    uint32_t full_dequant_buffer;
    uint32_t materialized_weight_bytes_nonzero;
    uint32_t serial_gpu_chain;
    uint32_t weight_migration;
    uint32_t synthetic_io;
    uint32_t device_lost;
    uint32_t critical_path_nvme_reads;
} D2PackedProductProof;

typedef struct D2GpuCounterSnapshot {
    uint64_t host_forward_layer_calls;
    uint64_t host_materializations;
    uint64_t cpu_f32_expands;
    uint64_t forward_slot0;
    uint64_t forward_slot1;
    uint64_t q2k_packed_ops;
    uint64_t critical_path_nvme_reads;
    uint64_t external_runtime_calls;
} D2GpuCounterSnapshot;

typedef struct D2DecodeTokenProof {
    uint64_t token_ordinal;
    uint64_t q2k_ops_seen;
    uint64_t q2k_ops_product;
    uint64_t gpu0_packed_bytes;
    uint64_t gpu1_packed_bytes;
    uint64_t overlap_ns_sum;
    uint64_t critical_path_ns_sum;
    uint32_t min_shorter_pm;
    uint32_t min_critical_pm;
    uint32_t all_ops_ok;
    uint32_t any_dual_forward;
    uint32_t any_device_lost;
    uint32_t stale_72_byte_path_used;
    uint32_t full_model_forward;
    uint32_t final_norm_real;
    uint32_t lm_head_real;
    uint32_t sampler_commit_real;
    uint32_t kv_advance_real;
    uint32_t sealed_logits_reuse;
    uint32_t host_fwd_delta;
    uint32_t host_mat_delta;
    uint32_t cpu_f32_delta;
    uint32_t slot0_delta;
    uint32_t slot1_delta;
    uint32_t is_real_gpu_forward;
    uint32_t committed_pass;
} D2DecodeTokenProof;

typedef struct D2Bind16Window {
    uint32_t tokens_required;
    uint32_t tokens_committed;
    uint32_t tokens_pass;
    uint32_t authority; /* 1 only at 16/16 pass */
    uint32_t promote;   /* always 0 */
} D2Bind16Window;

typedef int (*D2PackedProductRunFn)(
    void* user,
    const D2PackedProductRequest* req,
    D2PackedProductProof* proof);

typedef struct D2EngineSsVkBind16 {
    D2PackedProductRunFn run;
    void* user;
    D2DecodeTokenProof token;
    D2GpuCounterSnapshot snap_begin;
    D2Bind16Window window;
    uint64_t next_operator_ordinal;
    uint32_t initialized;
} D2EngineSsVkBind16;

void d2bind16_init(D2EngineSsVkBind16* b);
void d2bind16_bind(D2EngineSsVkBind16* b, D2PackedProductRunFn fn, void* user);
void d2bind16_begin_token(D2EngineSsVkBind16* b, uint64_t token_ordinal,
                          const D2GpuCounterSnapshot* before);
int  d2bind16_dispatch_q2k(D2EngineSsVkBind16* b,
                           const D2PackedProductRequest* req);
void d2bind16_end_forward(D2EngineSsVkBind16* b,
                          const D2GpuCounterSnapshot* after,
                          int is_real_gpu_forward);
void d2bind16_note_tail(D2EngineSsVkBind16* b,
                        int final_norm, int lm_head,
                        int kv_advance, int sampler_commit,
                        int sealed_logits_reuse);
int  d2bind16_commit_token(D2EngineSsVkBind16* b);
const D2DecodeTokenProof* d2bind16_token(const D2EngineSsVkBind16* b);
const D2Bind16Window* d2bind16_window(const D2EngineSsVkBind16* b);

#ifdef __cplusplus
}
#endif
#endif
