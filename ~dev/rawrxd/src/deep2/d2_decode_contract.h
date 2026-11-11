#ifndef D2_DECODE_CONTRACT_H
#define D2_DECODE_CONTRACT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    D2X_OK = 0,
    D2X_EINVAL = -1,
    D2X_ESTATE = -2,
    D2X_ECALL = -3,
    D2X_EAUTH = -4,
    D2X_ECANCEL = -5
};

typedef struct D2DecodeReceipt {
    uint64_t token_index;
    uint64_t critical_path_ns;
    uint64_t overlap_ns;
    uint64_t finish_skew_ns;

    uint64_t packed_bytes_gpu0;
    uint64_t packed_bytes_gpu1;

    uint32_t aggregate_bw_authority;
    uint32_t product_linked;
    uint32_t packed_q2k_live;
    uint32_t material_same_token_overlap;

    uint32_t full_model_forward;
    uint32_t final_norm_real;
    uint32_t lm_head_real;
    uint32_t sampler_commit_real;

    uint32_t kv_advance_real;
    uint32_t output_parity;
    uint32_t sealed_logits_reuse;
    uint32_t host_forward_layer_calls;

    uint32_t host_materializations;
    uint32_t cpu_f32_expands;
    uint32_t command_rebuilds_this_token;
    uint32_t kv_host_roundtrips;

    uint32_t critical_path_nvme_reads;
    uint32_t serial_gpu_chain;
    uint32_t weight_migration;
    uint32_t synthetic_io;

    uint32_t device_lost;
    uint32_t external_runtime_calls;
    uint32_t token_id_valid;
    uint32_t utf8_valid;
} D2DecodeReceipt;

static inline int d2_decode_receipt_authoritative(const D2DecodeReceipt* r) {
    if (!r) return 0;
    return
        r->aggregate_bw_authority &&
        r->product_linked &&
        r->packed_q2k_live &&
        r->material_same_token_overlap &&
        r->full_model_forward &&
        r->final_norm_real &&
        r->lm_head_real &&
        r->sampler_commit_real &&
        r->kv_advance_real &&
        r->output_parity &&
        !r->sealed_logits_reuse &&
        !r->host_forward_layer_calls &&
        !r->host_materializations &&
        !r->cpu_f32_expands &&
        !r->command_rebuilds_this_token &&
        !r->kv_host_roundtrips &&
        !r->critical_path_nvme_reads &&
        !r->serial_gpu_chain &&
        !r->weight_migration &&
        !r->synthetic_io &&
        !r->device_lost &&
        !r->external_runtime_calls &&
        r->token_id_valid;
}

#ifdef __cplusplus
}
#endif
#endif
