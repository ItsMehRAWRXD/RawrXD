#ifndef DEEP2_E2E_TYPES_H
#define DEEP2_E2E_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    D2_OK = 0,
    D2_EINVAL = -1,
    D2_ESTATE = -2,
    D2_ECALLBACK = -3,
    D2_EAUTH = -4,
    D2_ENOSPACE = -5,
    D2_ECANCEL = -6
};

typedef struct D2TokenTiming {
    uint64_t token_index;
    uint64_t gpu0_start_ns;
    uint64_t gpu0_end_ns;
    uint64_t gpu1_start_ns;
    uint64_t gpu1_end_ns;
    uint64_t gpu0_work_units;
    uint64_t gpu1_work_units;
    uint64_t gpu0_packed_bytes;
    uint64_t gpu1_packed_bytes;
    uint64_t critical_path_ns;
    uint64_t overlap_ns;
    uint64_t finish_skew_ns;
    uint64_t start_skew_ns;
    uint32_t product_linked;
    uint32_t packed_q2k_live;
    uint32_t output_parity;
    uint32_t material_same_token_overlap;
    uint32_t serial_gpu_chain;
    uint32_t weight_migration;
    uint32_t synthetic_device_io;
    uint32_t device_lost;
    uint32_t full_dequant_buffer;
    uint32_t materialized_weight_bytes_nonzero;
    uint32_t critical_path_nvme_reads;
    uint32_t command_rebuilds_this_token;
    uint32_t kv_host_roundtrips;
    uint32_t external_runtime_calls;
    uint32_t reserved0;
    uint32_t reserved1;
} D2TokenTiming;

static inline uint64_t d2_u64_absdiff(uint64_t a, uint64_t b) {
    return a >= b ? a - b : b - a;
}
static inline uint64_t d2_min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }
static inline uint64_t d2_max_u64(uint64_t a, uint64_t b) { return a > b ? a : b; }

static inline void d2_finalize_timing(D2TokenTiming* t) {
    uint64_t start_max, end_min, span_start, span_end;
    if (!t) return;
    t->start_skew_ns = d2_u64_absdiff(t->gpu0_start_ns, t->gpu1_start_ns);
    t->finish_skew_ns = d2_u64_absdiff(t->gpu0_end_ns, t->gpu1_end_ns);
    start_max = d2_max_u64(t->gpu0_start_ns, t->gpu1_start_ns);
    end_min = d2_min_u64(t->gpu0_end_ns, t->gpu1_end_ns);
    t->overlap_ns = end_min > start_max ? end_min - start_max : 0;
    span_start = d2_min_u64(t->gpu0_start_ns, t->gpu1_start_ns);
    span_end = d2_max_u64(t->gpu0_end_ns, t->gpu1_end_ns);
    t->critical_path_ns = span_end > span_start ? span_end - span_start : 0;
}

static inline int d2_token_authority_safe(const D2TokenTiming* t) {
    if (!t) return 0;
    return t->product_linked && t->packed_q2k_live && t->output_parity &&
           t->material_same_token_overlap && !t->serial_gpu_chain &&
           !t->weight_migration && !t->synthetic_device_io && !t->device_lost &&
           !t->full_dequant_buffer && !t->materialized_weight_bytes_nonzero &&
           !t->critical_path_nvme_reads && !t->kv_host_roundtrips &&
           !t->external_runtime_calls;
}

#ifdef __cplusplus
}
#endif
#endif
