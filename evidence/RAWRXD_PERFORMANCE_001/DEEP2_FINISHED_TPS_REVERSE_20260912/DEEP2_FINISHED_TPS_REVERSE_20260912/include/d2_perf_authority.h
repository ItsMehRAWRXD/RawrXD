#ifndef D2_PERF_AUTHORITY_H
#define D2_PERF_AUTHORITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct D2PerfProjection {
    uint64_t touched_weight_bytes_per_token;
    double target_tps;
    double required_weight_bw_gbs;
    double device_peak_bw_gbs;
    double peak_bw_utilization;
    double ideal_weight_only_ms_per_token;
} D2PerfProjection;

typedef struct D2PerfObservation {
    uint64_t generated_tokens;
    uint64_t wall_ns;
    uint64_t touched_weight_bytes_total;
    uint64_t gpu0_weight_bytes_total;
    uint64_t gpu1_weight_bytes_total;
    uint64_t host_to_device_bytes_total;
    uint64_t cross_gpu_bytes_total;
    uint64_t allocation_count_after_warmup;
    uint64_t sealed_logits_reuse_count;
    uint64_t synthetic_logits_count;
    uint64_t synthetic_weight_count;
    int full_model_decode;
    int all_blocks_every_token;
    int device_lost;
} D2PerfObservation;

typedef struct D2PerfObservedResult {
    double measured_tps;
    double effective_weight_bw_gbs;
    double ms_per_token;
    int authority_eligible;
} D2PerfObservedResult;

D2PerfProjection d2_perf_project(uint64_t touched_weight_bytes_per_token,
                                 double target_tps,
                                 double device_peak_bw_gbs);

D2PerfObservedResult d2_perf_observe(const D2PerfObservation* obs);

#ifdef __cplusplus
}
#endif

#endif
