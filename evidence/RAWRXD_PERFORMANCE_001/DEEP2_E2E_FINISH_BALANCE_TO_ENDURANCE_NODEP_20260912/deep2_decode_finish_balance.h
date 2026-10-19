#ifndef DEEP2_DECODE_FINISH_BALANCE_H
#define DEEP2_DECODE_FINISH_BALANCE_H
#include "deep2_e2e_types.h"
#ifdef __cplusplus
extern "C" {
#endif
#define D2_BAL_Q 16u
#define D2_BAL_ONE (1u << D2_BAL_Q)
typedef struct D2DecodeBalancerConfig {
    uint64_t total_work_units;
    uint64_t alignment_units;
    uint32_t ewma_old_q16;
    uint32_t min_lane_percent_q16;
    uint32_t rollback_percent_q16;
} D2DecodeBalancerConfig;
typedef struct D2DecodeBalancer {
    D2DecodeBalancerConfig cfg;
    uint64_t cost0_ns_per_work_q16;
    uint64_t cost1_ns_per_work_q16;
    uint64_t next_work0;
    uint64_t next_work1;
    uint64_t best_work0;
    uint64_t best_work1;
    uint64_t best_critical_ns;
    int64_t last_start_skew_signed_ns;
    int64_t last_finish_skew_signed_ns;
    uint64_t samples;
    uint64_t rejected_samples;
} D2DecodeBalancer;
int d2_balance_init(D2DecodeBalancer* s, const D2DecodeBalancerConfig* cfg, uint64_t initial_work0);
int d2_balance_observe_and_plan(D2DecodeBalancer* s, const D2TokenTiming* timing,
                                uint64_t* out_work0, uint64_t* out_work1);
#ifdef __cplusplus
}
#endif
#endif
