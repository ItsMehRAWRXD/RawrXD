/* deep2_lb.h — C ABI mirror of deep2_lb.inc (caller-owned, no CRT) */
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    D2LB_Q16_ONE = 65536,
    D2LB_Q16_80_20_LANE1 = 13107,
    D2LB_SAMPLE_VALID = 1,
    D2LB_SAMPLE_PARITY_OK = 2,
    D2LB_SAMPLE_DEVICE_OK = 4,
    D2LB_SAMPLE_REQUIRED = 7
};

#pragma pack(push, 8)
typedef struct D2LB_SAMPLE {
    uint32_t rows0, rows1, flags, reserved0;
    uint64_t duration0_ns, duration1_ns, critical_ns, overlap_ns;
} D2LB_SAMPLE;

typedef struct D2LB_PLAN {
    uint32_t rows0, rows1, share1_q16, flags;
    uint64_t predicted_ns0, predicted_ns1;
} D2LB_PLAN;
#pragma pack(pop)

typedef struct alignas(16) D2LB_STATE {
    uint32_t share1_q16, best_share1_q16, min_share1_q16, max_share1_q16;
    uint32_t samples_ok, samples_rejected, last_plan_flags, reserved0;
    uint64_t ewma_nsrow0_q16, ewma_nsrow1_q16;
    uint64_t last_duration0_ns, last_duration1_ns, last_skew_ns;
    uint64_t last_critical_ns, best_critical_ns, last_overlap_ns;
    uint32_t last_rows0, last_rows1, last_align_rows, reserved1;
    uint8_t pad[16]; /* STRUCT 16 → 128 bytes caller-owned */
} D2LB_STATE;

void D2LbInit(D2LB_STATE* state);
void D2LbPlan(D2LB_STATE* state, uint32_t totalRows, uint32_t alignRows, D2LB_PLAN* plan);
void D2LbObserve(D2LB_STATE* state, const D2LB_SAMPLE* sample);

#ifdef __cplusplus
}
#endif
