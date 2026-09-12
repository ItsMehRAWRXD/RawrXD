/* deep2_decode_balance.h — C ABI for finish-time balancer (offsets match .inc) */
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    D2DB_Q16_ONE = 65536,
    D2DB_DEFAULT_GPU1_SHARE_Q16 = 21234, /* ~32.4% */
    D2DB_F_MODEL_READY = 1,
    D2DB_F_ROLLBACK_LAST = 2,
    D2DB_F_AUTH_VALID = 4
};

typedef struct D2DB_STATE {
    uint64_t magic;
    uint64_t cost0_q16;
    uint64_t cost1_q16;
    int64_t  start_skew_ewma_ns;
    int64_t  finish_skew_ewma_ns;
    uint64_t best_critical_ns;
    uint32_t best_share1_q16;
    uint32_t share1_q16;
    uint32_t valid_samples;
    uint32_t bad_samples;
    uint64_t token_index;
    uint64_t last_critical_ns;
    int64_t  last_finish_skew_ns;
    int64_t  last_start_skew_ns;
    uint64_t flags;
} D2DB_STATE; /* 104 bytes */

typedef struct D2DB_PLAN {
    uint32_t rows0, rows1, share1_q16, mode;
    uint64_t pred_end0_ns, pred_end1_ns;
} D2DB_PLAN; /* 32 */

typedef struct D2DB_SAMPLE {
    uint32_t rows0, rows1;
    uint64_t start0_ns, end0_ns, start1_ns, end1_ns;
    uint64_t critical_ns, overlap_ns;
    uint32_t output_parity, device_ok, same_token, product_linked;
    uint32_t packed_live, serial_chain, weight_migration, reserved;
} D2DB_SAMPLE; /* 88 */

void D2DbInit(D2DB_STATE* state);
int  D2DbPlanToken(D2DB_STATE* state, uint32_t totalRows, uint32_t rowAlignment, D2DB_PLAN* plan);
int  D2DbObserveToken(D2DB_STATE* state, const D2DB_SAMPLE* sample);

#ifdef __cplusplus
}
#endif
