#ifndef RAWRXD_WSC15_H
#define RAWRXD_WSC15_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WSC15_COUNT 15u
#define WSC_NOT_RUN 0u
#define WSC_FAIL    1u
#define WSC_PASS    2u

enum {
    WSC01_FIXED_SLOT_BOUND = 0,
    WSC02_FIXED_WINDOW_BOUND,
    WSC03_REQUEST_IN_FILE_BOUNDS,
    WSC04_SINGLE_WINDOW_REQUEST,
    WSC05_PIN_SAFE_EVICTION,
    WSC06_UNPINNED_LRU_ONLY,
    WSC07_NO_FULL_TENSOR_FALLBACK,
    WSC08_CURRENT_BYTES_BOUNDED,
    WSC09_PEAK_BYTES_BOUNDED,
    WSC10_CACHE_REUSE_ACCOUNTED,
    WSC11_NEW_BYTES_ACCOUNTED,
    WSC12_EVICTION_ACCOUNTED,
    WSC13_LEASE_LIFETIME_CLOSED,
    WSC14_TOKEN_WORKING_SET_CLOSED,
    WSC15_CONJUNCTION
};

typedef struct wsc15_raw {
    uint64_t file_bytes;
    uint64_t window_bytes;
    uint64_t slot_count;

    uint64_t request_offset;
    uint64_t request_bytes;

    uint64_t current_mapped_bytes;
    uint64_t peak_mapped_bytes;
    uint64_t configured_max_mapped_bytes;

    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t reused_bytes;
    uint64_t newly_mapped_bytes;
    uint64_t evictions;

    uint64_t live_pins_before_evict;
    uint64_t evictions_while_pinned;
    uint64_t non_lru_evictions;

    uint64_t full_tensor_fallback_count;

    uint64_t leases_acquired;
    uint64_t leases_released;
    uint64_t invalid_release_count;

    uint64_t token_id;
    uint64_t token_begin_mapped_bytes;
    uint64_t token_end_mapped_bytes;
    uint64_t token_peak_mapped_bytes;
    uint64_t token_newly_mapped_bytes;
    uint64_t token_reused_bytes;

    uint64_t request_observed;
    uint64_t token_observed;
} wsc15_raw;

typedef struct wsc15_result {
    uint64_t witness[WSC15_COUNT];
    uint64_t pass_count;
    uint64_t fail_count;
    uint64_t not_run_count;
    uint64_t contract_pass;
} wsc15_result;

void wsc15_evaluate(const wsc15_raw* raw, wsc15_result* out);

#ifdef __cplusplus
}
#endif
#endif
