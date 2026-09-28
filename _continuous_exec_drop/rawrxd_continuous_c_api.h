#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawrXDContinuousStatus {
    uint64_t run_id;
    uint64_t sequence;
    uint64_t work_epoch;
    uint64_t token_index;
    uint32_t state;
    uint32_t event_kind;
    uint32_t finish_reason;
    uint32_t layer_index;
    uint32_t layer_count;
} RawrXDContinuousStatus;

// Stable numeric values mirror continuous_execution.hpp enums.
// This header deliberately contains no fake inference implementation.

#ifdef __cplusplus
}
#endif
