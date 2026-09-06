#pragma once

#include "RawrXD_TokenPressureValve.hpp"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TPV_SamplerHints {
    int32_t repeat_penalty_bps; /* basis points added by caller, e.g. 120 = +1.20% */
    int32_t top_k_delta;        /* negative narrows, positive widens */
    uint32_t stop_hint;
    uint32_t compress_hint;
    uint32_t repair_hint;
    uint32_t approval_hold;
} TPV_SamplerHints;

uint32_t TPV_ClassifyUtf8Token(const char* token_bytes, uint32_t token_len);
uint32_t TPV_UpdateUtf8Token(TPV_State* state, uint32_t token_id, const char* token_bytes, uint32_t token_len, TPV_Result* out_result);
uint32_t TPV_ResultToSamplerHints(const TPV_Result* result, TPV_SamplerHints* out_hints);

#ifdef __cplusplus
}
#endif

