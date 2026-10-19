#ifndef DEEP2_ENDURANCE_H
#define DEEP2_ENDURANCE_H

#include <stdint.h>
#include <stddef.h>
#include "deep2_streamer_live.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct D2EnduranceCase {
    const char* model_path;
    const char* prompt;
    size_t prompt_bytes;
    uint64_t tokens_per_generation;
    uint32_t generations;
    uint32_t resets_between_generations;
} D2EnduranceCase;

typedef struct D2EnduranceResult {
    uint64_t cases_run;
    uint64_t cases_passed;
    uint64_t generations_run;
    uint64_t tokens_generated;
    uint64_t callback_failures;
    uint64_t authority_failures;
    uint64_t device_lost_failures;
    uint64_t external_runtime_calls;
} D2EnduranceResult;

int d2_run_endurance(
    D2Streamer* streamer,
    const D2EnduranceCase* cases,
    size_t case_count,
    D2EnduranceResult* out);

int d2_endurance_pass(const D2EnduranceResult* r);

#ifdef __cplusplus
}
#endif
#endif
