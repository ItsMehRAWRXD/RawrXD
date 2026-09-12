#ifndef D2_ENDURANCE_GATE_H
#define D2_ENDURANCE_GATE_H

#include "d2_daily_streamer_live.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct D2EndurancePlan {
    const char* model_path;
    const char* prompt;
    size_t prompt_bytes;
    uint64_t tokens_per_generation;
    uint32_t generations;
    uint32_t reset_between;
    uint32_t reopen_after_case;
} D2EndurancePlan;

typedef struct D2EnduranceReport {
    uint64_t cases_run;
    uint64_t cases_pass;
    uint64_t generations;
    uint64_t tokens;
    uint64_t failures;
} D2EnduranceReport;

int d2_endurance_run(
    D2DailyStreamer* s,
    const D2EndurancePlan* plans,
    size_t plan_count,
    D2EnduranceReport* report);

int d2_endurance_pass(const D2EnduranceReport* r);

#ifdef __cplusplus
}
#endif
#endif
