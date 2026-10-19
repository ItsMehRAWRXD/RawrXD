/* morning_grouch.h — agnostic residency touch counters (streamer layer) */
#ifndef RAWRXD_MORNING_GROUCH_H
#define RAWRXD_MORNING_GROUCH_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MG_COLD = 0,
    MG_MORNING_GROUCH = 1,
    MG_WARM = 2,
    MG_HOT = 3
} mg_residency_state;

typedef struct {
    uint64_t morning_grouch_loads;
    uint64_t morning_grouch_bytes;
    uint64_t morning_grouch_ns;
    uint64_t warm_cache_hits;
    uint64_t hot_gpu_hits;
    uint64_t expert_first_touches;
    uint64_t expert_reuses;
    uint64_t rejected_speculative; /* must stay 0 if law holds */
} mg_counters;

void mg_counters_clear(mg_counters *c);

/* Record a demand-path residency outcome. speculative!=0 increments reject. */
void mg_on_touch(mg_counters *c, mg_residency_state prior,
                 uint64_t bytes, uint64_t ns, int is_expert, int speculative);

#ifdef __cplusplus
}
#endif
#endif
