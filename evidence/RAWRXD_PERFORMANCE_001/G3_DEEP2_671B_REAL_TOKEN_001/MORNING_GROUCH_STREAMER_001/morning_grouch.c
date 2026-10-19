/* morning_grouch.c */
#include "morning_grouch.h"

void mg_counters_clear(mg_counters *c)
{
    if (!c) return;
    c->morning_grouch_loads = 0;
    c->morning_grouch_bytes = 0;
    c->morning_grouch_ns = 0;
    c->warm_cache_hits = 0;
    c->hot_gpu_hits = 0;
    c->expert_first_touches = 0;
    c->expert_reuses = 0;
    c->rejected_speculative = 0;
}

void mg_on_touch(mg_counters *c, mg_residency_state prior,
                 uint64_t bytes, uint64_t ns, int is_expert, int speculative)
{
    if (!c) return;
    if (speculative) { c->rejected_speculative++; return; }
    if (prior == MG_COLD) {
        c->morning_grouch_loads++;
        c->morning_grouch_bytes += bytes;
        c->morning_grouch_ns += ns;
        if (is_expert) c->expert_first_touches++;
        return;
    }
    if (prior == MG_WARM) {
        c->warm_cache_hits++;
        if (is_expert) c->expert_reuses++;
        return;
    }
    if (prior == MG_HOT) {
        c->hot_gpu_hits++;
        if (is_expert) c->expert_reuses++;
        return;
    }
    /* MG_MORNING_GROUCH mid-state: count as first-touch acquisition window */
    c->morning_grouch_loads++;
    c->morning_grouch_bytes += bytes;
    c->morning_grouch_ns += ns;
    if (is_expert) c->expert_first_touches++;
}
