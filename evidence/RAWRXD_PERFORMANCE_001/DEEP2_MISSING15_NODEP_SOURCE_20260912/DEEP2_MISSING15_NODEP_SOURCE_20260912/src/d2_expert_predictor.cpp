#include "d2_nodep.h"

extern "C" int d2_expert_predict(const uint32_t* previous, size_t prev_count, uint32_t expert_count, uint32_t topk, uint32_t* out_ids, size_t out_count) {
    if (!previous || !prev_count || !expert_count || !topk || !out_ids || out_count < topk) return 0;
    // Allocation-free locality predictor: preserve valid recent expert order, then fill round-robin.
    size_t n=0;
    for (size_t rev=0; rev<prev_count && n<topk; ++rev) {
        uint32_t id=previous[prev_count-1-rev];
        if (id>=expert_count) continue;
        bool dup=false; for (size_t j=0;j<n;j++) if (out_ids[j]==id) dup=true;
        if (!dup) out_ids[n++]=id;
    }
    for (uint32_t id=0; n<topk && id<expert_count; ++id) {
        bool dup=false; for (size_t j=0;j<n;j++) if (out_ids[j]==id) dup=true;
        if (!dup) out_ids[n++]=id;
    }
    return n==topk ? 1 : 0;
}
