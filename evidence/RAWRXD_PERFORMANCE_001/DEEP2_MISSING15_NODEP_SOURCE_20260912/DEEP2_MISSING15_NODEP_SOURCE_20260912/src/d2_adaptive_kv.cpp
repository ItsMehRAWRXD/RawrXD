#include "d2_nodep.h"

extern "C" int d2_adaptive_kv_plan(D2KvEntry* e, size_t count, uint64_t target_q8_equiv_tokens) {
    if (!e && count) return 0;
    uint64_t units=0;
    for (size_t i=0;i<count;i++) {
        if (e[i].importance_ppm >= 750000 || e[i].age_tokens < 128) e[i].codec=D2_KV_Q8;
        else if (e[i].importance_ppm >= 350000 || e[i].age_tokens < 1024) e[i].codec=D2_KV_Q4;
        else e[i].codec=D2_KV_Q2;
        units += (e[i].codec==D2_KV_Q8?4:(e[i].codec==D2_KV_Q4?2:1));
    }
    const uint64_t budget_units = target_q8_equiv_tokens * 4;
    while (units > budget_units) {
        size_t victim=count; uint64_t worst=~0ull;
        for (size_t i=0;i<count;i++) if (e[i].codec!=D2_KV_EVICT) {
            uint64_t keep = uint64_t(e[i].importance_ppm) * 2 + (e[i].age_tokens<1000000 ? (1000000-e[i].age_tokens) : 0);
            if (keep < worst) { worst=keep; victim=i; }
        }
        if (victim==count) break;
        units -= (e[victim].codec==D2_KV_Q8?4:(e[victim].codec==D2_KV_Q4?2:1));
        e[victim].codec=D2_KV_EVICT;
    }
    return 1;
}
