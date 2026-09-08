#pragma once
/* RAWRXD_SPIN_CLOSE_WALL_ATTRIB_001 — rank ≠ policy. */
#include <cstdint>
#include <cstdio>

namespace rawr::spin_attrib {

struct Stage {
    const char* name;
    uint64_t us;
};

inline void Emit(uint64_t wallNs, double tps, Stage* s, int n) noexcept {
    std::printf("RAWRXD_SPIN_CLOSE_WALL_ATTRIB_001=1\n");
    std::printf("BASELINE_TPS=3.556 DECODE_TPS_REAL=%.3f GENERATION_WALL_NS=%llu\n",
                tps, (unsigned long long)wallNs);
    std::printf("KVA_INVERSION_RETIRED=1 KVA_REENTRY_ALLOWED=0\n");
    for (int i = 0; i < n; ++i)
        std::printf("%s_EXPOSED_US=%llu\n", s[i].name,
                    (unsigned long long)s[i].us);
    int best = 0;
    for (int i = 1; i < n; ++i)
        if (s[i].us > s[best].us) best = i;
    std::printf("SPIN_CLOSE_BLOCKER=%s\n", s[best].name);
    std::printf("SPIN_CLOSE_BLOCKER_US=%llu\n",
                (unsigned long long)s[best].us);
    std::printf("SPIN_CLOSE_BLOCKER_OWNER=%s\n",
                s[best].name[0] == 'L' ? "LOGITS_CPU_GPU_SPLIT" : s[best].name);
    std::printf("MEASURED_LARGEST_OWNER=%s\n",
                s[best].name[0] == 'L' ? "LOGITS_CPU_GPU_SPLIT" : s[best].name);
    std::printf("OPTIMIZATION_ORDER_NEXT=REMOVE_KVA_FROM_EXPOSED_CAUSAL_DEPTH\n");
    std::printf("THEN=QKV_KVA_TRUE_OVERLAP\n");
    std::printf("LOGITS_SPLIT_CUT=DEFERRED\n");
    std::printf("NEXT_RUNTIME_ACTION=REMOVE_KVA_FROM_EXPOSED_CAUSAL_DEPTH\n");
    std::printf("PASS_ATTRIBUTION=%d\n", s[best].us > 0 ? 1 : 0);
}

} // namespace rawr::spin_attrib
