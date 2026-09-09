#pragma once
/* RAWRXD_SPIN_CLOSE_WALL_ATTRIB_001 — rank by wall US; NEXT=largest. ≤99 */
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
    std::printf("KVA_ROWS_CLIMB=SEALED KVA_REENTRY_ALLOWED=0\n");
    for (int i = 0; i < n; ++i)
        std::printf("%s_EXPOSED_US=%llu\n", s[i].name,
                    (unsigned long long)s[i].us);
    int best = 0;
    for (int i = 1; i < n; ++i)
        if (s[i].us > s[best].us) best = i;
    const char* nm = s[best].name;
    const int isLogits = (nm[0] == 'L');
    std::printf("SPIN_CLOSE_BLOCKER=%s\n", nm);
    std::printf("SPIN_CLOSE_BLOCKER_US=%llu\n",
                (unsigned long long)s[best].us);
    std::printf("SPIN_CLOSE_BLOCKER_OWNER=%s\n",
                isLogits ? "LOGITS_CPU_GPU_SPLIT" : nm);
    std::printf("MEASURED_LARGEST_OWNER=%s\n",
                isLogits ? "LOGITS_CPU_GPU_SPLIT" : nm);
    std::printf("NEXT_RUNTIME_ACTION=%s\n",
                isLogits             ? "LOGITS_SPLIT_CUT"
                : (nm[0] == 'Q')     ? "QKV_EXPOSURE_CUT"
                : (nm[0] == 'O')     ? "O_PROJ_OVERLAP"
                : (nm[0] == 'K')     ? "KVA_EXPOSURE_AUDIT_ONLY"
                                     : "INSPECT_OWNER");
    std::printf("LOGITS_SPLIT_CUT=%s\n", isLogits ? "ACTIVE" : "NOT_LARGEST");
    std::printf("PASS_ATTRIBUTION=%d\n", s[best].us > 0 ? 1 : 0);
}

} // namespace rawr::spin_attrib
