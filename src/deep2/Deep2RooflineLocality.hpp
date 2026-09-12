#pragma once
/* DEEP2_ROOFLINE_LOCALITY_001 — measure BYTES_NOT_ALREADY_LOCAL_*. PROMOTE=0. */
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace Deep2 {

struct RooflineLocalityMetrics {
    uint64_t target = 64;
    uint64_t generated = 0;
    uint64_t wup_d = 0;
    uint64_t weight_req = 0;
    uint64_t weight_local = 0;
    uint64_t bytes_not_local = 0;
    uint64_t bytes_not_local_pt = 0;
    uint64_t host_to_device = 0;
    uint64_t inter_gpu = 0;
    uint64_t critical_host = 0;
    uint64_t gpu0_fwd = 0;
    uint64_t gpu1_fwd = 0;
    uint64_t same_token_overlap = 0;
    uint64_t wall_ns = 0;
    uint64_t token_ns_p50 = 0;
    uint64_t token_ns_p95 = 0;
    double tps = 0.0;
    int residency_sealed = 1;
    int dual = 0;
    int pass = 0;
    int runtime = 0;
};

inline uint64_t RooflinePercentileNs(std::vector<uint64_t>& v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    const size_t i = (size_t)((v.size() - 1) * p);
    return v[i < v.size() ? i : v.size() - 1];
}

inline void RooflineLocalityWriteReceipt(
    const char* path, const RooflineLocalityMetrics& m) noexcept
{
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return;
    const char* st = !m.runtime ? "SOURCE_WIRED" :
        (m.pass ? "LIVE_PRODUCT_PASS" : "RUNTIME_HOLD");
    const char* rf = !m.runtime ? "NOT_RUN" : (m.pass ? "PASS" : "HOLD");
    std::fprintf(f, "GATE=DEEP2_ROOFLINE_LOCALITY_001\n");
    std::fprintf(f, "STATUS=%s\n", st);
    std::fprintf(f, "SOURCE_WIRED=1\nRUNTIME_REACHED=%d\n", m.runtime ? 1 : 0);
    std::fprintf(f, "LIVE_PRODUCT_RUN=%s\n",
                 m.pass ? "PASS" : (m.runtime ? "HOLD" : "NOT_RUN"));
    std::fprintf(f, "TARGET=%llu\nGENERATED_TOKENS=%llu\n",
                 (unsigned long long)m.target,
                 (unsigned long long)m.generated);
    std::fprintf(f, "RESIDENCY_SEALED=%d\nwup_d=%llu\n",
                 m.residency_sealed, (unsigned long long)m.wup_d);
    std::fprintf(f, "WEIGHT_BYTES_REQUESTED_TOTAL=%llu\n",
                 (unsigned long long)m.weight_req);
    std::fprintf(f, "WEIGHT_BYTES_ALREADY_LOCAL=%llu\n",
                 (unsigned long long)m.weight_local);
    std::fprintf(f, "BYTES_NOT_ALREADY_LOCAL_TOTAL=%llu\n",
                 (unsigned long long)m.bytes_not_local);
    std::fprintf(f, "BYTES_NOT_ALREADY_LOCAL_PER_TOKEN=%llu\n",
                 (unsigned long long)m.bytes_not_local_pt);
    std::fprintf(f, "HOST_TO_DEVICE_BYTES=%llu\n",
                 (unsigned long long)m.host_to_device);
    std::fprintf(f, "INTER_GPU_BYTES=%llu\n",
                 (unsigned long long)m.inter_gpu);
    std::fprintf(f, "CRITICAL_PATH_HOST_BYTES=%llu\n",
                 (unsigned long long)m.critical_host);
    std::fprintf(f, "GPU0_FORWARD_COUNT=%llu\n",
                 (unsigned long long)m.gpu0_fwd);
    std::fprintf(f, "GPU1_FORWARD_COUNT=%llu\n",
                 (unsigned long long)m.gpu1_fwd);
    std::fprintf(f, "SAME_TOKEN_OVERLAP_COUNT=%llu\n",
                 (unsigned long long)m.same_token_overlap);
    std::fprintf(f, "GENERATION_WALL_NS=%llu\n",
                 (unsigned long long)m.wall_ns);
    std::fprintf(f, "TOKEN_NS_P50=%llu\nTOKEN_NS_P95=%llu\n",
                 (unsigned long long)m.token_ns_p50,
                 (unsigned long long)m.token_ns_p95);
    std::fprintf(f, "TPS_MEASURED=%.6f\n", m.tps);
    std::fprintf(f, "DUAL=%d\nROOFLINE_LOCALITY=%s\n", m.dual, rf);
    std::fprintf(f, "ROOFLINE_LOCALITY_SEALED=%d\n", m.pass ? 1 : 0);
    std::fprintf(f, "VERIFY=%s\nPROMOTE=0\nTIP_CLIMB=HOLD\n",
                 m.pass ? "PASS" : (m.runtime ? "HOLD" : "NOT_RUN"));
    std::fprintf(f, "NEXT=%s\nNOT_RUN!=PASS\n",
                 m.pass ? "DEEP2_DAILY_STREAMER_LIVE_001"
                        : "DEEP2_ROOFLINE_LOCALITY_001");
    std::fclose(f);
}

} // namespace Deep2
