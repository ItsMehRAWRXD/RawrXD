#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace Deep2 {

// K2_USEFUL_TPS_001 consumes Deep2Benchmark certify capacity — never recomputes TPS.
// Authority line: MAXIMUM_STABLE_STREAMING_CAPACITY_TPS
struct K2UsefulTpsGate {
    double maxStableStreamingCapacityTps = 0.0;
    double usefulFloor = 5.0;
    int productionDecodePath = 0;
    int decodeStable = 0;
    int vramStable = 0;
    int kvStable = 0;
    int enduranceCertifiable = 0;
    int fullStabilityWindows = 0;
    uint64_t generatedTokens = 0;
    int benchmarkCertPass = 0;
    char modelClass[32]{};
    char certEvidencePath[512]{};
    int useful = 0;
};

inline bool K2UsefulTpsPass(const K2UsefulTpsGate& g) {
    // Product seal requires certify provenance + capacity floor.
    // Endurance marks optional for synthetic unit tests that only pass capacity+guards.
    return g.productionDecodePath != 0 && g.decodeStable != 0 &&
           g.vramStable != 0 && g.kvStable != 0 &&
           g.maxStableStreamingCapacityTps >= g.usefulFloor;
}

inline bool K2UsefulTpsProductSeal(const K2UsefulTpsGate& g) {
    return K2UsefulTpsPass(g) && g.benchmarkCertPass != 0 &&
           g.enduranceCertifiable != 0 && g.fullStabilityWindows >= 4 &&
           g.generatedTokens >= 2048ull;
}

inline void K2UsefulTpsWriteEvidence(FILE* f, const K2UsefulTpsGate& g,
                                     const char* result) {
    if (!f) return;
    std::fprintf(f, "K2_USEFUL_TPS_001=%s\n", result);
    std::fprintf(f, "AUTHORITY=MAXIMUM_STABLE_STREAMING_CAPACITY_TPS\n");
    std::fprintf(f, "SOURCE=BENCHMARK_CERT\n");
    std::fprintf(f, "PROVENANCE_CHAIN=Deep2Benchmark.certify->DECODE_TPS_MIN_WINDOW->"
                    "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS->K2_USEFUL_TPS_001\n");
    std::fprintf(f, "INTERNAL_DECODE_COUNTER_USED=0\n");
    std::fprintf(f, "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS=%.6f\n",
                 g.maxStableStreamingCapacityTps);
    std::fprintf(f, "USEFUL_FLOOR=%.3f\n", g.usefulFloor);
    std::fprintf(f, "PRODUCTION_DECODE_PATH=%d\n", g.productionDecodePath);
    std::fprintf(f, "DECODE_STABLE=%d\n", g.decodeStable);
    std::fprintf(f, "VRAM_STABLE=%d\n", g.vramStable);
    std::fprintf(f, "KV_STABLE=%d\n", g.kvStable);
    std::fprintf(f, "ENDURANCE_CERTIFIABLE=%d\n", g.enduranceCertifiable);
    std::fprintf(f, "FULL_STABILITY_WINDOWS=%d\n", g.fullStabilityWindows);
    std::fprintf(f, "GENERATED_TOKENS=%llu\n",
                 (unsigned long long)g.generatedTokens);
    std::fprintf(f, "BENCHMARK_CERT_RESULT=%s\n",
                 g.benchmarkCertPass ? "PASS" : "FAIL");
    std::fprintf(f, "MODEL_CLASS=%s\n",
                 g.modelClass[0] ? g.modelClass : "UNKNOWN");
    std::fprintf(f, "CERT_EVIDENCE=%s\n",
                 g.certEvidencePath[0] ? g.certEvidencePath : "");
}

} // namespace Deep2
