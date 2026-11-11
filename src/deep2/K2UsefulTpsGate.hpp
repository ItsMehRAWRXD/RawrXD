#pragma once
#include "NsTokenRate.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace Deep2 {

// K2_USEFUL_TPS_001 — authority is CAPACITY_NS_TOKEN; TPS is reciprocal only.
struct K2UsefulTpsGate {
    double maxStableStreamingCapacityTps = 0.0;
    uint64_t capacityNsToken = 0;
    uint64_t capacityTargetNsToken = kCapacityTargetNsToken;
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
    // Execution validity is independent of USEFUL_FLOOR.
    return g.productionDecodePath != 0 && g.decodeStable != 0 &&
           g.kvStable != 0;
}

inline bool K2UsefulTpsTargetMet(const K2UsefulTpsGate& g) {
    // Sole gate: WALL_NS <= TOKENS × TOKEN_BUDGET_NS.
    if (g.generatedTokens && g.capacityNsToken) {
        const GenerationBudget b{g.generatedTokens,
                                 g.capacityNsToken * g.generatedTokens,
                                 g.capacityTargetNsToken
                                     ? g.capacityTargetNsToken
                                     : kTokenBudgetNs5Tps};
        // capacityNsToken is already ns/token (worst window); compare directly.
        return CapacityNsMeetsFloor(g.capacityNsToken, b.budgetNsPerToken);
    }
    if (g.capacityNsToken != 0)
        return CapacityNsMeetsFloor(g.capacityNsToken, g.capacityTargetNsToken);
    return g.maxStableStreamingCapacityTps >= g.usefulFloor;
}

inline bool K2UsefulTpsProductSeal(const K2UsefulTpsGate& g) {
    return K2UsefulTpsPass(g) && K2UsefulTpsTargetMet(g) &&
           g.benchmarkCertPass != 0 && g.enduranceCertifiable != 0 &&
           g.fullStabilityWindows >= 4 && g.generatedTokens >= 2048ull &&
           g.certEvidencePath[0] != '\0';
}

inline void K2UsefulTpsWriteEvidence(FILE* f, const K2UsefulTpsGate& g,
                                     const char* result) {
    if (!f) return;
    std::fprintf(f, "K2_USEFUL_TPS_001=%s\n", result);
    std::fprintf(f, "WALL_CLOCK_UNIT=NS\n");
    std::fprintf(f, "RATE_GATE_SOURCE=GENERATION_WALL_NS\n");
    std::fprintf(f, "TIMING_PRIMITIVE=NS_PER_TOKEN\n");
    std::fprintf(f, "AUTHORITY=GENERATION_WALL_NS<=TOKENS*TOKEN_BUDGET_NS\n");
    std::fprintf(f, "SOURCE=BENCHMARK_CERT\n");
    std::fprintf(f, "TPS_DERIVED_ONLY=1\n");
    std::fprintf(f, "TOKEN_PLUS_ONE=0\n");
    std::fprintf(f, "TPS_DISPLAY_SCALE=1\n");
    std::fprintf(f, "CAPACITY_NS_TOKEN=%llu\n",
                 (unsigned long long)g.capacityNsToken);
    std::fprintf(f, "TOKEN_BUDGET_NS=%llu\n",
                 (unsigned long long)g.capacityTargetNsToken);
    std::fprintf(f, "WALL_WITHIN_BUDGET=%d\n",
                 K2UsefulTpsTargetMet(g) ? 1 : 0);
    std::fprintf(f, "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS=%.6f\n",
                 g.maxStableStreamingCapacityTps);
    std::fprintf(f, "USEFUL_FLOOR=%.3f\n", g.usefulFloor);
    std::fprintf(f, "PERFORMANCE_TARGET_MET=%d\n",
                 K2UsefulTpsTargetMet(g) ? 1 : 0);
    std::fprintf(f, "EXECUTION_VALID=%d\n", K2UsefulTpsPass(g) ? 1 : 0);
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
