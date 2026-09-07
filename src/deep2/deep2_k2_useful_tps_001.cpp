// deep2_k2_useful_tps_001.cpp — K2_USEFUL_TPS_001
// Product seal only via MAXIMUM_STABLE_STREAMING_CAPACITY_TPS + certify provenance.
#include "K2UsefulTpsGate.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static int EnvInt(const char* k, int defV) {
    const char* e = std::getenv(k);
    if (!e || !e[0]) return defV;
    return std::atoi(e);
}

int main() {
    printf("K2_USEFUL_TPS_001\n");
    printf("AUTHORITY=MAXIMUM_STABLE_STREAMING_CAPACITY_TPS\n");
    printf("INTERNAL_DECODE_COUNTER_USED=0\n");

    const char* capEnv = std::getenv("MAXIMUM_STABLE_STREAMING_CAPACITY_TPS");
    if (!capEnv || !capEnv[0]) {
        printf("SOURCE=MISSING_CERT_CAPACITY\n");
        printf("NOTE=run scripts/Run-U13-FromCertify.ps1 after Deep2Benchmark certify\n");
        printf("K2_USEFUL_TPS_001=FAIL\n");
        return 1;
    }

    K2UsefulTpsGate g{};
    g.usefulFloor = 5.0;
    g.maxStableStreamingCapacityTps = atof(capEnv);
    g.productionDecodePath = EnvInt("PRODUCTION_DECODE_PATH", 0);
    g.decodeStable = EnvInt("DECODE_STABLE", 0);
    g.vramStable = EnvInt("VRAM_STABLE", 0);
    g.kvStable = EnvInt("KV_STABLE", 0);
    g.enduranceCertifiable = EnvInt("ENDURANCE_CERTIFIABLE", 0);
    g.fullStabilityWindows = EnvInt("FULL_STABILITY_WINDOWS", 0);
    {
        const char* gt = std::getenv("GENERATED_TOKENS");
#ifdef _WIN32
        g.generatedTokens = gt ? (uint64_t)_strtoui64(gt, nullptr, 10) : 0ull;
#else
        g.generatedTokens = gt ? strtoull(gt, nullptr, 10) : 0ull;
#endif
    }
    {
        const char* br = std::getenv("BENCHMARK_CERT_RESULT");
        g.benchmarkCertPass = (br && std::strcmp(br, "PASS") == 0) ? 1 : 0;
    }
    {
        const char* mc = std::getenv("MODEL_CLASS");
        std::snprintf(g.modelClass, sizeof(g.modelClass), "%s",
                      mc && mc[0] ? mc : "K2");
    }
    {
        const char* ce = std::getenv("CERT_EVIDENCE");
        if (ce)
            std::snprintf(g.certEvidencePath, sizeof(g.certEvidencePath), "%s",
                          ce);
    }

    const bool product = K2UsefulTpsProductSeal(g);
    g.useful = product ? 1 : 0;
    K2UsefulTpsWriteEvidence(stdout, g, product ? "PASS" : "FAIL");
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001", nullptr);
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\GATE_STATUS.txt", "w");
    if (f) {
        K2UsefulTpsWriteEvidence(f, g, product ? "PASS" : "FAIL");
        fclose(f);
    }
#endif
    return product ? 0 : 1;
}
