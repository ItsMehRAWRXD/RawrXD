#include "../src/deep2/K2UsefulTpsGate.hpp"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
// Consumes MAXIMUM_STABLE_STREAMING_CAPACITY_TPS — never recomputes wall TPS.
// argv: capacity floor prod decode vram kv [endurance windows generated certPass model]
int main(int argc, char** argv) {
    Deep2::K2UsefulTpsGate g{};
    g.maxStableStreamingCapacityTps = (argc > 1) ? atof(argv[1]) : 0.0;
    g.usefulFloor = (argc > 2) ? atof(argv[2]) : 5.0;
    g.productionDecodePath = (argc > 3) ? atoi(argv[3]) : 1;
    g.decodeStable = (argc > 4) ? atoi(argv[4]) : 1;
    g.vramStable = (argc > 5) ? atoi(argv[5]) : 1;
    g.kvStable = (argc > 6) ? atoi(argv[6]) : 1;
    g.enduranceCertifiable = (argc > 7) ? atoi(argv[7]) : 0;
    g.fullStabilityWindows = (argc > 8) ? atoi(argv[8]) : 0;
#ifdef _WIN32
    g.generatedTokens =
        (argc > 9) ? (uint64_t)_strtoui64(argv[9], nullptr, 10) : 0ull;
#else
    g.generatedTokens = (argc > 9) ? strtoull(argv[9], nullptr, 10) : 0ull;
#endif
    g.benchmarkCertPass = (argc > 10) ? atoi(argv[10]) : 0;
    std::snprintf(g.modelClass, sizeof(g.modelClass), "%s",
                  (argc > 11) ? argv[11] : "K2");
#ifdef _WIN32
    {
        const char* ce = std::getenv("CERT_EVIDENCE");
        if (ce && ce[0])
            std::snprintf(g.certEvidencePath, sizeof(g.certEvidencePath), "%s", ce);
    }
#endif

    const bool product = Deep2::K2UsefulTpsProductSeal(g);
    g.useful = product ? 1 : 0;

    Deep2::K2UsefulTpsWriteEvidence(stdout, g, product ? "PASS" : "FAIL");
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001", nullptr);
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\GATE_STATUS.txt", "w");
    if (f) {
        Deep2::K2UsefulTpsWriteEvidence(f, g, product ? "PASS" : "FAIL");
        fclose(f);
    }
#endif
    return product ? 0 : 1;
}
