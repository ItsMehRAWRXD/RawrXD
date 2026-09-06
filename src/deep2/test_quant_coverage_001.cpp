/*
 * QUANT-COVERAGE-001 / P0 — ABI + geometry cert
 *
 * Proves:
 *   - Canonical ggml type IDs (static_assert + runtime)
 *   - Q8_K blockBytes == 292 (not 29)
 *   - IQ1_S == 50, IQ4_NL == 18/32
 *   - Unknown types fail-closed (LookupQuantType == nullptr)
 *   - Loader TensorInfo geometry matches table
 *   - Registry GetBlockGeometryForType matches table
 *
 * Does NOT claim full modern kernel coverage (P2: IQ1_M/BF16/MXFP4/...).
 */
#include "QuantTypeTable.hpp"
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define MKDIR(p) mkdir(p, 0755)
#endif

using namespace Deep2;

static int g_fail = 0;

#define CHECK(cond, ...)                         \
    do {                                         \
        if (!(cond)) {                           \
            std::printf("FAIL: ");               \
            std::printf(__VA_ARGS__);            \
            std::printf("\n");                   \
            ++g_fail;                            \
        } else {                                 \
            std::printf("PASS: ");               \
            std::printf(__VA_ARGS__);            \
            std::printf("\n");                   \
        }                                        \
    } while (0)

int main() {
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\QUANT_COVERAGE_001)";
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    char reportPath[1024];
    std::snprintf(reportPath, sizeof(reportPath), "%s\\REPORT.txt", outDir);
    FILE* rep = std::fopen(reportPath, "w");
    if (!rep) rep = stdout;

    auto emit = [&](const char* fmt, auto... args) {
        std::fprintf(rep, fmt, args...);
        std::printf(fmt, args...);
    };

    emit("QUANT-COVERAGE-001 P0 ABI+geometry\n");
    emit("GGML_TYPE_COUNT=%u\n", (unsigned)GGMLType::GGML_TYPE_COUNT);

    // --- Canonical IDs ---
    CHECK((uint32_t)GGMLType::GGML_TYPE_Q8_1 == 9, "Q8_1 id=9 (was wrongly Q8_K)");
    CHECK((uint32_t)GGMLType::GGML_TYPE_Q8_K == 15, "Q8_K id=15");
    CHECK((uint32_t)GGMLType::GGML_TYPE_IQ2_XXS == 16, "IQ2_XXS id=16");
    CHECK((uint32_t)GGMLType::GGML_TYPE_IQ1_S == 19, "IQ1_S id=19");
    CHECK((uint32_t)GGMLType::GGML_TYPE_IQ4_NL == 20, "IQ4_NL id=20");
    CHECK((uint32_t)GGMLType::GGML_TYPE_I8 == 24, "I8 id=24");
    CHECK((uint32_t)GGMLType::GGML_TYPE_IQ1_M == 29, "IQ1_M id=29");
    CHECK((uint32_t)GGMLType::GGML_TYPE_BF16 == 30, "BF16 id=30");
    CHECK((uint32_t)GGMLType::GGML_TYPE_MXFP4 == 39, "MXFP4 id=39");
    CHECK((uint32_t)GGMLType::GGML_TYPE_NVFP4 == 40, "NVFP4 id=40");
    CHECK((uint32_t)GGMLType::GGML_TYPE_COUNT == 43, "COUNT=43");

    // --- Critical geometry ---
    CHECK(sizeof(block_q8_K) == 292, "sizeof(block_q8_K)=292");
    CHECK(QuantTypeBlockBytes(15) == 292, "table Q8_K bytes=292");
    CHECK(QuantTypeBlockBytes(19) == 50, "table IQ1_S bytes=50");
    CHECK(QuantTypeBlockElements(19) == 256, "table IQ1_S elems=256");
    CHECK(QuantTypeBlockBytes(20) == 18, "table IQ4_NL bytes=18");
    CHECK(QuantTypeBlockElements(20) == 32, "table IQ4_NL elems=32");
    CHECK(sizeof(block_iq4_nl) == 18, "sizeof(block_iq4_nl)=18");
    CHECK(sizeof(block_iq1_s) == 50, "sizeof(block_iq1_s)=50");

    // --- Fail-closed ---
    CHECK(LookupQuantType(4) == nullptr, "removed Q4_2 fail-closed");
    CHECK(LookupQuantType(31) == nullptr, "removed Q4_0_4_4 fail-closed");
    CHECK(LookupQuantType(999) == nullptr, "out-of-range fail-closed");
    CHECK(LookupQuantType(12) != nullptr, "Q4_K known");

    // --- Loader TensorInfo uses table ---
    TensorInfo ti;
    ti.type = GGMLType::GGML_TYPE_Q8_K;
    CHECK(ti.GetBlockSize() == 292, "TensorInfo Q8_K GetBlockSize=292");
    ti.type = GGMLType::GGML_TYPE_IQ4_NL;
    CHECK(ti.GetBlockSize() == 18 && ti.GetElemsPerBlock() == 32,
          "TensorInfo IQ4_NL 18/32");
    ti.type = (GGMLType)4; // removed
    CHECK(ti.GetBlockSize() == 0 && ti.GetElemsPerBlock() == 0,
          "TensorInfo unknown → 0/0 fail-closed");

    // --- Registry geometry matches table ---
    QuantKernelRegistry::Instance().Initialize();
    auto g8k = QuantKernelRegistry::Instance().GetGeometry(15);
    CHECK(g8k.blockSize == 292 && g8k.elemsPerBlock == 256,
          "registry Q8_K geometry 292/256");
    auto gNl = GetBlockGeometryForType(20);
    CHECK(gNl.blockSize == 18 && gNl.elemsPerBlock == 32,
          "GetBlockGeometryForType IQ4_NL 18/32");

    // --- Coverage inventory ---
    const auto stats = ComputeQuantCoverageStats();
    emit("\nCOVERAGE known=%d persisted=%d kernel_ready=%d missing_kernels=%d\n",
         stats.knownTypes, stats.persistedTypes, stats.kernelReady, stats.missingKernels);

    emit("\n--- persisted types ---\n");
    emit("%-10s %4s %6s %6s %7s %8s\n", "name", "id", "elems", "bytes", "kernel", "status");
    for (uint32_t i = 0; i < (uint32_t)GGMLType::GGML_TYPE_COUNT; ++i) {
        const auto& d = QuantTypeTable()[i];
        if (!d.persistedGGUF || d.blockElements == 0) continue;
        emit("%-10s %4u %6u %6u %7s %8s\n", d.name, d.ggmlId, d.blockElements, d.blockBytes,
             d.kernelReady ? "YES" : "NO", d.kernelReady ? "READY" : "P2_GAP");
    }

    // Existing 21 kernel-ready set should still be marked ready
    const uint32_t readyExpect[] = {
        0, 1, 2, 3, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};
    int readyOk = 0;
    for (uint32_t id : readyExpect) {
        const auto* d = LookupQuantType(id);
        if (d && d->kernelReady) ++readyOk;
        else {
            emit("FAIL: expected kernelReady id=%u\n", id);
            ++g_fail;
        }
    }
    CHECK(readyOk == 21, "legacy 21 kernelReady flags intact (%d/21)", readyOk);

    // P2 gaps must be present as known geometry but not kernelReady
    const uint32_t p2[] = {9, 29, 30, 34, 35, 39, 40, 41, 42};
    int p2ok = 0;
    for (uint32_t id : p2) {
        const auto* d = LookupQuantType(id);
        if (d && !d->kernelReady) ++p2ok;
        else {
            emit("FAIL: P2 gap id=%u should be known geometry, kernelReady=false\n", id);
            ++g_fail;
        }
    }
    CHECK(p2ok == 9, "P2 modern gaps reserved (%d/9)", p2ok);

    emit("\nVERDICT fails=%d\n", g_fail);
    emit("NEXT: P1 cert 21 dequant/GEMV vs scalar; P2 implement IQ1_M/BF16/MXFP4/NVFP4/...\n");

    // GATE.txt
    {
        char gatePath[1024];
        std::snprintf(gatePath, sizeof(gatePath), "%s\\GATE.txt", outDir);
        FILE* g = std::fopen(gatePath, "w");
        if (g) {
            std::fprintf(g,
                "QUANT-COVERAGE-001\n"
                "phase=P0_ABI_GEOMETRY\n"
                "verdict=%s\n"
                "fails=%d\n"
                "Q8_K_bytes=292\n"
                "IQ4_NL=18/32\n"
                "IQ1_S=50/256\n"
                "COUNT=43\n"
                "kernel_ready=%d\n"
                "missing_kernels=%d\n"
                "fail_closed=YES\n"
                "single_table=QuantTypeTable.hpp\n"
                "DO_NOT_CLAIM=all_quants_until_P2_kernels\n",
                g_fail == 0 ? "PASS" : "FAIL", g_fail, stats.kernelReady, stats.missingKernels);
            std::fclose(g);
        }
    }

    if (rep != stdout) {
        std::fclose(rep);
        std::printf("wrote %s\n", reportPath);
    }
    return g_fail == 0 ? 0 : 1;
}
