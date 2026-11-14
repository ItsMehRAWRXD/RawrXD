/* ATTN_V_Q6K_SPV_FIX_OR_DEFAULT_PATH_CERT — host Q6×Q8_K vs gemv_q6k.spv on L0 attn_v.
 * PROMOTE=0 · INVENT_PASS=0 · CROSS_SHA_CREDIT=0 · ≠ Ornith */
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include "vulkan_compute.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using Deep2::GGUFLoader;
using Deep2::QuantKernelRegistry;

static uint32_t f32bits(float v) {
    uint32_t u = 0;
    std::memcpy(&u, &v, 4);
    return u;
}

static int ulpDiff(float a, float b) {
    if (!std::isfinite(a) || !std::isfinite(b)) return -1;
    const int32_t ia = (int32_t)f32bits(a);
    const int32_t ib = (int32_t)f32bits(b);
    const int32_t sa = ia < 0 ? 0x80000000 - ia : ia;
    const int32_t sb = ib < 0 ? 0x80000000 - ib : ib;
    const int64_t d = (int64_t)sa - (int64_t)sb;
    return (int)(d < 0 ? -d : d);
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    SetEnvironmentVariableA("RAWRXD_GPU_POLICY", "SOLO");
    /* Force SPV path inside DispatchGEMVQuant (no host bypass). */
    SetEnvironmentVariableA("RAWRXD_FORCE_VULKAN_QUANT_GEMV", "1");
    SetEnvironmentVariableA("RAWRXD_QUANT_HOST_Q8K_PARITY", "0");
#endif
    const char* model = argc > 1 ? argv[1]
                                 : R"(G:\~dev\rawrxd\models\tinyllama.gguf)";
    const char* outDir = R"(G:\~dev\rawrxd\evidence\ATTN_V_Q6K_SPV_FIX_OR_DEFAULT_PATH_CERT)";
#ifdef _WIN32
    CreateDirectoryA(R"(G:\~dev\rawrxd\evidence)", nullptr);
    CreateDirectoryA(outDir, nullptr);
#endif
    std::printf("ATTN_V_Q6K_SPV_HOST_PARITY\nmodel=%s\n", model);
    fflush(stdout);

    Deep2::GGUFLoadOptions opt;
    opt.mmap = true;
    opt.loadTensors = true;
    opt.verbose = false;
    auto lr = GGUFLoader::Load(model, opt);
    if (!lr.success) {
        std::fprintf(stderr, "GGUF_LOAD_FAIL %s\n", lr.error);
        return 2;
    }
    const auto* tv = lr.GetTensor("blk.0.attn_v.weight");
    if (!tv || !tv->data) {
        std::fprintf(stderr, "MISSING blk.0.attn_v.weight\n");
        return 2;
    }
    const uint32_t cols = tv->dimensions.size() > 0 ? (uint32_t)tv->dimensions[0] : 0;
    const uint32_t rows = tv->dimensions.size() > 1 ? (uint32_t)tv->dimensions[1] : 0;
    std::printf("tensor=blk.0.attn_v.weight type=%d bytes=%llu rows=%u cols=%u\n",
                (int)tv->type, (unsigned long long)tv->size, rows, cols);
    if (!rows || !cols || (cols % 256u) != 0u) {
        std::fprintf(stderr, "BAD_SHAPE\n");
        return 2;
    }

    /* Prefer frozen ATTN_NORM_0 if present; else deterministic synthetic. */
    std::vector<float> x(cols, 0.f);
    const char* frozen =
        R"(G:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V2\deep2_ATTN_NORM_0_pos0_layer0_full_n2048_seq901.bin)";
    FILE* fx = std::fopen(frozen, "rb");
    bool usedFrozen = false;
    if (fx) {
        if (std::fread(x.data(), 4, cols, fx) == cols) usedFrozen = true;
        std::fclose(fx);
    }
    if (!usedFrozen) {
        for (uint32_t i = 0; i < cols; ++i)
            x[i] = 0.01f * (float)((i % 17) + 1);
    }
    std::printf("input=%s\n", usedFrozen ? "ATTN_NORM_0_frozen" : "synthetic");

    auto& reg = QuantKernelRegistry::Instance();
    if (reg.GetRegisteredCount() == 0) reg.Initialize();
    auto hostGemv = reg.GetGEMV(14);
    if (!hostGemv) {
        std::fprintf(stderr, "NO_HOST_Q6_GEMV\n");
        return 2;
    }
    std::vector<float> yHost(rows, 0.f), ySpv(rows, 0.f);
    hostGemv((const uint8_t*)tv->data, x.data(), yHost.data(), rows, cols);

    size_t hostNf = 0;
    double hostN2 = 0.0;
    for (uint32_t i = 0; i < rows; ++i) {
        if (!std::isfinite(yHost[i])) ++hostNf;
        else hostN2 += (double)yHost[i] * (double)yHost[i];
    }
    std::printf("HOST finite=%zu/%u norm=%.6e\n", rows - hostNf, rows,
                hostN2 > 0 ? std::sqrt(hostN2) : 0.0);

    CPUInference::VulkanCompute vc;
    if (!vc.Initialize()) {
        std::fprintf(stderr, "VULKAN_INIT_FAIL\n");
        return 3;
    }
    /* DispatchGEMVQuant under RAWRXD_FORCE_VULKAN_QUANT_GEMV=1 → gemv_q6k.spv */
    if (!vc.DispatchGEMVQuant(14, tv->data, (size_t)tv->size, x.data(),
                              ySpv.data(), rows, cols)) {
        std::fprintf(stderr, "SPV_DISPATCH_FAIL\n");
        return 3;
    }

    size_t spvNf = 0, bothFin = 0;
    double maxAbs = 0.0, ss = 0.0;
    int maxUlp = 0, firstBad = -1, firstNan = -1;
    for (uint32_t i = 0; i < rows; ++i) {
        const float a = yHost[i], b = ySpv[i];
        if (!std::isfinite(b)) {
            ++spvNf;
            if (firstNan < 0) firstNan = (int)i;
            continue;
        }
        if (!std::isfinite(a)) continue;
        ++bothFin;
        const double d = std::fabs((double)a - (double)b);
        ss += d * d;
        if (d > maxAbs) maxAbs = d;
        const int u = ulpDiff(a, b);
        if (u > maxUlp) maxUlp = u;
        if (d > 1e-5 && firstBad < 0) firstBad = (int)i;
    }
    const double rms = bothFin ? std::sqrt(ss / (double)bothFin) : -1.0;
    const char* gate =
        (spvNf == 0 && hostNf == 0 && maxAbs <= 1e-4) ? "PARITY_OK"
        : (spvNf > 0)                                  ? "SPV_NONFINITE"
                                                       : "PARITY_OPEN";
    std::printf("SPV  finite=%zu/%u nonFinite=%zu\n", rows - spvNf, rows, spvNf);
    std::printf("CMP  bothFinite=%zu maxAbs=%.6e maxULP=%d rms=%.6e "
                "firstBad=%d firstNan=%d gate=%s\n",
                bothFin, maxAbs, maxUlp, rms, firstBad, firstNan, gate);
    std::printf("y0 host=%.8g spv=%.8g\n", yHost[0], ySpv[0]);
    std::printf("DISPOSITION_HINT=%s\n",
                spvNf > 0 ? "KEEP_HOST_DEFAULT_HYBRID_NE_SPV_CERT"
                          : (maxAbs <= 1e-4 ? "SPV_PARITY_CANDIDATE"
                                            : "SPV_NUMERIC_OPEN"));
    fflush(stdout);

    const std::string receipt = std::string(outDir) + "\\PARITY_RECEIPT.txt";
    FILE* f = std::fopen(receipt.c_str(), "w");
    if (f) {
        std::fprintf(f,
                     "ATTN_V_Q6K_SPV_HOST_PARITY\n"
                     "PROMOTE=0 CERTIFIED=0 INVENT_PASS=0\n"
                     "TENSOR=blk.0.attn_v.weight\n"
                     "ROWS=%u COLS=%u BYTES=%llu\n"
                     "INPUT=%s\n"
                     "HOST_FINITE=%zu/%u HOST_NORM=%.6e\n"
                     "SPV_FINITE=%zu/%u SPV_NONFINITE=%zu\n"
                     "BOTH_FINITE=%zu MAX_ABS=%.17g MAX_ULP=%d RMS=%.17g\n"
                     "FIRST_BAD=%d FIRST_NAN=%d GATE=%s\n"
                     "Y0_HOST=%.17g Y0_SPV=%.17g\n"
                     "KERNEL=gemv_q6k.spv vs QuantKernelRegistry Q6×Q8_K\n"
                     "ORNITH=NOT_TOUCHED\n",
                     rows, cols, (unsigned long long)tv->size,
                     usedFrozen ? "ATTN_NORM_0_frozen" : "synthetic",
                     rows - hostNf, rows, hostN2 > 0 ? std::sqrt(hostN2) : 0.0,
                     rows - spvNf, rows, spvNf, bothFin, maxAbs, maxUlp, rms,
                     firstBad, firstNan, gate, yHost[0], ySpv[0]);
        std::fclose(f);
    }
    return spvNf > 0 ? 10 : (maxAbs <= 1e-4 ? 0 : 11);
}
