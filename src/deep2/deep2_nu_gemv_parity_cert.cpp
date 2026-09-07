// deep2_nu_gemv_parity_cert.cpp — NU_GEMV_PARITY_001
#include "NUGemv.hpp"
#include "NUFusedPacker.hpp"
#include "vulkan_compute.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

struct Bound { double maxAbs; double rms; };

static void FillW(std::vector<float>& W, uint32_t rows, uint32_t cols) {
    for (uint32_t r = 0; r < rows; ++r)
        for (uint32_t c = 0; c < cols; ++c)
            W[(size_t)r * cols + c] =
                std::sin(0.013f * (float)(r * cols + c)) * 0.5f +
                0.02f * (float)((int)(c % 5) - 2);
}

static void FillX(std::vector<float>& x) {
    for (size_t i = 0; i < x.size(); ++i)
        x[i] = 0.01f * (float)((i % 17) + 1);
}

static void Stats(const float* a, const float* b, size_t n, double& mx, double& rms) {
    double s = 0, m = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = std::fabs((double)a[i] - (double)b[i]);
        if (d > m) m = d;
        s += d * d;
    }
    mx = m;
    rms = n ? std::sqrt(s / (double)n) : 0;
}

static bool Arm(CPUInference::VulkanCompute& vc, NUFormatTag tag, Bound b,
                uint32_t rows, uint32_t cols, const char* name, bool& okOut) {
    std::vector<float> W((size_t)rows * cols), x(cols);
    std::vector<float> yF32(rows), yNuCpu(rows), yNuGpu(rows), Wdec(rows * cols);
    FillW(W, rows, cols);
    FillX(x);
    NU_GemvF32Cpu(W.data(), x.data(), yF32.data(), rows, cols);

    NUFusedPacker packer;
    NUPackerConfig cfg;
    if (!packer.initialize(cfg)) { okOut = false; return false; }
    auto nu = packer.packTensor(W.data(), W.size(), tag);
    uint32_t elems = 0, fmt = 0;
    const bool valid = NU_ValidateStream(nu.data(), nu.size(), &elems, &fmt);
    const size_t got =
        packer.unpackTensor(nu.data(), nu.size(), Wdec.data(), Wdec.size());
    double wMx = 0, wRms = 0;
    Stats(W.data(), Wdec.data(), W.size(), wMx, wRms);

    NU_GemvStatsReset();
    const bool cpuOk =
        NU_GemvCpu(nu.data(), nu.size(), x.data(), yNuCpu.data(), rows, cols);
    NU_GemvStatsReset();
    const bool gpuOk =
        NU_GemvGpu(vc, nu.data(), nu.size(), x.data(), yNuGpu.data(), rows, cols,
                   0x4E555001ull ^ (uint64_t)tag);

    double cMx = 0, cRms = 0, gMx = 0, gRms = 0, cgMx = 0, cgRms = 0;
    Stats(yF32.data(), yNuCpu.data(), rows, cMx, cRms);
    Stats(yF32.data(), yNuGpu.data(), rows, gMx, gRms);
    Stats(yNuCpu.data(), yNuGpu.data(), rows, cgMx, cgRms);

    const bool cpuPar = cpuOk && cMx <= b.maxAbs && cRms <= b.rms;
    const bool gpuPar = gpuOk && gMx <= b.maxAbs && gRms <= b.rms;
    const bool gpuCpu = cgMx <= 1e-4 && cgRms <= 1e-5;
    printf("%s valid=%d fmt=%u wMax=%.4g wRms=%.4g "
           "cpuMax=%.4g cpuRms=%.4g gpuMax=%.4g gpuRms=%.4g cgMax=%.4g %s\n",
           name, valid ? 1 : 0, fmt, wMx, wRms, cMx, cRms, gMx, gRms, cgMx,
           (cpuPar && gpuPar && gpuCpu) ? "OK" : "BAD");
    okOut = valid && got == W.size() && cpuPar && gpuPar && gpuCpu &&
            elems == (uint32_t)W.size();
    return okOut;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "CACHE");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\NU_GEMV_PARITY_001", nullptr);
#endif
    printf("NU_GEMV_PARITY_001\n");
    CPUInference::VulkanCompute vc;
    if (!vc.Initialize()) {
        printf("NU_GEMV_PARITY_001=FAIL vulkan_init\n");
#ifdef _WIN32
        _exit(2);
#else
        return 2;
#endif
    }
    const uint32_t rows = 64, cols = 64;
    // Output bounds vs original F32 GEMV (quantization-aware).
    bool q80 = false, q40 = false, q4k = false, f16 = false;
    Arm(vc, NUFormatTag::NU_Q8_0, {0.05, 0.02}, rows, cols, "Q8_0", q80);
    Arm(vc, NUFormatTag::NU_Q4_0, {0.35, 0.12}, rows, cols, "Q4_0", q40);
    Arm(vc, NUFormatTag::NU_Q4_K, {0.25, 0.08}, rows, cols, "Q4_K", q4k);
    Arm(vc, NUFormatTag::NU_F16, {0.002, 0.001}, rows, cols, "F16", f16);

    const bool pass = q80 && q40 && q4k && f16;
    // Parity closed ⇒ live NU consume may be wired by next gate.
    const int auth = pass ? 1 : 0;
    printf("LIVE_NU_CONSUME_AUTHORIZED=%d\n", auth);
    printf("Q8_0=%d Q4_0=%d Q4_K=%d F16=%d\n", q80, q40, q4k, f16);
    printf("NU_GEMV_PARITY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f =
        fopen("G:\\~dev\\rawrxd\\evidence\\NU_GEMV_PARITY_001\\GATE_STATUS.txt",
              "w");
    if (f) {
        fprintf(f, "Q8_0=%d Q4_0=%d Q4_K=%d F16=%d\n", q80, q40, q4k, f16);
        fprintf(f, "LIVE_NU_CONSUME_AUTHORIZED=%d\n", auth);
        fprintf(f, "NU_GEMV_PARITY_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    vc.Cleanup();
#ifdef _WIN32
    _exit(pass ? 0 : 2);
#else
    return pass ? 0 : 2;
#endif
}
