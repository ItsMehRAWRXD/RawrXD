// deep2_nu_gpu_gemv_cert.cpp — NU_GPU_GEMV_001
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

static double Rmse(const float* a, const float* b, size_t n) {
    double s = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = (double)a[i] - (double)b[i];
        s += d * d;
    }
    return std::sqrt(s / (double)(n ? n : 1));
}

static bool Arm(CPUInference::VulkanCompute& vc, NUFormatTag tag,
                uint32_t rows, uint32_t cols, double maxRmse,
                const char* name, bool& okOut) {
    std::vector<float> W((size_t)rows * cols), x(cols), yGpu(rows), yCpu(rows);
    FillW(W, rows, cols);
    FillX(x);
    NUFusedPacker packer;
    NUPackerConfig cfg;
    if (!packer.initialize(cfg)) { okOut = false; return false; }
    auto nu = packer.packTensor(W.data(), W.size(), tag);
    uint32_t elems = 0, fmt = 0;
    const bool valid = NU_ValidateStream(nu.data(), nu.size(), &elems, &fmt);
    NU_GemvStatsReset();
    const bool cpuOk =
        NU_GemvCpu(nu.data(), nu.size(), x.data(), yCpu.data(), rows, cols);
    NU_GemvStatsReset();
    const bool gpuOk =
        NU_GemvGpu(vc, nu.data(), nu.size(), x.data(), yGpu.data(), rows, cols,
                   0x4E554701ull ^ (uint64_t)tag);
    const auto& st = NU_GemvStatsGet();
    const double err = (cpuOk && gpuOk) ? Rmse(yGpu.data(), yCpu.data(), rows) : 1e9;
    printf("%s valid=%d elems=%u fmt=%u nuBytes=%zu cpu=%d gpu=%d ops=%llu "
           "rmse=%.6f\n",
           name, valid ? 1 : 0, elems, fmt, nu.size(), cpuOk ? 1 : 0,
           gpuOk ? 1 : 0, (unsigned long long)st.ops, err);
    okOut = valid && cpuOk && gpuOk && st.ops >= 1 && st.nuBytes == nu.size() &&
            elems == (uint32_t)W.size() && err <= maxRmse;
    return okOut;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "CACHE");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\NU_GPU_GEMV_001", nullptr);
#endif
    printf("NU_GPU_GEMV_001\n");
    CPUInference::VulkanCompute vc;
    if (!vc.Initialize()) {
        printf("NU_GPU_GEMV_001=FAIL vulkan_init\n");
#ifdef _WIN32
        _exit(2);
#else
        return 2;
#endif
    }
    const uint32_t rows = 64, cols = 64;
    bool q40 = false, q80 = false, f16 = false;
    Arm(vc, NUFormatTag::NU_Q4_0, rows, cols, 1e-3, "Q4_0", q40);
    Arm(vc, NUFormatTag::NU_Q8_0, rows, cols, 1e-3, "Q8_0", q80);
    Arm(vc, NUFormatTag::NU_F16, rows, cols, 1e-3, "F16", f16);

    // Bad magic must not dispatch
    std::vector<float> W((size_t)rows * cols), x(cols), y(rows);
    FillW(W, rows, cols);
    FillX(x);
    NUFusedPacker packer;
    NUPackerConfig cfg;
    packer.initialize(cfg);
    auto bad = packer.packTensor(W.data(), W.size(), NUFormatTag::NU_Q4_0);
    reinterpret_cast<NUStreamHeader*>(bad.data())->magic = 0xBAD00BAD;
    NU_GemvStatsReset();
    const bool rejected =
        !NU_GemvGpu(vc, bad.data(), bad.size(), x.data(), y.data(), rows, cols);
    const bool failCounted = NU_GemvStatsGet().fail >= 1;

    const bool pass = q40 && q80 && f16 && rejected && failCounted;
    printf("BAD_MAGIC_REJECT=%d FAIL_COUNTED=%d\n", rejected ? 1 : 0,
           failCounted ? 1 : 0);
    NU_GemvStatsEmit(stdout);
    printf("NU_GPU_GEMV_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f =
        fopen("G:\\~dev\\rawrxd\\evidence\\NU_GPU_GEMV_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "Q4_0=%d Q8_0=%d F16=%d BAD_MAGIC=%d\n", q40, q80, f16,
                rejected && failCounted);
        fprintf(f, "NU_GPU_GEMV_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    vc.Cleanup();
#ifdef _WIN32
    _exit(pass ? 0 : 2);
#else
    return pass ? 0 : 2;
#endif
}
