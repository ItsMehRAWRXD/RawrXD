// deep2_nu_perf_cert.cpp — NU_PERF_001
#include "NUGemv.hpp"
#include "NUFusedPacker.hpp"
#include "vulkan_compute.h"
#include <chrono>
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
using Clock = std::chrono::steady_clock;

static double Ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "CACHE");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\NU_PERF_001", nullptr);
#endif
    printf("NU_PERF_001\n");
    CPUInference::VulkanCompute vc;
    if (!vc.Initialize()) {
        printf("NU_PERF_001=FAIL vulkan_init\n");
#ifdef _WIN32
        _exit(2);
#else
        return 2;
#endif
    }
    const uint32_t rows = 256, cols = 256;
    const int iters = 32;
    std::vector<float> W((size_t)rows * cols), x(cols), y(rows), y2(rows);
    for (size_t i = 0; i < W.size(); ++i)
        W[i] = 0.01f * (float)((i * 7) % 100);
    for (uint32_t c = 0; c < cols; ++c)
        x[c] = 0.01f * (float)((c % 13) + 1);

    NUFusedPacker packer;
    NUPackerConfig cfg;
    packer.initialize(cfg);
    auto tPack0 = Clock::now();
    auto nu = packer.packTensor(W.data(), W.size(), NUFormatTag::NU_Q4_0);
    auto tPack1 = Clock::now();
    const double packMs = Ms(tPack0, tPack1);
    const double f32Bytes = (double)W.size() * 4.0;
    const double ratio = (double)nu.size() / f32Bytes;

    auto tF0 = Clock::now();
    for (int i = 0; i < iters; ++i)
        NU_GemvF32Cpu(W.data(), x.data(), y.data(), rows, cols);
    auto tF1 = Clock::now();
    const double f32Ms = Ms(tF0, tF1) / (double)iters;

    NU_GemvStatsReset();
    auto tC0 = Clock::now();
    bool cpuOk = true;
    for (int i = 0; i < iters; ++i)
        cpuOk = NU_GemvCpu(nu.data(), nu.size(), x.data(), y2.data(), rows, cols) &&
                cpuOk;
    auto tC1 = Clock::now();
    const double nuCpuMs = Ms(tC0, tC1) / (double)iters;

    NU_GemvStatsReset();
    auto tG0 = Clock::now();
    bool gpuOk = true;
    for (int i = 0; i < iters; ++i)
        gpuOk = NU_GemvGpu(vc, nu.data(), nu.size(), x.data(), y2.data(), rows,
                           cols, 0x4E555001ull) &&
                gpuOk;
    auto tG1 = Clock::now();
    const double nuGpuMs = Ms(tG0, tG1) / (double)iters;

    // Pass: compression + all paths complete + finite timings
    const bool lean = ratio < 0.55;
    const bool timed = packMs >= 0 && f32Ms > 0 && nuCpuMs > 0 && nuGpuMs > 0;
    const bool pass = lean && cpuOk && gpuOk && timed && nu.size() > 0;

    printf("ROWS=%u COLS=%u ITERS=%d\n", rows, cols, iters);
    printf("NU_BYTES=%zu F32_BYTES=%.0f RATIO=%.3f\n", nu.size(), f32Bytes, ratio);
    printf("PACK_MS=%.3f F32_GEMV_MS=%.3f NU_CPU_MS=%.3f NU_GPU_MS=%.3f\n",
           packMs, f32Ms, nuCpuMs, nuGpuMs);
    printf("CPU_OK=%d GPU_OK=%d\n", cpuOk ? 1 : 0, gpuOk ? 1 : 0);
    printf("NU_PERF_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f =
        fopen("G:\\~dev\\rawrxd\\evidence\\NU_PERF_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "RATIO=%.3f PACK_MS=%.3f F32_MS=%.3f NU_CPU_MS=%.3f NU_GPU_MS=%.3f\n",
                ratio, packMs, f32Ms, nuCpuMs, nuGpuMs);
        fprintf(f, "NU_PERF_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    vc.Cleanup();
#ifdef _WIN32
    _exit(pass ? 0 : 2);
#else
    return pass ? 0 : 2;
#endif
}
