// deep2_k2_gpu_mla_nu_bridge_cert.cpp — K2_GPU_MLA_NU_BRIDGE_001
#include "NUFusedPacker.hpp"
#include "NUGemv.hpp"
#include "NULiveConsumer.hpp"
#include "vulkan_compute.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_LIVE_NU", "1");
    _putenv_s("DEEP2_LIVE_NU_AUTH", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_NU_BRIDGE_001",
                     nullptr);
#endif
    printf("K2_GPU_MLA_NU_BRIDGE_001\n");
    CPUInference::VulkanCompute vc;
    if (!vc.Initialize()) {
        printf("K2_GPU_MLA_NU_BRIDGE_001=SKIP\n");
        return 0;
    }
    const uint32_t rows = 64, cols = 256;
    std::vector<float> W((size_t)rows * cols), x(cols), yF(rows), yNu(rows);
    for (uint32_t i = 0; i < rows * cols; ++i)
        W[i] = 0.02f * (float)((int)(i % 7) - 3);
    for (uint32_t i = 0; i < cols; ++i)
        x[i] = 0.01f * (float)((i % 17) + 1);
    NU_GemvF32Cpu(W.data(), x.data(), yF.data(), rows, cols);

    NUFusedPacker packer;
    NUPackerConfig cfg{};
    if (!packer.initialize(cfg)) {
        printf("K2_GPU_MLA_NU_BRIDGE_001=FAIL packer\n");
        return 2;
    }
    auto nu = packer.packTensor(W.data(), W.size(), NUFormatTag::NU_Q4_K);
    NU_LiveStatsReset();
    const bool consumed =
        NU_LiveConsumeGemv(vc, nu.data(), nu.size(), x.data(), yNu.data(), rows,
                           cols, 0x4D4C4131ull);
    const auto& st = NU_LiveStatsGet();
    double maxAbs = 0, ss = 0;
    for (uint32_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)yF[r] - (double)yNu[r]);
        if (d > maxAbs) maxAbs = d;
        ss += d * d;
    }
    const double rms = std::sqrt(ss / (double)rows);
    const bool pass = consumed && st.ops >= 1 && maxAbs < 2.0 && rms < 0.5;
    printf("CONSUMED=%d OPS=%llu maxAbs=%.4g rms=%.4g\n", consumed ? 1 : 0,
           (unsigned long long)st.ops, maxAbs, rms);
    printf("K2_GPU_MLA_NU_BRIDGE_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_NU_BRIDGE_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "ops=%llu maxAbs=%.6g rms=%.6g\n",
                (unsigned long long)st.ops, maxAbs, rms);
        fprintf(f, "K2_GPU_MLA_NU_BRIDGE_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    return pass ? 0 : 2;
}
