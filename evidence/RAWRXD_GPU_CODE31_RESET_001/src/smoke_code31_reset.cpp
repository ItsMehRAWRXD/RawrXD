// smoke_code31_reset.cpp — fail-closed recognition + live Code 10/31 reset probe
#include "GpuPreflight.hpp"
#include <cstdio>
#include <cstdlib>

static bool IsProductGpu(const GpuHealth& g) {
    return g.friendlyName.find(L"R9700") != std::wstring::npos ||
           g.friendlyName.find(L"7800 XT") != std::wstring::npos;
}

int main() {
    std::fprintf(stderr, "RAWRXD_GPU_CODE31_RESET_001_BEGIN\n");
    const bool r31 = GpuProblemCodeRecoverable(31) && GpuIsCode31(31);
    const bool r10 = GpuProblemCodeRecoverable(10);
    const bool r0 = !GpuProblemCodeRecoverable(0) && !GpuIsCode31(0);
    const bool dx =
        GpuIsDxgiDeviceRemovedHr((long)0x887A0005L) &&
        GpuIsDxgiDeviceRemovedHr((long)0x887A0006L) &&
        GpuIsDxgiDeviceRemovedHr((long)0x887A0007L) &&
        !GpuIsDxgiDeviceRemovedHr(0);
    std::fprintf(stderr,
                 "RECOG_CODE31=%d RECOG_CODE10=%d RECOG_NONE=%d RECOG_DXGI=%d\n",
                 r31 ? 1 : 0, r10 ? 1 : 0, r0 ? 1 : 0, dx ? 1 : 0);

    auto gpus = EnumerateGpuHealth();
    int code31 = 0, code10 = 0, unhealthy = 0, productUnhealthy = 0;
    for (const auto& g : gpus) {
        const bool c31 = GpuIsCode31(g.problem);
        const bool c10 = (g.problem == 10);
        std::fprintf(stderr,
                     "GPU problem=%lu code31=%d code10=%d healthy=%d product=%d name=%ls\n",
                     g.problem, c31 ? 1 : 0, c10 ? 1 : 0, g.healthy ? 1 : 0,
                     IsProductGpu(g) ? 1 : 0, g.friendlyName.c_str());
        if (c31) ++code31;
        if (c10) ++code10;
        if (!g.healthy) ++unhealthy;
        if (IsProductGpu(g) && !g.healthy) ++productUnhealthy;
    }
    std::fprintf(stderr,
                 "LIVE_GPU_COUNT=%zu LIVE_CODE31=%d LIVE_CODE10=%d "
                 "LIVE_UNHEALTHY=%d LIVE_PRODUCT_UNHEALTHY=%d\n",
                 gpus.size(), code31, code10, unhealthy, productUnhealthy);

    int resetAttempt = 0, resetPass = 0;
    for (const auto& g : gpus) {
        if (!IsProductGpu(g) || g.healthy || !g.devInst) continue;
        if (!GpuProblemCodeRecoverable(g.problem)) continue;
        ++resetAttempt;
        if (AttemptGpuDevNodeReset(g.devInst, g.problem)) ++resetPass;
    }
    std::fprintf(stderr, "RESET_ATTEMPT=%d RESET_PASS=%d\n", resetAttempt, resetPass);

    int productUnhealthyAfter = 0;
    if (resetAttempt > 0) {
        gpus = EnumerateGpuHealth();
        for (const auto& g : gpus) {
            if (IsProductGpu(g) && !g.healthy) ++productUnhealthyAfter;
            std::fprintf(stderr,
                         "GPU_AFTER problem=%lu healthy=%d name=%ls\n",
                         g.problem, g.healthy ? 1 : 0, g.friendlyName.c_str());
        }
    } else {
        productUnhealthyAfter = productUnhealthy;
    }

    const bool recogOk = r31 && r10 && r0 && dx;
    const bool productOk = (productUnhealthyAfter == 0);
    const char* disposition = (!recogOk || !productOk) ? "FAIL" : "PASS";

    std::fprintf(stderr,
                 "SOURCE_WIRED=1 RUNTIME_REACHED=1 CODE31_PRESENT=%d CODE10_PRESENT=%d "
                 "RESET_VERIFIED=%d PRODUCT_HEALTHY=%d DISPOSITION=%s PROMOTE=0\n"
                 "RAWRXD_GPU_CODE31_RESET_001_END\n",
                 code31 > 0 ? 1 : 0, code10 > 0 ? 1 : 0,
                 productOk ? 1 : 0, productOk ? 1 : 0, disposition);
    return recogOk && productOk ? 0 : 1;
}
