/* DualStickStreamWindow.cpp — plan/arm + exec counters (not config-only). */
#include "DualStickStreamWindow.hpp"
#include <cstring>

namespace Deep2 {

DualStickExec& DualStickState() {
    static DualStickExec s;
    return s;
}

DualStickWindowPlan PlanDualStickWindows(const DeviceManagerSnapshot& snap,
                                         uint64_t budgetBytes) {
    DualStickWindowPlan p{};
    p.totalBudgetBytes = budgetBytes ? budgetBytes : (59568ull << 20);
    p.noTruncateNeedle = 1;
    uint64_t vram[2] = {0, 0};
    for (unsigned i = 0; i < snap.plan.openCount && p.stickCount < 2; ++i) {
        int idx = snap.plan.openIndexes[i];
        if (idx < 0 || (unsigned)idx >= snap.deviceCount) continue;
        const DeviceIdentity& d = snap.devices[idx];
        if (d.integrated) continue;
        char* name = (p.stickCount == 0) ? p.stick0Name : p.stick1Name;
        std::snprintf(name, 128, "%s", d.name);
        /* DXGI can under-report; floor discrete sticks at 16/32 GiB class. */
        uint64_t dv = d.dedicatedVram;
        if (dv < (4ull << 30))
            dv = (p.stickCount == 0) ? (32ull << 30) : (16ull << 30);
        vram[p.stickCount] = dv;
        ++p.stickCount;
    }
    if (p.stickCount <= 1) {
        p.stick0Bytes = p.totalBudgetBytes;
        return p;
    }
    const uint64_t sum = vram[0] + vram[1];
    /* Avoid uint64 overflow: (budget * vram0) / sum. */
    p.stick0Bytes = (p.totalBudgetBytes / sum) * vram[0] +
                    ((p.totalBudgetBytes % sum) * vram[0]) / sum;
    p.stick1Bytes = p.totalBudgetBytes - p.stick0Bytes;
    const uint64_t floor1 = p.totalBudgetBytes / 4;
    if (p.stick1Bytes < floor1) {
        p.stick1Bytes = floor1;
        p.stick0Bytes = p.totalBudgetBytes - floor1;
    }
    return p;
}

void EmitDualStickWindowReceipt(FILE* f, const DualStickWindowPlan& p) {
    if (!f) f = stderr;
    if (p.stickCount >= 1) DualStickState().planned = 1;
    std::fprintf(f,
        "DUAL_STICK_STREAM=1\nSTREAM_BUDGET_BYTES=%llu\nSTICK_COUNT=%u\n"
        "STICK0_WINDOW_BYTES=%llu\nSTICK1_WINDOW_BYTES=%llu\n"
        "STICK0_NAME=%s\nSTICK1_NAME=%s\nNO_TRUNCATE_NEEDLE=%d\n"
        "WINDOW_ON_FILL=MINT_NEXT_STICK\nPHYSICAL_PAGE_POOL_GROWS=0\n"
        "DUALSTICK_PLANNED=%d\n",
        (unsigned long long)p.totalBudgetBytes, p.stickCount,
        (unsigned long long)p.stick0Bytes, (unsigned long long)p.stick1Bytes,
        p.stick0Name[0] ? p.stick0Name : "-",
        p.stick1Name[0] ? p.stick1Name : "-", p.noTruncateNeedle,
        DualStickState().planned);
}

void ArmDualStickNoTruncate(const DualStickWindowPlan& p) {
    SetEnv("DEEP2_NO_TRUNCATE_NEEDLE", "1");
    SetEnv("DEEP2_GPU_DEVICE_CLASS", "DISCRETE");
    SetEnv("DEEP2_GPU_POLICY", "MULTI");
    SetEnv("DEEP2_GPU_SELECT", "");
    SetEnv("RAWRXD_GPU_SELECT", "");
    SetEnv("RAWRXD_GPU_NAME", "");
    if (p.stick0Bytes) {
        char b0[32];
        std::snprintf(b0, sizeof(b0), "%llu",
                      (unsigned long long)(p.stick0Bytes >> 20));
        SetEnv("DEEP2_STICK0_BUDGET_MIB", b0);
    }
    if (p.stick1Bytes) {
        char b1[32];
        std::snprintf(b1, sizeof(b1), "%llu",
                      (unsigned long long)(p.stick1Bytes >> 20));
        SetEnv("DEEP2_STICK1_BUDGET_MIB", b1);
    }
    DualStickState().armed = 1;
    /* Arm path only — does not claim DUALSTICK_RUNTIME_USED. */
    DualStickArmWarmup(0, 0);
    if (p.stickCount > 1) DualStickArmWarmup(1, 0);
}

} // namespace Deep2
