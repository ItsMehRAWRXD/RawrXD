// DualStickStreamWindow.cpp — state + plan + arm; no external deps.
#include "DualStickStreamWindow.hpp"
#include <cstring>
#include <cstdio>

namespace Deep2 {

static DualStickExec g_dualStickState;

DualStickExec& DualStickState() {
    return g_dualStickState;
}

DualStickWindowPlan PlanDualStickWindows(const DeviceManagerSnapshot& snap,
                                         uint64_t budgetBytes) {
    DualStickWindowPlan plan{};
    plan.totalBudgetBytes = budgetBytes;
    if (snap.deviceCount == 0) {
        plan.stickCount = 0;
        return plan;
    }
    if (snap.deviceCount >= 1) {
        plan.stick0Bytes = snap.device0FreeBytes > budgetBytes ? budgetBytes / 2 : snap.device0FreeBytes;
        std::snprintf(plan.stick0Name, sizeof(plan.stick0Name), "%s", snap.device0Name);
        plan.stickCount = 1;
    }
    if (snap.deviceCount >= 2) {
        plan.stick1Bytes = snap.device1FreeBytes > budgetBytes ? budgetBytes / 2 : snap.device1FreeBytes;
        std::snprintf(plan.stick1Name, sizeof(plan.stick1Name), "%s", snap.device1Name);
        plan.stickCount = 2;
    }
    g_dualStickState.planned = 1;
    return plan;
}

void ArmDualStickNoTruncate(const DualStickWindowPlan& p) {
    (void)p;
    g_dualStickState.armed = 1;
    g_dualStickState.armCount++;
}

void DualStickArmWarmup(unsigned stick, uint32_t layer) {
    (void)stick;
    (void)layer;
    g_dualStickState.armCount++;
}

} // namespace Deep2

