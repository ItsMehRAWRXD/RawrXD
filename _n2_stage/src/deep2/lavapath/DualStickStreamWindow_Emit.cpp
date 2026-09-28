// DualStickStreamWindow_Emit.cpp ? diagnostics + receipts; no external deps.
#include "DualStickStreamWindow.hpp"
#include <cstdio>

namespace Deep2 {

void EmitDualStickWindowReceipt(FILE* f, const DualStickWindowPlan& p) {
    if (!f) return;
    std::fprintf(f, "--- DualStick Window Receipt ---\n");
    std::fprintf(f, "totalBudgetBytes=%llu\n", (unsigned long long)p.totalBudgetBytes);
    std::fprintf(f, "stickCount=%u\n", p.stickCount);
    std::fprintf(f, "stick0Name=%s\n", p.stick0Name);
    std::fprintf(f, "stick0Bytes=%llu\n", (unsigned long long)p.stick0Bytes);
    std::fprintf(f, "stick1Name=%s\n", p.stick1Name);
    std::fprintf(f, "stick1Bytes=%llu\n", (unsigned long long)p.stick1Bytes);
    std::fprintf(f, "noTruncateNeedle=%d\n", p.noTruncateNeedle);
}

void EmitDualStickMechanics(FILE* f) {
    if (!f) return;
    const DualStickExec& s = DualStickState();
    std::fprintf(f, "--- DualStick Mechanics ---\n");
    std::fprintf(f, "requested=%d planned=%d armed=%d\n", s.requested, s.planned, s.armed);
    std::fprintf(f, "armCount=%llu armAcquires=%llu\n", (unsigned long long)s.armCount, (unsigned long long)s.armAcquires);
    std::fprintf(f, "armConsumers=%llu armOwnershipAdvances=%llu\n", (unsigned long long)s.armConsumers, (unsigned long long)s.armOwnershipAdvances);
    std::fprintf(f, "armBytesWorked=%llu\n", (unsigned long long)s.armBytesWorked);
    std::fprintf(f, "forwardCallsGpu0=%llu forwardCallsGpu1=%llu\n", (unsigned long long)s.forwardCallsGpu0, (unsigned long long)s.forwardCallsGpu1);
    std::fprintf(f, "runtimeDevices=%llu runtimeBytesWorked=%llu\n", (unsigned long long)s.runtimeDevices, (unsigned long long)s.runtimeBytesWorked);
}

void EmitDualStickEnvAuthority(FILE* f) {
    if (!f) return;
    const DualStickExec& s = DualStickState();
    std::fprintf(f, "--- DualStick Env Authority ---\n");
    std::fprintf(f, "requested=%d planned=%d armed=%d\n", s.requested, s.planned, s.armed);
}

} // namespace Deep2

