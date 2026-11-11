// GPU_CODE31_RESET_001 — enumerate + PnP health/reset witnesses (no model load)
#include "deep2/Deep2DeviceManager.hpp"
#include <cstdio>
#include <cstdint>
#include <climits>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

extern "C" unsigned Deep2Device_ScoreAdapter(unsigned long long dedicated,
                                             unsigned long long shared,
                                             unsigned flags) {
    unsigned long long score = dedicated * 2u + shared;
    if (flags & 1u) score += dedicated / 4u;
    if (score > UINT_MAX) score = UINT_MAX;
    return static_cast<unsigned>(score);
}

extern "C" int Deep2Device_PickBestIndex(const unsigned* scores,
                                         const unsigned long long* vram,
                                         unsigned count,
                                         unsigned minScore) {
    (void)vram;
    if (!scores || count == 0) return -1;
    int bestIdx = -1;
    unsigned bestScore = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (scores[i] >= minScore && scores[i] > bestScore) {
            bestScore = scores[i];
            bestIdx = static_cast<int>(i);
        }
    }
    return bestIdx;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
#endif
    Deep2::DeviceManagerSnapshot snap{};
    const bool enumOk = Deep2::Deep2Device_Enumerate(snap);
    const bool policyOk = Deep2::Deep2Device_ApplyPolicy(snap);
    Deep2::Deep2Device_EmitWitnesses(nullptr, snap);

    unsigned unhealthy = 0, resetAttempted = 0, resetOk = 0, saw31 = 0, recovered31 = 0;
    for (unsigned i = 0; i < snap.deviceCount; ++i) {
        const Deep2::DeviceIdentity& d = snap.devices[i];
        if (!d.healthy) ++unhealthy;
        if (d.problemCode == 31) ++saw31;
        if (d.resetAttempted) ++resetAttempted;
        if (d.resetOk) ++resetOk;
        if (d.resetAttempted && d.problemCode == 0) ++recovered31;
    }

    std::printf("GPU_CODE31_RESET_001\n");
    std::printf("ENUM_OK=%d POLICY_OK=%d DETECTED=%u OPENED=%u\n",
                (int)enumOk, (int)policyOk, snap.plan.detected, snap.plan.opened);
    unsigned resetSkipped = 0, resetNeedsElevation = 0;
    for (unsigned i = 0; i < snap.deviceCount; ++i) {
        const Deep2::DeviceIdentity& d = snap.devices[i];
        if (d.resetSkipped) ++resetSkipped;
        if (d.resetRequiresElevation) ++resetNeedsElevation;
    }
    std::printf("UNHEALTHY=%u RESET_ATTEMPTED=%u RESET_OK=%u RESET_SKIPPED=%u "
                "RESET_REQUIRES_ELEVATION=%u PROBLEM_31=%u RECOVERED_31=%u\n",
                unhealthy, resetAttempted, resetOk, resetSkipped,
                resetNeedsElevation, saw31, recovered31);
    std::printf("PLAN_REASON=%s PRIMARY=%s\n",
                snap.plan.reason,
                snap.plan.primaryIndex >= 0 ? snap.plan.primaryName : "(none)");
    std::printf("PROMOTE=0\n");
    const bool recognize = enumOk && snap.deviceCount > 0;
    std::printf("RECOGNIZE=%s\n", recognize ? "PASS" : "FAIL");
    const char* resetDisposition =
        recovered31 ? "RESET_CLEARED_31"
        : (resetAttempted
           ? (resetOk ? "RESET_OK_BUT_CODE_REMAINS" : "RESET_ATTEMPTED_FAILED")
           : (saw31 ? (resetNeedsElevation ? "RESET_BLOCKED_REQUIRES_ELEVATION"
                            : "RESET_SKIPPED_OPT_IN_REQUIRED")
                    : "NO_CODE31_AT_REFRESH"));
    std::printf("RESET_DISPOSITION=%s\n", resetDisposition);
    std::fflush(stdout);
    return recognize ? 0 : 1;
}
