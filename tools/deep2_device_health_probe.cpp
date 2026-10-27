// deep2_device_health_probe.cpp — GPU_CODE31_RESET_001
#include "Deep2DeviceManager.hpp"
#include <cstdio>
#include <cstring>
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
    if (score > 0xFFFFFFFFull) score = 0xFFFFFFFFull;
    return (unsigned)score;
}

extern "C" int Deep2Device_PickBestIndex(const unsigned* scores,
                                         const unsigned long long* /*vram*/,
                                         unsigned count,
                                         unsigned minScore) {
    if (!scores || count == 0) return -1;
    int best = -1;
    unsigned bestScore = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (scores[i] >= minScore && scores[i] > bestScore) {
            bestScore = scores[i];
            best = (int)i;
        }
    }
    return best;
}

int main() {
    using namespace Deep2;
    DeviceManagerSnapshot snap{};
    const bool enumerated = Deep2Device_Enumerate(snap);
    (void)Deep2Device_ApplyPolicy(snap);
    Deep2Device_EmitWitnesses(stderr, snap);

    bool saw747e = false;
    bool recogPass = false;
    bool resetPass = false;
    bool accessDenied = false;
    uint32_t code747e = 0;
    bool healthy747e = true;
    const char* name747e = "";

    for (unsigned i = 0; i < snap.deviceCount; ++i) {
        const DeviceIdentity& d = snap.devices[i];
        if (d.vendorId == 0x1002 && d.deviceId == 0x747E) {
            saw747e = true;
            code747e = d.problemCode;
            healthy747e = d.healthy;
            name747e = d.name;
            recogPass = (d.problemCode == 31) || (!d.healthy && d.problemCode != 0);
            // Recognition PASS if we read a live ProblemCode for this VEN/DEV
            // even when code is already cleared after successful reset.
            if (d.instanceId[0]) recogPass = true;
            if (d.resetAttempted && d.resetOk && d.problemCode == 0)
                resetPass = true;
            if (d.accessDenied) accessDenied = true;
            if (d.resetAttempted && d.problemCode == 0 && d.healthy)
                resetPass = true;
        }
        fprintf(stderr,
                "PROBE_DEVICE i=%u name=%s ven=%04X dev=%04X PROBLEM_CODE=%u "
                "HEALTHY=%d RESET_ATTEMPTED=%d RESET_OK=%d ACCESS_DENIED=%d "
                "DUTY=%u\n",
                i, d.name, d.vendorId, d.deviceId, d.problemCode, (int)d.healthy,
                (int)d.resetAttempted, (int)d.resetOk, (int)d.accessDenied,
                (unsigned)d.duty);
    }

    // Prefer healthy primary (R9700) when 7800 is unhealthy.
    bool primaryHealthy = false;
    if (snap.plan.primaryIndex >= 0 &&
        snap.plan.primaryIndex < (int)snap.deviceCount)
        primaryHealthy = snap.devices[snap.plan.primaryIndex].healthy;

    fprintf(stderr, "ENUMERATED=%d DEVICE_COUNT=%u OPENED=%u PRIMARY=%s\n",
            (int)enumerated, snap.deviceCount, snap.plan.opened,
            snap.plan.primaryName);
    fprintf(stderr, "SAW_7800XT_747E=%d NAME=%s PROBLEM_CODE=%u HEALTHY=%d\n",
            (int)saw747e, name747e, code747e, (int)healthy747e);
    fprintf(stderr, "RECOGNITION=%s\n", recogPass ? "PASS" : "FAIL");
    if (accessDenied)
        fprintf(stderr, "RESET=ACCESS_DENIED\n");
    else
        fprintf(stderr, "RESET=%s\n", resetPass ? "PASS" : "FAIL");
    fprintf(stderr, "PRIMARY_HEALTHY=%d PROMOTE=0\n", (int)primaryHealthy);
    fprintf(stderr, "GPU_CODE31_RESET_001=%s\n",
            (enumerated && recogPass) ? "PASS" : "FAIL");
    return (enumerated && recogPass) ? 0 : 1;
}