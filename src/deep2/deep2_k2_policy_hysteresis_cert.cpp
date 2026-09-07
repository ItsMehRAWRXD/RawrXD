// deep2_k2_policy_hysteresis_cert.cpp — K2_POLICY_HYSTERESIS_001
#include "K2LivePolicy.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

static uint32_t CountFlipsRaw(const uint32_t (*pts)[2], int n) {
    K2LivePolicy_ClearSticky();
    K2LivePolicyMode prev = K2LivePolicyMode::Off;
    bool have = false;
    uint32_t flips = 0;
    for (int i = 0; i < n; ++i) {
        auto d = K2LivePolicy_DecideRaw(pts[i][0], pts[i][1]);
        if (have && d.mode != prev) ++flips;
        prev = d.mode; have = true;
    }
    return flips;
}

static uint32_t CountFlipsSticky(const uint32_t (*pts)[2], int n) {
    K2LivePolicy_ClearSticky();
    K2LivePolicyMode prev = K2LivePolicyMode::Off;
    bool have = false;
    uint32_t flips = 0;
    for (int i = 0; i < n; ++i) {
        auto d = K2LivePolicy_Decide(pts[i][0], pts[i][1]);
        if (have && d.mode != prev) ++flips;
        prev = d.mode; have = true;
    }
    return flips;
}

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_POLICY_HYSTERESIS_001", nullptr);
    _putenv_s("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    _putenv_s("DEEP2_LIVE_HYSTERESIS_HOLD", "4");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
#endif
    printf("K2_POLICY_HYSTERESIS_001\n");
    printf("CROSSOVER=8 HOLD=%u\n", K2LivePolicy_HysteresisHold());
    // Oscillate around crossover: reuse 7/10/7/10/6/12 (depth=1 × tokens)
    static const uint32_t osc[][2] = {
        {1, 7}, {1, 10}, {1, 7}, {1, 10}, {1, 6}, {1, 12}, {1, 7}, {1, 12},
    };
    const int n = (int)(sizeof(osc) / sizeof(osc[0]));
    const uint32_t rawFlips = CountFlipsRaw(osc, n);
    const uint32_t stickyFlips = CountFlipsSticky(osc, n);
    printf("OSC_RAW_FLIPS=%u OSC_STICKY_FLIPS=%u\n", rawFlips, stickyFlips);

    // Full-depth lane must stay trampoline under veto (no layer promotion thrash).
    K2LivePolicy_ClearSticky();
    auto a = K2LivePolicy_Decide(61, 2);
    auto b = K2LivePolicy_Decide(61, 4);
    auto c = K2LivePolicy_Decide(4, 2);
    printf("D61x2 mode=%u arm=%s veto=%u\n", (unsigned)a.mode, a.arm, a.layerVeto);
    printf("D61x4 mode=%u arm=%s\n", (unsigned)b.mode, b.arm);
    printf("D4x2 mode=%u reason=%s\n", (unsigned)c.mode, c.reason);

    const bool damp = stickyFlips < rawFlips && stickyFlips <= 2;
    const bool fullStable =
        a.mode == K2LivePolicyMode::TrampolineOutput &&
        b.mode == K2LivePolicyMode::TrampolineOutput &&
        a.layerVeto == 1 && b.layerVeto == 1 &&
        a.arm && std::strcmp(a.arm, "FULL_DEPTH_PROMO") == 0;
    // After sticky trampoline at 61, a brief shallow probe must not immediately
    // drop to Off without crossing exit band (hold).
    K2LivePolicy_ClearSticky();
    (void)K2LivePolicy_Decide(61, 2); // commit trampoline
    auto shallow = K2LivePolicy_Decide(1, 7); // raw OFF, but inside exit band
    const bool holdOn = shallow.mode == K2LivePolicyMode::TrampolineOutput &&
                        std::strcmp(shallow.reason, "hysteresis_hold_on") == 0;

    const bool pass = damp && fullStable && holdOn && rawFlips >= 3;
    printf("DAMP=%d FULL_STABLE=%d HOLD_ON=%d\n", damp, fullStable, holdOn);
    printf("K2_POLICY_HYSTERESIS_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_POLICY_HYSTERESIS_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "OSC_RAW_FLIPS=%u OSC_STICKY_FLIPS=%u\n", rawFlips, stickyFlips);
        fprintf(f, "HOLD_ON=%d FULL_STABLE=%d\n", holdOn ? 1 : 0, fullStable ? 1 : 0);
        fprintf(f, "K2_POLICY_HYSTERESIS_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    return pass ? 0 : 2;
}
