// deep2_k2_live_policy_split_cert.cpp — K2_LIVE_POLICY_SPLIT_001
// No model: Decide+Apply shallow vs full-depth wiring
#include "Deep2LivePath.hpp"
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

static void EnvAuto() {
#ifdef _WIN32
    _putenv_s("DEEP2_LIVE_POLICY", "AUTO");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
    _putenv_s("DEEP2_LIVE_CROSSOVER_STEPS", "8");
#endif
}

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_LIVE_POLICY_SPLIT_001", nullptr);
#endif
    EnvAuto();
    printf("K2_LIVE_POLICY_SPLIT_001\n");

    K2LivePolicy_ClearSticky();
    auto off = K2LivePolicy_Apply(1, 4);
    const bool offOk = off.mode == K2LivePolicyMode::Off &&
                       !LivePath_EnhancementsEnabled();

    K2LivePolicy_ClearSticky();
    auto sh = K2LivePolicy_Apply(4, 2);
    const bool shOk =
        sh.mode == K2LivePolicyMode::TrampolineOutput && sh.layerVeto == 0 &&
        sh.arm && std::strcmp(sh.arm, "TRAMPOLINE_OUTPUT_CACHE") == 0 &&
        LivePath_MechOn(LP_MECH_TRAMPOLINE) &&
        !LivePath_MechOn(LP_MECH_CYCLONE) && !LivePath_MechOn(LP_MECH_ELASTIC) &&
        !LivePath_FusedEnabled();

    K2LivePolicy_ClearSticky();
    auto full = K2LivePolicy_Apply(61, 2);
    const bool fullOk =
        full.mode == K2LivePolicyMode::TrampolineOutput && full.layerVeto == 1 &&
        full.arm && std::strcmp(full.arm, "FULL_DEPTH_PROMO") == 0 &&
        LivePath_MechOn(LP_MECH_TRAMPOLINE) &&
        LivePath_MechOn(LP_MECH_CYCLONE) && LivePath_MechOn(LP_MECH_ELASTIC) &&
        LivePath_FusedEnabled();

    printf("OFF mode=%u\n", (unsigned)off.mode);
    printf("SHALLOW arm=%s veto=%u ok=%d\n", sh.arm, sh.layerVeto, shOk ? 1 : 0);
    printf("FULL arm=%s veto=%u ok=%d\n", full.arm, full.layerVeto, fullOk ? 1 : 0);

    const bool pass = offOk && shOk && fullOk;
    printf("OFF_OK=%d SHALLOW_OK=%d FULL_OK=%d\n",
           offOk ? 1 : 0, shOk ? 1 : 0, fullOk ? 1 : 0);
    printf("K2_LIVE_POLICY_SPLIT_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_LIVE_POLICY_SPLIT_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "SHALLOW_ARM=%s FULL_ARM=%s\n", sh.arm, full.arm);
        fprintf(f, "K2_LIVE_POLICY_SPLIT_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    return pass ? 0 : 2;
}
