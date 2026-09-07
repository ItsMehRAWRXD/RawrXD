// K2LivePolicy_Apply.cpp — env overrides + emit + last snapshot
#include "K2LivePolicy.hpp"
#include "Deep2LivePath.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <string.h>
#endif

namespace Deep2 {
namespace {
K2LivePolicyDecision g_last{};
}

#ifdef _WIN32
static bool Eq(const char* a, const char* b) { return a && b && _stricmp(a, b) == 0; }
#else
static bool Eq(const char* a, const char* b) { return a && b && strcasecmp(a, b) == 0; }
#endif

K2LivePolicyDecision K2LivePolicy_Last() { return g_last; }

K2LivePolicyDecision K2LivePolicy_Apply(uint32_t layerDepth, uint32_t tokens) {
    K2LivePolicy_ResetSwitches();
    K2LivePolicyDecision d = K2LivePolicy_Decide(layerDepth, tokens);
    const char* pol = std::getenv("DEEP2_LIVE_POLICY");
    // Production default: unset/empty POLICY → AUTO (manual arms are cert-only).
    const bool defaultAuto = !pol || !pol[0];
    if (defaultAuto) pol = "AUTO";
    if (Eq(pol, "MANUAL")) {
        d.manualOverride = 1; d.autoSelected = 0; d.reason = "manual_arm";
        // MANUAL must still arm LIVE_PATH/MECH from ambient cert pins.
        // Leaving ApplyMode skipped lets poison LIVE_PATH=0 kill trampoline
        // (OwnsOutput=0 → wrong logits path / crash before PERF).
        const char* live = std::getenv("DEEP2_LIVE_PATH");
        const char* mech = std::getenv("DEEP2_LIVE_MECH");
        const bool liveOff =
            live && ((live[0] == '0' && live[1] == 0) ||
                     Eq(live, "off") || Eq(live, "false") || Eq(live, "no"));
        const bool wantTramp =
            mech && (std::strstr(mech, "trampoline") || std::strstr(mech, "TRAMPOLINE"));
        if (!liveOff && wantTramp) {
            d.mode = K2LivePolicyMode::TrampolineOutput;
            d.arm = "TRAMPOLINE_OUTPUT_CACHE";
            K2LivePolicy_ApplyMode(d.mode, /*fullDepthPromo=*/false);
        } else if (!liveOff && mech && mech[0] && !Eq(mech, "none")) {
            // Keep Decide mode; re-apply so LIVE_PATH stays on.
            K2LivePolicy_ApplyMode(d.mode, d.layerVeto != 0);
        } else if (!liveOff) {
            d.mode = K2LivePolicyMode::TrampolineOutput;
            d.arm = "TRAMPOLINE_OUTPUT_CACHE";
            K2LivePolicy_ApplyMode(d.mode, /*fullDepthPromo=*/false);
        }
        K2LivePolicy_SetStickyArm(d.mode, d.arm);
        K2LivePolicy_NoteSwitch(d.mode);
        d.switches = K2LivePolicy_SwitchCount();
        if (d.switches == 0) d.switches = 1;
        g_last = d;
        return d;
    }
    d.autoSelected = Eq(pol, "AUTO") ? 1u : 0u;
    d.manualOverride = d.autoSelected ? 0u : 1u;
    if (defaultAuto && Eq(pol, "AUTO"))
        d.reason = "default_auto";
    if (Eq(pol, "OFF") || Eq(pol, "0")) {
        d.mode = K2LivePolicyMode::Off; d.arm = "OFF"; d.reason = "force_off";
    } else if (Eq(pol, "MIN")) {
        d.mode = K2LivePolicyMode::Min; d.arm = "MIN"; d.reason = "force_min";
    } else if (Eq(pol, "TRAMPOLINE") || Eq(pol, "B2") || Eq(pol, "OUTPUT")) {
        // Explicit B2: trampoline-only (no cyclone), for A/B witnesses.
        d.mode = K2LivePolicyMode::TrampolineOutput;
        d.arm = "TRAMPOLINE_OUTPUT_CACHE"; d.reason = "force_trampoline";
#ifdef _WIN32
        _putenv_s("DEEP2_LIVE_PATH", "1");
        _putenv_s("DEEP2_LIVE_MECH", "trampoline");
        _putenv_s("DEEP2_LIVE_FUSED", "0");
#else
        setenv("DEEP2_LIVE_PATH", "1", 1);
        setenv("DEEP2_LIVE_MECH", "trampoline", 1);
        setenv("DEEP2_LIVE_FUSED", "0", 1);
#endif
        LivePath_SetEnhancementsEnabled(true);
        LivePath_SetFusedEnabled(false);
        LivePath_ApplyMechEnv();
        K2LivePolicy_SetStickyArm(d.mode, d.arm);
        K2LivePolicy_NoteSwitch(d.mode);
        d.switches = K2LivePolicy_SwitchCount();
        if (d.switches == 0) d.switches = 1;
        g_last = d;
        return d;
    } else if (Eq(pol, "PROMO") || Eq(pol, "FULL") || Eq(pol, "PROMOTED")) {
        d.mode = K2LivePolicyMode::TrampolineOutput;
        d.arm = "FULL_DEPTH_PROMO"; d.reason = "force_promo";
        d.layerVeto = 1;
    } else if (Eq(pol, "LAYER") || Eq(pol, "CYCLONE") || Eq(pol, "CACHE") ||
               Eq(pol, "ON") || Eq(pol, "1")) {
        if (d.budgetFit) {
            d.mode = K2LivePolicyMode::LayerCycloneElastic;
            d.arm = "CYCLONE_ELASTIC"; d.reason = "force_layer_fit";
        } else {
            d.mode = K2LivePolicyMode::TrampolineOutput;
            d.arm = "FULL_DEPTH_PROMO";
            d.reason = "force_layer_veto_to_promo";
            d.layerVeto = 1;
        }
    } else if (Eq(pol, "AUTO")) {
        d.autoSelected = 1; d.manualOverride = 0;
    }
    const bool promo =
        (d.arm && std::strcmp(d.arm, "FULL_DEPTH_PROMO") == 0) ||
        (d.mode == K2LivePolicyMode::TrampolineOutput && d.layerVeto);
    K2LivePolicy_ApplyMode(d.mode, promo);
    K2LivePolicy_SetStickyArm(d.mode, d.arm);
    K2LivePolicy_NoteSwitch(d.mode);
    d.switches = K2LivePolicy_SwitchCount();
    if (d.switches == 0) d.switches = 1;
    g_last = d;
    return d;
}

void K2LivePolicy_Emit(FILE* f, const K2LivePolicyDecision& d) {
    if (!f) f = stdout;
    fprintf(f, "AUTO_POLICY_ACTIVE=%u\n", d.autoSelected);
    fprintf(f, "MANUAL_ARM_FORCING=%u\n", d.manualOverride);
    fprintf(f, "K2_LIVE_POLICY_ARM=%s\n", d.arm ? d.arm : "");
    fprintf(f, "K2_LIVE_POLICY_MODE=%u\n", (unsigned)d.mode);
    fprintf(f, "K2_LIVE_POLICY_REASON=%s\n", d.reason ? d.reason : "");
    fprintf(f, "K2_LIVE_POLICY_REUSE_STEPS=%llu\n",
            (unsigned long long)d.reuseSteps);
    fprintf(f, "K2_LIVE_POLICY_CROSSOVER_STEPS=%llu\n",
            (unsigned long long)d.crossoverSteps);
    fprintf(f, "LAYER_COUNT=%u TOKENS=%u\n", d.layerCount, d.tokens);
    fprintf(f, "CACHE_BUDGET=%llu PREDICTED_LAYER=%llu PREDICTED_OUTPUT=%llu\n",
            (unsigned long long)d.cacheBudget,
            (unsigned long long)d.predictedLayerBytes,
            (unsigned long long)d.predictedOutputBytes);
    fprintf(f, "BUDGET_FIT=%u LAYER_VETO=%u\n", d.budgetFit, d.layerVeto);
    fprintf(f, "POLICY_SWITCHES_PER_REQUEST=%u\n", d.switches ? d.switches : 1u);
    {
        const char* live = std::getenv("DEEP2_LIVE_PATH");
        const char* mech = std::getenv("DEEP2_LIVE_MECH");
        fprintf(f, "LIVE_PATH_ENV=%s MECH_ENV=%s WANTED=%u\n",
                live && live[0] ? live : "(unset)",
                mech && mech[0] ? mech : "(unset)",
                LivePath_Wanted() ? 1u : 0u);
    }
    fflush(f);
}

} // namespace Deep2
