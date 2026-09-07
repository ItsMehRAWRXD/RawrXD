// K2LivePolicy.cpp — estimates + DecideRaw + switches + ApplyMode
#include "K2LivePolicy.hpp"
#include "Deep2LivePath.hpp"
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdlib.h>
#endif

namespace Deep2 {
namespace {
uint64_t g_cross = 8;
uint32_t g_switches = 0;
K2LivePolicyMode g_last = K2LivePolicyMode::Off;
bool g_haveLast = false;
} // namespace

void K2LivePolicy_SetSticky(K2LivePolicyMode m); // Hysteresis.cpp
void K2LivePolicy_SetStickyArm(K2LivePolicyMode m, const char* arm);

uint64_t K2LivePolicy_CrossoverSteps() {
    if (const char* e = std::getenv("DEEP2_LIVE_CROSSOVER_STEPS")) {
        long v = std::atol(e); if (v > 0) return (uint64_t)v;
    }
    return g_cross;
}
void K2LivePolicy_SetCrossoverSteps(uint64_t steps) { if (steps) g_cross = steps; }
uint64_t K2LivePolicy_ReuseSteps(uint32_t d, uint32_t t) {
    return (uint64_t)d * (uint64_t)t;
}
uint32_t K2LivePolicy_SwitchCount() { return g_switches; }
void K2LivePolicy_ResetSwitches() { g_switches = 0; g_haveLast = false; }
void K2LivePolicy_NoteSwitch(K2LivePolicyMode m) {
    if (g_haveLast && g_last != m) ++g_switches;
    else if (!g_haveLast) g_switches = 1;
    g_last = m; g_haveLast = true;
}

uint64_t K2LivePolicy_CacheBudgetBytes() {
    if (const char* e = std::getenv("DEEP2_LIVE_CACHE_BUDGET_MIB")) {
        long v = std::atol(e); if (v > 0) return (uint64_t)v << 20;
    }
    return 3072ull << 20;
}
uint64_t K2LivePolicy_EstimateOutputBytes() {
    if (const char* e = std::getenv("DEEP2_LIVE_OUTPUT_WEIGHT_BYTES")) {
        long long v = std::atoll(e); if (v > 0) return (uint64_t)v;
    }
    return 963379200ull;
}
uint64_t K2LivePolicy_EstimateLayerBytes(uint32_t layers) {
    return (uint64_t)layers * 55300000ull;
}

K2LivePolicyDecision K2LivePolicy_DecideRaw(uint32_t layerDepth, uint32_t tokens) {
    K2LivePolicyDecision d{};
    d.layerCount = layerDepth; d.tokens = tokens;
    d.reuseSteps = K2LivePolicy_ReuseSteps(layerDepth, tokens);
    d.crossoverSteps = K2LivePolicy_CrossoverSteps();
    d.cacheBudget = K2LivePolicy_CacheBudgetBytes();
    d.predictedOutputBytes = K2LivePolicy_EstimateOutputBytes();
    d.predictedLayerBytes = K2LivePolicy_EstimateLayerBytes(layerDepth);
    const uint64_t usable = (d.cacheBudget > d.predictedOutputBytes)
        ? (d.cacheBudget - d.predictedOutputBytes) : 0;
    d.budgetFit = (d.predictedLayerBytes > 0 && d.predictedLayerBytes <= usable) ? 1u : 0u;
    d.layerVeto = d.budgetFit ? 0u : 1u;
    const char* allow = std::getenv("DEEP2_LIVE_ALLOW_LAYER_CACHE");
    const bool allowLayer = allow && allow[0] == '1';
    if (d.reuseSteps == 0 || d.reuseSteps < d.crossoverSteps) {
        d.mode = K2LivePolicyMode::Off; d.arm = "OFF";
        d.reason = (d.reuseSteps == 0) ? "no_work" : "reuse_below_crossover";
    } else if (allowLayer && d.budgetFit) {
        d.mode = K2LivePolicyMode::LayerCycloneElastic;
        d.arm = "CYCLONE_ELASTIC"; d.reason = "layer_ws_fits_and_allowed";
    } else {
        // TRAMPOLINE_PROMOTION_001 + FUSED_REBENCH_001 (UNFREEZE_C002)
        d.mode = K2LivePolicyMode::TrampolineOutput;
        d.arm = d.layerVeto ? "FULL_DEPTH_PROMO" : "TRAMPOLINE_OUTPUT_CACHE";
        d.reason = d.layerVeto ? "promo_trampoline_reuse_layer_veto"
                               : "default_trampoline";
    }
    return d;
}

void K2LivePolicy_ApplyMode(K2LivePolicyMode mode) {
    K2LivePolicy_ApplyMode(mode, /*fullDepthPromo=*/false);
}

void K2LivePolicy_ApplyMode(K2LivePolicyMode mode, bool fullDepthPromo) {
#ifdef _WIN32
    auto put = [](const char* k, const char* v) {
        SetEnvironmentVariableA(k, v);
        _putenv_s(k, v);
    };
#else
    auto put = [](const char* k, const char* v) { setenv(k, v, 1); };
#endif
    if (mode == K2LivePolicyMode::Off) {
        LivePath_SetEnhancementsEnabled(false);
        LivePath_SetFusedEnabled(false);
        put("DEEP2_LIVE_PATH", "0"); put("DEEP2_LIVE_MECH", "none");
        put("DEEP2_LIVE_FUSED", "0");
    } else if (mode == K2LivePolicyMode::Min) {
        LivePath_SetEnhancementsEnabled(false);
        LivePath_SetFusedEnabled(false);
        put("DEEP2_LIVE_PATH", "1"); put("DEEP2_LIVE_MECH", "none");
        put("DEEP2_LIVE_FUSED", "0");
    } else if (mode == K2LivePolicyMode::TrampolineOutput) {
        LivePath_SetEnhancementsEnabled(true);
        put("DEEP2_LIVE_PATH", "1");
        if (fullDepthPromo) {
            // FULL_DEPTH_PROMO + UNFREEZE_C002
            LivePath_SetFusedEnabled(true);
            put("DEEP2_LIVE_MECH", "trampoline,cyclone,elastic");
            put("DEEP2_LIVE_FUSED", "1");
        } else {
            // short/shallow trampoline+cache
            LivePath_SetFusedEnabled(false);
            put("DEEP2_LIVE_MECH", "trampoline");
            put("DEEP2_LIVE_FUSED", "0");
        }
    } else {
        LivePath_SetEnhancementsEnabled(true);
        LivePath_SetFusedEnabled(false);
        put("DEEP2_LIVE_PATH", "1"); put("DEEP2_LIVE_MECH", "cyclone,elastic");
        put("DEEP2_LIVE_FUSED", "0");
    }
    LivePath_ApplyMechEnv();
    // Prefer arm from last Decide when ApplyMode follows Apply; fallback by promo.
    const char* arm = "OFF";
    if (mode == K2LivePolicyMode::Min) arm = "MIN";
    else if (mode == K2LivePolicyMode::LayerCycloneElastic) arm = "CYCLONE_ELASTIC";
    else if (mode == K2LivePolicyMode::TrampolineOutput)
        arm = fullDepthPromo ? "FULL_DEPTH_PROMO" : "TRAMPOLINE_OUTPUT_CACHE";
    K2LivePolicy_SetStickyArm(mode, arm);
}

} // namespace Deep2
