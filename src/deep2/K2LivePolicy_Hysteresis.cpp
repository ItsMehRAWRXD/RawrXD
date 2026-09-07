// K2LivePolicy_Hysteresis.cpp — sticky Decide wrapper
#include "K2LivePolicy.hpp"
#include <cstdlib>
#include <cstring>

namespace Deep2 {
namespace {
K2LivePolicyMode g_sticky = K2LivePolicyMode::Off;
const char* g_stickyArm = "OFF";
bool g_stickyOk = false;
} // namespace

void K2LivePolicy_ClearSticky() { g_stickyOk = false; }
void K2LivePolicy_SetSticky(K2LivePolicyMode m) {
    g_sticky = m; g_stickyOk = true;
    if (m == K2LivePolicyMode::Off) g_stickyArm = "OFF";
    else if (m == K2LivePolicyMode::Min) g_stickyArm = "MIN";
    else if (m == K2LivePolicyMode::LayerCycloneElastic)
        g_stickyArm = "CYCLONE_ELASTIC";
    else g_stickyArm = "TRAMPOLINE_OUTPUT_CACHE";
}
void K2LivePolicy_SetStickyArm(K2LivePolicyMode m, const char* arm) {
    g_sticky = m; g_stickyOk = true;
    g_stickyArm = arm ? arm : "OFF";
}

uint32_t K2LivePolicy_HysteresisHold() {
    if (const char* e = std::getenv("DEEP2_LIVE_HYSTERESIS_HOLD")) {
        long v = std::atol(e); if (v >= 0) return (uint32_t)v;
    }
    return 4;
}

K2LivePolicyDecision K2LivePolicy_Decide(uint32_t layerDepth, uint32_t tokens) {
    K2LivePolicyDecision d = K2LivePolicy_DecideRaw(layerDepth, tokens);
    const uint32_t hold = K2LivePolicy_HysteresisHold();
    if (!g_stickyOk || hold == 0) {
        g_sticky = d.mode; g_stickyArm = d.arm; g_stickyOk = true;
        return d;
    }
    const uint64_t enterUp = d.crossoverSteps + hold;
    const uint64_t exitDown = (d.crossoverSteps > hold) ? (d.crossoverSteps - hold) : 0;
    if (g_sticky == K2LivePolicyMode::Off && d.mode != K2LivePolicyMode::Off) {
        if (d.reuseSteps < enterUp) {
            d.mode = K2LivePolicyMode::Off; d.arm = "OFF";
            d.reason = "hysteresis_hold_off";
            return d;
        }
    } else if (g_sticky != K2LivePolicyMode::Off && d.mode == K2LivePolicyMode::Off) {
        if (d.reuseSteps > exitDown) {
            d.mode = g_sticky;
            d.arm = g_stickyArm;
            d.reason = "hysteresis_hold_on";
            return d;
        }
    } else if (g_sticky == K2LivePolicyMode::TrampolineOutput &&
               d.mode == K2LivePolicyMode::LayerCycloneElastic) {
        d.mode = K2LivePolicyMode::TrampolineOutput;
        d.arm = g_stickyArm;
        d.reason = "hysteresis_hold_trampoline";
        return d;
    }
    g_sticky = d.mode;
    g_stickyArm = d.arm;
    return d;
}

} // namespace Deep2
