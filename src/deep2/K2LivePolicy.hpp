// K2LivePolicy.hpp — auto workload policy (trampoline default + budget veto)
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

enum class K2LivePolicyMode : uint32_t {
    Off = 0,
    Min = 1,
    TrampolineOutput = 2,
    LayerCycloneElastic = 3
};

struct K2LivePolicyDecision {
    K2LivePolicyMode mode = K2LivePolicyMode::TrampolineOutput;
    uint64_t reuseSteps = 0;
    uint64_t crossoverSteps = 0;
    uint64_t cacheBudget = 0;
    uint64_t predictedLayerBytes = 0;
    uint64_t predictedOutputBytes = 0;
    uint32_t layerCount = 0;
    uint32_t tokens = 0;
    uint32_t budgetFit = 0;
    uint32_t layerVeto = 0;
    uint32_t autoSelected = 0;
    uint32_t manualOverride = 0;
    uint32_t switches = 0;
    const char* arm = "TRAMPOLINE_OUTPUT_CACHE";
    const char* reason = "";
};

uint64_t K2LivePolicy_CrossoverSteps();
void K2LivePolicy_SetCrossoverSteps(uint64_t steps);
uint64_t K2LivePolicy_ReuseSteps(uint32_t layerDepth, uint32_t tokens);
uint64_t K2LivePolicy_CacheBudgetBytes();
uint64_t K2LivePolicy_EstimateLayerBytes(uint32_t layers);
uint64_t K2LivePolicy_EstimateOutputBytes();
K2LivePolicyDecision K2LivePolicy_Decide(uint32_t layerDepth, uint32_t tokens);
// Raw decision without sticky hysteresis (for diagnostics).
K2LivePolicyDecision K2LivePolicy_DecideRaw(uint32_t layerDepth, uint32_t tokens);
K2LivePolicyDecision K2LivePolicy_Apply(uint32_t layerDepth, uint32_t tokens);
K2LivePolicyDecision K2LivePolicy_Last();
void K2LivePolicy_Emit(FILE* f, const K2LivePolicyDecision& d);
void K2LivePolicy_NoteSwitch(K2LivePolicyMode m);
uint32_t K2LivePolicy_SwitchCount();
void K2LivePolicy_ResetSwitches();
void K2LivePolicy_ClearSticky();
void K2LivePolicy_SetSticky(K2LivePolicyMode m);
void K2LivePolicy_SetStickyArm(K2LivePolicyMode m, const char* arm);
uint32_t K2LivePolicy_HysteresisHold();
void K2LivePolicy_ApplyMode(K2LivePolicyMode mode);
// fullDepthPromo: trampoline+cyclone+elastic+fused (vs trampoline-only)
void K2LivePolicy_ApplyMode(K2LivePolicyMode mode, bool fullDepthPromo);

} // namespace Deep2
