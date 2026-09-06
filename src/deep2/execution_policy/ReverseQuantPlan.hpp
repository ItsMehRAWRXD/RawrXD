// ============================================================================
// ReverseQuantPlan.hpp — VRAM → quant + placement (constraint solver)
//
// OLD:      quant/model size → required VRAM
// REVERSED: gpuVRAMBytes → fidelity ceiling → residency / stream
//
// Quant is a derived execution variable, not a user guess.
// Fail-soft: if no quant fully fits, continue into partial + stream.
// ============================================================================
#pragma once

#include "ExecutionPolicy.hpp"
#include "LearnedProfile.hpp"
#include <algorithm>
#include <cstdint>
#include <string>

namespace Deep2 {
namespace Exec {

enum class QuantType : uint8_t {
    Q8_0 = 0,
    Q6_K,
    Q5_K_M,
    Q4_K_M,
    Q3_K_M,
    Q2_K,
    StreamFallback
};

struct ModelMetadata {
    uint64_t parameterCount = 0;
    int nLayers = 0;
    uint64_t quantMetadataBytes = 0;
    uint64_t tensorAlignmentBytes = 0;
    std::string name;
};

struct WeightBudget {
    uint64_t gpu0Bytes = 0;
    uint64_t gpu1Bytes = 0;
    uint64_t ramBytes = 0;
    uint64_t jointGpuBytes = 0;
};

struct QuantPlan {
    QuantType preferredQuant = QuantType::Q4_K_M;
    uint64_t weightBudgetBytes = 0;
    uint64_t predictedWeightBytes = 0;
    uint64_t predictedPeakVram = 0;
    double headroomRatio = 0.0;
    bool fullGpuResident = false;
};

struct ReverseExecutionPlan {
    QuantPlan quant;
    uint64_t gpu0WeightBytes = 0;
    uint64_t gpu1WeightBytes = 0;
    uint64_t ramWeightBytes = 0;
    uint64_t nvmeWeightBytes = 0;
    int gpu0Layers = 0;
    int gpu1Layers = 0;
    int ramLayers = 0;
    int streamLayers = 0;
    int nLayers = 0;
    double expectedHeadroom = 0.0;
    bool fullResident = false;
    bool streamingRequired = false;
    std::string detail;
};

inline const char* QuantTypeName(QuantType q) {
    switch (q) {
    case QuantType::Q8_0: return "Q8_0";
    case QuantType::Q6_K: return "Q6_K";
    case QuantType::Q5_K_M: return "Q5_K_M";
    case QuantType::Q4_K_M: return "Q4_K_M";
    case QuantType::Q3_K_M: return "Q3_K_M";
    case QuantType::Q2_K: return "Q2_K";
    default: return "STREAM";
    }
}

inline double BitsPerWeight(QuantType q) {
    switch (q) {
    case QuantType::Q8_0: return 8.5;
    case QuantType::Q6_K: return 6.5;
    case QuantType::Q5_K_M: return 5.5;
    case QuantType::Q4_K_M: return 4.5;
    case QuantType::Q3_K_M: return 3.5;
    case QuantType::Q2_K: return 2.6;
    default: return 4.5;
    }
}

inline uint64_t EstimateModelBytes(uint64_t parameterCount, QuantType q,
                                   uint64_t meta = 0, uint64_t align = 0) {
    if (parameterCount == 0)
        return 0;
    const uint64_t body =
        static_cast<uint64_t>((parameterCount * BitsPerWeight(q)) / 8.0);
    return body + meta + align;
}

inline uint64_t SubSat(uint64_t a, uint64_t b) {
    return a > b ? a - b : 0;
}

inline uint64_t UsableWeightBytes(uint64_t gpuVramBytes, uint64_t kvBytes,
                                  uint64_t scratchBytes, uint64_t actBytes,
                                  uint64_t reserveBytes,
                                  uint64_t pinnedOtherBytes) {
    return SubSat(gpuVramBytes, kvBytes + scratchBytes + actBytes +
                                    reserveBytes + pinnedOtherBytes);
}

inline bool ReversePlannerMayWrite(SettingAuthority a) {
    return a == SettingAuthority::AutoDetect ||
           a == SettingAuthority::AutoPlanner ||
           a == SettingAuthority::RuntimeLearned;
}

inline WeightBudget BudgetsFromHardware(const HardwareSnapshot& hw,
                                        const ExecutionPolicy& policy,
                                        uint64_t kvBytes, uint64_t scratchBytes,
                                        uint64_t actBytes, uint64_t reserveBytes,
                                        uint64_t pinnedOtherBytes) {
    WeightBudget b;
    uint64_t g0 = 0, g1 = 0;
    for (const auto& g : hw.gpus) {
        if (g.index == 0) g0 = g.vramBytes;
        if (g.index == 1) g1 = g.vramBytes;
    }
    if (!policy.memory.gpus.empty()) {
        for (const auto& slot : policy.memory.gpus) {
            if (!slot.budget.present) continue;
            if (slot.index == 0) g0 = slot.budget.value.n;
            if (slot.index == 1) g1 = slot.budget.value.n;
        }
    } else if (policy.memory.vramBudget.present && g0 == 0) {
        g0 = policy.memory.vramBudget.value.n;
    }

    const uint64_t total = g0 + g1;
    const uint64_t oh =
        kvBytes + scratchBytes + actBytes + reserveBytes + pinnedOtherBytes;
    if (g1 == 0) {
        b.gpu0Bytes = UsableWeightBytes(g0, kvBytes, scratchBytes, actBytes,
                                        reserveBytes, pinnedOtherBytes);
    } else if (total > 0) {
        const uint64_t oh0 = (oh * g0) / total;
        b.gpu0Bytes = SubSat(g0, oh0);
        b.gpu1Bytes = SubSat(g1, oh - oh0);
    }
    b.jointGpuBytes = b.gpu0Bytes + b.gpu1Bytes;
    b.ramBytes = policy.memory.ramBudget.present ? policy.memory.ramBudget.value.n
                                                 : hw.ramBytes;
    if (policy.memory.ram.weightCache.present)
        b.ramBytes = (std::min)(b.ramBytes, policy.memory.ram.weightCache.value.n);
    return b;
}

inline QuantPlan BuildPlan(QuantType q, uint64_t budget, uint64_t modelBytes,
                           uint64_t peakExtra) {
    QuantPlan p;
    p.preferredQuant = q;
    p.weightBudgetBytes = budget;
    p.predictedWeightBytes = modelBytes;
    p.predictedPeakVram = modelBytes + peakExtra;
    p.fullGpuResident = (modelBytes > 0 && modelBytes <= budget);
    p.headroomRatio =
        budget > 0 ? (double)SubSat(budget, modelBytes) / (double)budget : 0.0;
    return p;
}

inline QuantPlan BuildStreamingPlan(uint64_t budget) {
    QuantPlan p;
    p.preferredQuant = QuantType::StreamFallback;
    p.weightBudgetBytes = budget;
    p.fullGpuResident = false;
    p.headroomRatio = 1.0;
    return p;
}

inline QuantPlan QuantFromGpuBudget(uint64_t gpuVramBytes,
                                    uint64_t parameterCount, uint64_t kvBytes,
                                    uint64_t scratchBytes,
                                    uint64_t reserveBytes) {
    const uint64_t budget = UsableWeightBytes(gpuVramBytes, kvBytes, scratchBytes,
                                              0, reserveBytes, 0);
    static const QuantType kLadder[] = {
        QuantType::Q8_0,   QuantType::Q6_K,   QuantType::Q5_K_M,
        QuantType::Q4_K_M, QuantType::Q3_K_M, QuantType::Q2_K};
    for (QuantType q : kLadder) {
        const uint64_t need = EstimateModelBytes(parameterCount, q);
        if (need > 0 && need <= budget)
            return BuildPlan(q, budget, need,
                             kvBytes + scratchBytes + reserveBytes);
    }
    // Do not fail: stream at highest fidelity estimate.
    if (parameterCount > 0) {
        const uint64_t need = EstimateModelBytes(parameterCount, QuantType::Q8_0);
        auto p = BuildPlan(QuantType::Q8_0, budget, need,
                           kvBytes + scratchBytes + reserveBytes);
        p.fullGpuResident = false;
        return p;
    }
    return BuildStreamingPlan(budget);
}

namespace rq_detail {

inline void AssignLayers(ReverseExecutionPlan& out, const WeightBudget& bud,
                         uint64_t modelBytes) {
    const int L = (std::max)(1, out.nLayers);
    out.gpu0Layers = out.gpu1Layers = out.ramLayers = out.streamLayers = 0;
    out.gpu0WeightBytes = out.gpu1WeightBytes = 0;
    out.ramWeightBytes = out.nvmeWeightBytes = 0;

    if (modelBytes == 0 || bud.jointGpuBytes == 0) {
        out.streamLayers = L;
        out.nvmeWeightBytes = modelBytes;
        out.streamingRequired = true;
        out.fullResident = false;
        return;
    }

    if (modelBytes <= bud.jointGpuBytes) {
        const double f0 = (double)bud.gpu0Bytes / (double)bud.jointGpuBytes;
        int n0 = (int)(f0 * L + 0.5);
        n0 = (std::max)(0, (std::min)(L, n0));
        if (bud.gpu1Bytes == 0)
            n0 = L;
        if (n0 == 0 && bud.gpu0Bytes > 0)
            n0 = (std::min)(1, L);
        out.gpu0Layers = n0;
        out.gpu1Layers = L - n0;
        out.gpu0WeightBytes =
            (modelBytes * (uint64_t)n0) / (uint64_t)L;
        out.gpu1WeightBytes = modelBytes - out.gpu0WeightBytes;
        out.fullResident = true;
        out.streamingRequired = false;
        return;
    }

    uint64_t rem = modelBytes;
    const uint64_t take0 = (std::min)(bud.gpu0Bytes, rem);
    rem -= take0;
    const uint64_t take1 = (std::min)(bud.gpu1Bytes, rem);
    rem -= take1;
    const uint64_t takeRam = (std::min)(bud.ramBytes, rem);
    rem -= takeRam;

    out.gpu0WeightBytes = take0;
    out.gpu1WeightBytes = take1;
    out.ramWeightBytes = takeRam;
    out.nvmeWeightBytes = rem;

    auto layersFor = [&](uint64_t bytes) -> int {
        return (int)((bytes * (uint64_t)L + modelBytes / 2) / modelBytes);
    };
    out.gpu0Layers = layersFor(take0);
    out.gpu1Layers = layersFor(take1);
    out.ramLayers = layersFor(takeRam);
    out.streamLayers =
        L - out.gpu0Layers - out.gpu1Layers - out.ramLayers;
    if (out.streamLayers < 0)
        out.streamLayers = 0;
    int sum = out.gpu0Layers + out.gpu1Layers + out.ramLayers + out.streamLayers;
    if (sum < L)
        out.streamLayers += (L - sum);
    else if (sum > L && out.streamLayers >= sum - L)
        out.streamLayers -= (sum - L);

    out.fullResident = false;
    out.streamingRequired = (out.streamLayers > 0 || rem > 0);
}

inline void ReadOverhead(const ExecutionPolicy& policy, uint64_t rawSum,
                         uint64_t& kv, uint64_t& scratch, uint64_t& act,
                         uint64_t& reserve) {
    kv = scratch = act = reserve = 0;
    if (policy.memory.vramParts.kv.present)
        kv = policy.memory.vramParts.kv.value.n;
    if (policy.kv.gpuBudget.present)
        kv = (std::max)(kv, policy.kv.gpuBudget.value.n);
    if (policy.memory.vramParts.scratch.present)
        scratch = policy.memory.vramParts.scratch.value.n;
    if (policy.memory.vramParts.activations.present)
        act = policy.memory.vramParts.activations.value.n;
    if (policy.memory.vramParts.reserve.present)
        reserve = policy.memory.vramParts.reserve.value.n;
    if (kv + scratch + act + reserve == 0 && rawSum > 0) {
        kv = rawSum / 8;
        scratch = rawSum / 32;
        act = rawSum / 16;
        reserve = rawSum / 32;
    }
}

} // namespace rq_detail

// maximize fidelity s.t. VRAM0/1, RAM, KV; then partial/stream — never hard-fail.
inline ReverseExecutionPlan ReverseQuantPlanFromResources(
    const HardwareSnapshot& hw, const ModelMetadata& model,
    const ExecutionPolicy& policy) {
    ReverseExecutionPlan out;
    out.nLayers = (std::max)(1, model.nLayers);

    uint64_t raw0 = 0, raw1 = 0;
    for (const auto& g : hw.gpus) {
        if (g.index == 0) raw0 = g.vramBytes;
        if (g.index == 1) raw1 = g.vramBytes;
    }
    if (!policy.memory.gpus.empty()) {
        for (const auto& s : policy.memory.gpus) {
            if (!s.budget.present) continue;
            if (s.index == 0) raw0 = s.budget.value.n;
            if (s.index == 1) raw1 = s.budget.value.n;
        }
    } else if (policy.memory.vramBudget.present && raw0 == 0)
        raw0 = policy.memory.vramBudget.value.n;

    uint64_t kv = 0, scratch = 0, act = 0, reserve = 0;
    rq_detail::ReadOverhead(policy, raw0 + raw1, kv, scratch, act, reserve);

    const WeightBudget bud =
        BudgetsFromHardware(hw, policy, kv, scratch, act, reserve, 0);
    out.quant.weightBudgetBytes = bud.jointGpuBytes;

    static const QuantType kLadder[] = {
        QuantType::Q8_0,   QuantType::Q6_K,   QuantType::Q5_K_M,
        QuantType::Q4_K_M, QuantType::Q3_K_M, QuantType::Q2_K};

    const auto obj = policy.scheduler.objective.present
                         ? policy.scheduler.objective.value
                         : OptimizationTarget::HighestTPS;

    QuantType chosen = QuantType::StreamFallback;
    uint64_t chosenBytes = 0;

    // Pass 1: highest fidelity that fully fits joint GPU.
    for (QuantType q : kLadder) {
        const uint64_t need = EstimateModelBytes(
            model.parameterCount, q, model.quantMetadataBytes,
            model.tensorAlignmentBytes);
        if (need > 0 && need <= bud.jointGpuBytes) {
            chosen = q;
            chosenBytes = need;
            break;
        }
    }

    // Pass 2 (LowestMemory): same — already highest-full-fit.
    // Pass 3: nothing fully fits → keep max fidelity, solve residency.
    if (chosen == QuantType::StreamFallback && model.parameterCount > 0 &&
        bud.jointGpuBytes > 0) {
        if (obj == OptimizationTarget::LowestMemory) {
            // Prefer smallest that still places ≥1 layer on GPU.
            for (int i = 5; i >= 0; --i) {
                const uint64_t need = EstimateModelBytes(
                    model.parameterCount, kLadder[i], model.quantMetadataBytes,
                    model.tensorAlignmentBytes);
                if (need > 0) {
                    chosen = kLadder[i];
                    chosenBytes = need;
                    break;
                }
            }
        } else {
            chosen = QuantType::Q8_0;
            chosenBytes = EstimateModelBytes(model.parameterCount, chosen,
                                             model.quantMetadataBytes,
                                             model.tensorAlignmentBytes);
        }
    }

    if (chosen == QuantType::StreamFallback) {
        out.quant = BuildStreamingPlan(bud.jointGpuBytes);
        rq_detail::AssignLayers(out, bud, 0);
        out.detail = "no_capacity; stream_required";
        return out;
    }

    out.quant = BuildPlan(chosen, bud.jointGpuBytes, chosenBytes,
                          kv + scratch + act + reserve);
    rq_detail::AssignLayers(out, bud, chosenBytes);
    out.expectedHeadroom = out.quant.headroomRatio;
    out.quant.fullGpuResident = out.fullResident;
    out.detail = std::string("quant=") + QuantTypeName(chosen) +
                 " full=" + (out.fullResident ? "1" : "0") +
                 " g0L=" + std::to_string(out.gpu0Layers) +
                 " g1L=" + std::to_string(out.gpu1Layers) +
                 " streamL=" + std::to_string(out.streamLayers);
    return out;
}

inline bool ApplyReversePlanToPolicy(ExecutionPolicy& policy,
                                     const ReverseExecutionPlan& plan) {
    if (plan.nLayers <= 0)
        return false;

    if (!policy.placement.weightPolicy.present ||
        ReversePlannerMayWrite(policy.placement.weightPolicy.authority)) {
        const WeightPolicy wp =
            plan.fullResident     ? WeightPolicy::Gpu
            : plan.streamingRequired ? WeightPolicy::Stream
                                     : WeightPolicy::Hybrid;
        policy.placement.weightPolicy.force(wp, SettingAuthority::AutoPlanner,
                                            SettingMutability::TokenBoundary);
    }

    bool userOwnsPlacement = false;
    for (const auto& r : policy.placement.rules) {
        if (r.authority == SettingAuthority::UserLocked ||
            r.authority == SettingAuthority::UserOverride) {
            userOwnsPlacement = true;
            break;
        }
    }

    if (!userOwnsPlacement) {
        policy.placement.layerRanges.clear();
        int cursor = 0;
        auto push = [&](int count, DeviceKind d) {
            if (count <= 0)
                return;
            const int last = cursor + count - 1;
            policy.placement.layerRanges.push_back(
                {LayerRange{cursor, last}, d});
            cursor = last + 1;
        };
        push(plan.gpu0Layers, DeviceKind::Gpu0);
        push(plan.gpu1Layers, DeviceKind::Gpu1);
        push(plan.ramLayers, DeviceKind::Host);
        if (plan.streamLayers > 0)
            policy.placement.layerRanges.push_back(
                {LayerRange{cursor, -1}, DeviceKind::Stream});
    }

    if (plan.streamingRequired &&
        (!policy.streaming.enabled.present ||
         ReversePlannerMayWrite(policy.streaming.enabled.authority))) {
        policy.streaming.enabled.force(true, SettingAuthority::AutoPlanner,
                                       SettingMutability::TokenBoundary);
    }

    if (!policy.memory.vramParts.weights.present ||
        ReversePlannerMayWrite(policy.memory.vramParts.weights.authority)) {
        policy.memory.vramParts.weights.force(
            Bytes::Of(plan.quant.weightBudgetBytes),
            SettingAuthority::AutoPlanner, SettingMutability::TokenBoundary);
    }
    return true;
}

} // namespace Exec
} // namespace Deep2
