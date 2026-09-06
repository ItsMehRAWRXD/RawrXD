// ============================================================================
// AutoPlanner.hpp — Auto derives Expert values inside user locks
// Expert = AutoPlan + UserOverrides; AUTO—RESPECT OVERRIDES keeps locks.
// ============================================================================
#pragma once

#include "ExecutionPolicy.hpp"
#include "LearnedProfile.hpp"
#include "ReverseQuantPlan.hpp"
#include "../../core/GpuDecodeEfficiency.hpp"
#include <algorithm>

namespace Deep2 {
namespace Exec {

struct AutoPlanHints {
    int totalLayers = 28;
    int gpuCount = 1;
    uint64_t parameterCount = 0; // 0 → skip reverse quant solver
    uint64_t gpu0VramBytes = 0;
    uint64_t gpu1VramBytes = 0;
    uint64_t ramBytes = 0;
};

inline bool PlannerMayWrite(SettingAuthority a) {
    return a == SettingAuthority::AutoDetect ||
           a == SettingAuthority::AutoPlanner ||
           a == SettingAuthority::RuntimeLearned;
}

template <typename T>
bool PlanSet(Tunable<T>& cell, const T& v, SettingMutability mut) {
    if (cell.present && !PlannerMayWrite(cell.authority))
        return false;
    return cell.trySet(v, SettingAuthority::AutoPlanner, mut);
}

// Fill unlocked Expert knobs from budgets + objective. Locked cells untouched.
inline ExecutionPolicy AutoPlan(const ExecutionPolicy& seed,
                                const AutoPlanHints& hw = {}) {
    ExecutionPolicy p = seed;
    const uint64_t vram = p.memory.vramBudget.present
                              ? p.memory.vramBudget.value.n
                              : (12ULL * GB);
    const bool streamOk =
        !p.streaming.enabled.present || p.streaming.enabled.value;
    const auto objIn = p.scheduler.objective.present
                         ? p.scheduler.objective.value
                         : OptimizationTarget::HighestTPS;
    auto obj = objIn;
    if (obj == OptimizationTarget::LowestPower &&
        !rawrxd::GpuPowerValidForPolicy() &&
        !rawrxd::AmdGpuPowerTelemetryAvailable()) {
        obj = OptimizationTarget::Balanced;
    }

    // VRAM partition (weights dominate for TPS; stream reserve for low mem).
    const double wFrac =
        (obj == OptimizationTarget::LowestMemory) ? 0.35 : 0.50;
    const double kvFrac =
        (obj == OptimizationTarget::LowestMemory) ? 0.20 : 0.25;
    PlanSet(p.memory.vramParts.weights, Bytes::Of((uint64_t)(vram * wFrac)),
            SettingMutability::TokenBoundary);
    PlanSet(p.memory.vramParts.kv, Bytes::Of((uint64_t)(vram * kvFrac)),
            SettingMutability::TokenBoundary);
    PlanSet(p.memory.vramParts.streaming,
            Bytes::Of((uint64_t)(vram * (streamOk ? 0.12 : 0.05))),
            SettingMutability::TokenBoundary);
    PlanSet(p.memory.vramParts.activations, Bytes::Of(vram / 12),
            SettingMutability::TokenBoundary);
    PlanSet(p.memory.vramParts.scratch, Bytes::Of(vram / 24),
            SettingMutability::TokenBoundary);
    PlanSet(p.memory.vramParts.reserve, Bytes::Of(vram / 24),
            SettingMutability::TokenBoundary);

    // Reverse path: VRAM → quant fidelity → residency (when params known).
    const int L = (std::max)(1, hw.totalLayers);
    const int gpus = (std::max)(1, hw.gpuCount);
    bool needStream = streamOk;
    if (hw.parameterCount > 0) {
        HardwareSnapshot snap;
        if (hw.gpu0VramBytes > 0 || hw.gpu1VramBytes > 0) {
            if (hw.gpu0VramBytes > 0)
                snap.gpus.push_back({0, "gpu0", hw.gpu0VramBytes});
            if (hw.gpu1VramBytes > 0)
                snap.gpus.push_back({1, "gpu1", hw.gpu1VramBytes});
        } else {
            snap.gpus.push_back({0, "gpu0", vram});
            if (gpus >= 2)
                snap.gpus.push_back({1, "gpu1", vram});
        }
        snap.ramBytes = hw.ramBytes;
        ModelMetadata md;
        md.parameterCount = hw.parameterCount;
        md.nLayers = L;
        const ReverseExecutionPlan rp =
            ReverseQuantPlanFromResources(snap, md, p);
        (void)ApplyReversePlanToPolicy(p, rp);
        if (rp.streamingRequired)
            needStream = true;
    } else if (p.placement.layerRanges.empty()) {
        // Legacy heuristic when parameter census unavailable.
        int gpuLayers = (obj == OptimizationTarget::LowestMemory)
                            ? (std::max)(1, L / 4)
                            : (streamOk ? (L * 2) / 3 : L);
        gpuLayers = (std::min)(gpuLayers, L);
        if (gpus >= 2 && gpuLayers > 1) {
            const int mid = gpuLayers / 2;
            p.placement.layerRanges.push_back({{0, mid - 1}, DeviceKind::Gpu0});
            p.placement.layerRanges.push_back(
                {{mid, gpuLayers - 1}, DeviceKind::Gpu1});
        } else {
            p.placement.layerRanges.push_back(
                {{0, gpuLayers - 1}, DeviceKind::Gpu0});
        }
        if (gpuLayers < L)
            p.placement.layerRanges.push_back(
                {{gpuLayers, -1}, DeviceKind::Stream});
    }

    PlanSet(p.placement.embeddings, DeviceKind::Host,
            SettingMutability::TokenBoundary);
    PlanSet(p.placement.lmHead, DeviceKind::Gpu0,
            SettingMutability::TokenBoundary);
    PlanSet(p.placement.attentionClass, DeviceKind::Gpu0,
            SettingMutability::TokenBoundary);
    PlanSet(p.placement.ffnClass,
            needStream ? DeviceKind::Hybrid : DeviceKind::Gpu0,
            SettingMutability::TokenBoundary);

    const uint64_t chunk =
        (obj == OptimizationTarget::LowestMemory) ? (64ULL * MB) : (128ULL * MB);
    PlanSet(p.streaming.enabled, needStream, SettingMutability::TokenBoundary);
    PlanSet(p.streaming.chunkSize, Bytes::Of(chunk),
            SettingMutability::Immediate);
    PlanSet(p.streaming.prefetchDepth,
            (obj == OptimizationTarget::HighestTPS) ? 4 : 2,
            SettingMutability::Immediate);
    PlanSet(p.streaming.buffers, 3, SettingMutability::Immediate);
    PlanSet(p.streaming.prefetch, PrefetchPolicy::DependencyAware,
            SettingMutability::Immediate);

    PlanSet(p.kv.placement,
            (obj == OptimizationTarget::LowestMemory) ? KVPlacement::GPUPaged
            : (obj == OptimizationTarget::LowestPower &&
               rawrxd::GpuPowerValidForPolicy())
                  ? KVPlacement::GPUPaged
                  : KVPlacement::Hybrid,
            SettingMutability::SequenceBoundary);
    PlanSet(p.kv.gpuBudget, Bytes::Of((uint64_t)(vram * kvFrac)),
            SettingMutability::TokenBoundary);

    PlanSet(p.scheduler.eviction, EvictionPolicyKind::CostAware,
            SettingMutability::Immediate);
    return p;
}

// Switch Auto→Expert: expose planned values as editable (authority unchanged).
inline ExecutionPolicy ExposeAsExpert(const ExecutionPolicy& planned) {
    ExecutionPolicy p = planned;
    p.mode = UiMode::Expert;
    return p;
}

// Seed from fingerprint-bound profile, then fill remaining unlocked knobs.
inline ExecutionPolicy AutoPlanFromLearned(const ExecutionPolicy& seed,
                                           const LearnedProfile& learned,
                                           const AutoPlanHints& hw = {}) {
    ExecutionPolicy p = seed;
    if (learned.valid) {
        // Prefer prior successful placement for unlocked layer map.
        if (p.placement.layerRanges.empty() &&
            !learned.policy.placement.layerRanges.empty()) {
            p.placement.layerRanges = learned.policy.placement.layerRanges;
        }
        if (!p.streaming.chunkSize.present &&
            learned.policy.streaming.chunkSize.present) {
            PlanSet(p.streaming.chunkSize, learned.policy.streaming.chunkSize.value,
                    SettingMutability::Immediate);
        }
        if (!p.streaming.prefetchDepth.present &&
            learned.policy.streaming.prefetchDepth.present) {
            PlanSet(p.streaming.prefetchDepth,
                    learned.policy.streaming.prefetchDepth.value,
                    SettingMutability::Immediate);
        }
        if (!p.kv.placement.present && learned.policy.kv.placement.present) {
            PlanSet(p.kv.placement, learned.policy.kv.placement.value,
                    SettingMutability::SequenceBoundary);
        }
    }
    return AutoPlan(p, hw);
}

} // namespace Exec
} // namespace Deep2
