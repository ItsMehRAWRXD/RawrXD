// ============================================================================
// IdePolicySet.hpp — apply IDE string edits as Session deltas (fail-closed)
// ============================================================================
#pragma once

#include "IdePolicyBridge.hpp"
#include "ExecutionPolicyStore.hpp"
#include <cctype>
#include <cstdlib>
#include <filesystem>

namespace Deep2 {
namespace Exec {
namespace Ide {

inline void EnsureStore() {
    auto& store = ExecutionPolicyStore::Instance();
    const char* cands[] = {"config/rawrxd.settings.yaml", "rawrxd.settings.yaml",
                           nullptr};
    for (int i = 0; cands[i]; ++i) {
        if (std::filesystem::exists(cands[i])) {
            store.setPaths(cands[i], "profiles");
            store.load({});
            return;
        }
    }
}

inline DeviceKind ParseDev(std::string s) {
    for (auto& c : s)
        c = (char)std::tolower((unsigned char)c);
    if (s == "gpu" || s == "gpu0") return DeviceKind::Gpu0;
    if (s == "gpu1") return DeviceKind::Gpu1;
    if (s == "stream") return DeviceKind::Stream;
    if (s == "hybrid" || s == "adaptive") return DeviceKind::Hybrid;
    if (s == "disk") return DeviceKind::Disk;
    return DeviceKind::Host;
}

inline void UpsertLayer(ExecutionPolicy& d, DeviceKind want,
                        const std::string& range) {
    LayerRange lr{};
    if (!ParseRange(range, lr)) return;
    for (auto& e : d.placement.layerRanges) {
        if (e.second == want) {
            e.first = lr;
            return;
        }
    }
    d.placement.layerRanges.push_back({lr, want});
}

inline PolicyCommitResult Set(const std::string& key, const std::string& value) {
    EnsureStore();
    ExecutionPolicy d{};
    auto auth = SettingAuthority::Session;
    auto mut = SettingMutability::Immediate;

    if (key == "exec.mode") {
        if (value == "auto") d.mode = UiMode::Auto;
        else if (value == "expert") d.mode = UiMode::Expert;
        else d.mode = UiMode::Guided;
        if (d.mode == UiMode::Auto) {
            d = AutoPlan(ActivePolicy());
            d.mode = UiMode::Auto;
        } else if (value == "expert") {
            d = ExposeAsExpert(ActivePolicy());
        }
    } else if (key == "exec.vramGb") {
        d.memory.vramBudget.force(Bytes::GiB(std::atof(value.c_str())), auth,
                                  SettingMutability::TokenBoundary);
    } else if (key == "exec.ramGb") {
        d.memory.ramBudget.force(Bytes::GiB(std::atof(value.c_str())), auth,
                                 SettingMutability::TokenBoundary);
    } else if (key == "exec.streaming") {
        d.streaming.enabled.force(value == "true" || value == "1", auth,
                                  SettingMutability::TokenBoundary);
    } else if (key == "exec.chunkMb") {
        d.streaming.chunkSize.force(Bytes::MiB(std::atoi(value.c_str())), auth,
                                    mut);
    } else if (key == "exec.prefetch") {
        d.streaming.prefetchDepth.force(std::atoi(value.c_str()), auth, mut);
    } else if (key == "exec.buffers") {
        d.streaming.buffers.force(std::atoi(value.c_str()), auth, mut);
    } else if (key == "exec.kv") {
        KVPlacement kp = KVPlacement::Hybrid;
        if (value == "gpu") kp = KVPlacement::GPU;
        else if (value == "gpu_paged") kp = KVPlacement::GPUPaged;
        else if (value == "ram") kp = KVPlacement::RAM;
        else if (value == "disk_paged") kp = KVPlacement::DiskPaged;
        d.kv.placement.force(kp, auth, SettingMutability::SequenceBoundary);
    } else if (key == "exec.kvGpuGb") {
        d.kv.gpuBudget.force(Bytes::GiB(std::atof(value.c_str())), auth,
                             SettingMutability::TokenBoundary);
    } else if (key == "exec.kvQuant") {
        d.kv.quant.force(value, auth, SettingMutability::SequenceBoundary);
    } else if (key == "exec.workAvoid") {
        d.reuse.enabled.force(value == "true" || value == "1", auth,
                              SettingMutability::TokenBoundary);
    } else if (key == "exec.reuse") {
        ReuseMode m = ReuseMode::CertifiedReuse;
        if (value == "off") m = ReuseMode::Disabled;
        else if (value == "exact") m = ReuseMode::ExactOnly;
        d.reuse.mode.force(m, auth, SettingMutability::TokenBoundary);
    } else if (key == "exec.objective") {
        OptimizationTarget t = OptimizationTarget::HighestTPS;
        if (value == "lowest_memory") t = OptimizationTarget::LowestMemory;
        else if (value == "latency") t = OptimizationTarget::LowestLatency;
        else if (value == "power") t = OptimizationTarget::LowestPower;
        else if (value == "balanced") t = OptimizationTarget::Balanced;
        d.scheduler.objective.force(t, auth, mut);
    } else if (key == "exec.autoTune") {
        d.scheduler.autoTune.force(value == "true" || value == "1", auth, mut);
    } else if (key == "exec.respectOverrides") {
        d.scheduler.respectOverrides.force(value == "true" || value == "1", auth,
                                           mut);
    } else if (key == "exec.persist") {
        d.persistRuntimeChanges.force(value == "true" || value == "1", auth,
                                      mut);
    } else if (key == "exec.layersGpu0") {
        d.placement.layerRanges = ActivePolicy().placement.layerRanges;
        UpsertLayer(d, DeviceKind::Gpu0, value);
    } else if (key == "exec.layersGpu1") {
        d.placement.layerRanges = ActivePolicy().placement.layerRanges;
        UpsertLayer(d, DeviceKind::Gpu1, value);
    } else if (key == "exec.layersStream") {
        d.placement.layerRanges = ActivePolicy().placement.layerRanges;
        UpsertLayer(d, DeviceKind::Stream, value);
    } else if (key == "exec.attention") {
        d.placement.attentionClass.force(ParseDev(value), auth,
                                         SettingMutability::TokenBoundary);
    } else if (key == "exec.ffn") {
        d.placement.ffnClass.force(ParseDev(value), auth,
                                   SettingMutability::TokenBoundary);
    } else if (key == "exec.lmHead") {
        d.placement.lmHead.force(ParseDev(value), auth,
                                 SettingMutability::TokenBoundary);
    } else if (key == "exec.hotpatch") {
        d.hotpatch.enabled.force(value == "true" || value == "1", auth, mut);
    } else if (key == "exec.targetDecodeMs") {
        d.latency.targetDecodeMs.force(std::atof(value.c_str()), auth, mut);
        d.latency.autoTarget.force(false, auth, mut);
    } else if (key == "exec.targetTtftMs") {
        d.latency.targetTtftMs.force(std::atof(value.c_str()), auth, mut);
        d.latency.autoTarget.force(false, auth, mut);
    } else if (key == "exec.targetE2eMs") {
        d.latency.targetE2eMs.force(std::atof(value.c_str()), auth, mut);
        d.latency.autoTarget.force(false, auth, mut);
    } else if (key == "exec.latencyAuto") {
        d.latency.autoTarget.force(value == "true" || value == "1", auth, mut);
    } else if (key == "exec.targetSpeedup") {
        d.speedup.targetRealSpeedup.force(std::atof(value.c_str()), auth, mut);
        d.speedup.autoTarget.force(false, auth, mut);
    } else if (key == "exec.speedupAuto") {
        d.speedup.autoTarget.force(value == "true" || value == "1", auth, mut);
    } else if (key == "exec.minAcceptedGain") {
        d.speedup.minimumAcceptedGain.force(std::atof(value.c_str()), auth, mut);
    } else {
        PolicyCommitResult r;
        r.detail = "unknown key";
        return r;
    }

    auto r = ApplySessionDelta(d, "ide:" + key);
    if (r.ok && ActivePolicy().persistRuntimeChanges.present &&
        ActivePolicy().persistRuntimeChanges.value) {
        ExecutionPolicyStore::Instance().saveGlobal();
    }
    return r;
}

} // namespace Ide
} // namespace Exec
} // namespace Deep2
