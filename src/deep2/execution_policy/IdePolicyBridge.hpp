// ============================================================================
// IdePolicyBridge.hpp — IDE string keys ↔ ExecutionPolicyStore (one source of truth)
// ============================================================================
#pragma once

#include "AutoPlanner.hpp"
#include "ExecutionPolicyBridge.hpp"
#include <cstdio>
#include <string>

namespace Deep2 {
namespace Exec {
namespace Ide {

inline std::string FmtGb(const Tunable<Bytes>& t, double defGb) {
    char b[32];
    const double g =
        t.present ? (double)t.value.n / (double)GB : defGb;
    std::snprintf(b, sizeof(b), "%.1f", g);
    return b;
}

inline std::string ModeName(UiMode m) {
    switch (m) {
    case UiMode::Auto: return "auto";
    case UiMode::Expert: return "expert";
    default: return "guided";
    }
}

inline std::string DeviceStr(DeviceKind d) {
    switch (d) {
    case DeviceKind::Gpu0: return "gpu0";
    case DeviceKind::Gpu1: return "gpu1";
    case DeviceKind::Stream: return "stream";
    case DeviceKind::Hybrid: return "hybrid";
    case DeviceKind::Disk: return "disk";
    default: return "ram";
    }
}

inline std::string LayerMapStr(const ExecutionPolicy& p, DeviceKind want) {
    for (const auto& lr : p.placement.layerRanges) {
        if (lr.second != want) continue;
        std::string s = std::to_string(lr.first.first) + "-";
        s += (lr.first.last < 0) ? "*" : std::to_string(lr.first.last);
        return s;
    }
    return "";
}

inline bool ParseRange(const std::string& s, LayerRange& out) {
    auto dash = s.find('-');
    if (dash == std::string::npos) {
        out.first = out.last = std::atoi(s.c_str());
        return true;
    }
    out.first = std::atoi(s.substr(0, dash).c_str());
    const std::string rhs = s.substr(dash + 1);
    out.last = (rhs == "*") ? -1 : std::atoi(rhs.c_str());
    return true;
}

inline std::string Get(const std::string& key) {
    const auto& p = ActivePolicy();
    if (key == "exec.mode") return ModeName(p.mode);
    if (key == "exec.vramGb") return FmtGb(p.memory.vramBudget, 12.0);
    if (key == "exec.ramGb") return FmtGb(p.memory.ramBudget, 40.0);
    if (key == "exec.streaming")
        return (!p.streaming.enabled.present || p.streaming.enabled.value)
                   ? "true"
                   : "false";
    if (key == "exec.chunkMb") {
        const uint64_t n = p.streaming.chunkSize.present
                               ? p.streaming.chunkSize.value.n / MB
                               : 128;
        return std::to_string((int)n);
    }
    if (key == "exec.prefetch")
        return std::to_string(p.streaming.prefetchDepth.present
                                  ? p.streaming.prefetchDepth.value
                                  : 3);
    if (key == "exec.buffers")
        return std::to_string(
            p.streaming.buffers.present ? p.streaming.buffers.value : 3);
    if (key == "exec.kv") {
        if (!p.kv.placement.present) return "hybrid";
        switch (p.kv.placement.value) {
        case KVPlacement::GPU: return "gpu";
        case KVPlacement::GPUPaged: return "gpu_paged";
        case KVPlacement::RAM: return "ram";
        case KVPlacement::DiskPaged: return "disk_paged";
        default: return "hybrid";
        }
    }
    if (key == "exec.kvGpuGb") return FmtGb(p.kv.gpuBudget, 2.0);
    if (key == "exec.kvQuant")
        return p.kv.quant.present ? p.kv.quant.value : "q8";
    if (key == "exec.workAvoid")
        return (p.reuse.enabled.present && p.reuse.enabled.value) ? "true"
                                                                  : "false";
    if (key == "exec.reuse") {
        if (!p.reuse.mode.present) return "certified";
        if (p.reuse.mode.value == ReuseMode::Disabled) return "off";
        if (p.reuse.mode.value == ReuseMode::ExactOnly) return "exact";
        return "certified";
    }
    if (key == "exec.objective") {
        if (!p.scheduler.objective.present) return "throughput";
        switch (p.scheduler.objective.value) {
        case OptimizationTarget::LowestMemory: return "lowest_memory";
        case OptimizationTarget::LowestLatency: return "latency";
        case OptimizationTarget::LowestPower: return "power";
        case OptimizationTarget::Balanced: return "balanced";
        default: return "throughput";
        }
    }
    if (key == "exec.autoTune")
        return (!p.scheduler.autoTune.present || p.scheduler.autoTune.value)
                   ? "true"
                   : "false";
    if (key == "exec.respectOverrides")
        return (!p.scheduler.respectOverrides.present ||
                p.scheduler.respectOverrides.value)
                   ? "true"
                   : "false";
    if (key == "exec.persist")
        return (!p.persistRuntimeChanges.present ||
                p.persistRuntimeChanges.value)
                   ? "true"
                   : "false";
    if (key == "exec.layersGpu0") return LayerMapStr(p, DeviceKind::Gpu0);
    if (key == "exec.layersGpu1") return LayerMapStr(p, DeviceKind::Gpu1);
    if (key == "exec.layersStream") return LayerMapStr(p, DeviceKind::Stream);
    if (key == "exec.attention")
        return p.placement.attentionClass.present
                   ? DeviceStr(p.placement.attentionClass.value)
                   : "gpu0";
    if (key == "exec.ffn")
        return p.placement.ffnClass.present
                   ? DeviceStr(p.placement.ffnClass.value)
                   : "hybrid";
    if (key == "exec.lmHead")
        return p.placement.lmHead.present ? DeviceStr(p.placement.lmHead.value)
                                          : "gpu0";
    if (key == "exec.hotpatch")
        return (!p.hotpatch.enabled.present || p.hotpatch.enabled.value)
                   ? "true"
                   : "false";
    if (key == "exec.policySha") return PolicySha256(p);
    return "";
}

} // namespace Ide
} // namespace Exec
} // namespace Deep2
