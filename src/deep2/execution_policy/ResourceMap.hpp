// ============================================================================
// ResourceMap.hpp — live placement / budget snapshot for IDE Resource Map
// ============================================================================
#pragma once

#include "ExecutionPolicyBridge.hpp"
#include "ExecutionPolicyApply.hpp"
#include <algorithm>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

enum class ResidencyKind : uint8_t {
    Gpu0 = 0,
    Gpu1,
    Ram,
    NvmeStream,
    Pinned,
    Kv
};

struct ResourceMapItem {
    std::string name; // tensor or "L14" / "KV"
    ResidencyKind kind = ResidencyKind::Ram;
    uint64_t bytes = 0;
    bool pinned = false;
    bool hot = false;
};

struct ResourceMapSnapshot {
    uint64_t gpu0Used = 0, gpu0Budget = 0;
    uint64_t gpu1Used = 0, gpu1Budget = 0;
    uint64_t ramUsed = 0, ramBudget = 0;
    uint64_t nvmeCache = 0;
    uint64_t kvUsed = 0, kvBudget = 0;
    std::vector<ResourceMapItem> items;
    std::string policySha;
    uint64_t policyVersion = 0;
};

inline ResourceMapSnapshot BuildResourceMapFromPolicy(
    uint64_t gpu0Used = 0, uint64_t gpu1Used = 0, uint64_t ramUsed = 0,
    uint64_t nvmeCache = 0, uint64_t kvUsed = 0) {
    EnsurePolicyLoaded();
    const auto& p = ActivePolicy();
    ResourceMapSnapshot s;
    s.policySha = PolicySha256(p);
    s.policyVersion = p.version;

    const auto& report = LastApplyReport();
    s.gpu0Budget = p.memory.vramBudget.present ? p.memory.vramBudget.value.n : 0;
    if (!p.memory.gpus.empty() && p.memory.gpus[0].budget.present)
        s.gpu0Budget = p.memory.gpus[0].budget.value.n;
    if (p.memory.gpus.size() > 1 && p.memory.gpus[1].budget.present)
        s.gpu1Budget = p.memory.gpus[1].budget.value.n;

    uint64_t live0 = 0, live1 = 0;
    bool usedLive = false;
    for (const auto& o : report.observations) {
        if (o.observedGpu == 0) live0 += o.bytes;
        else if (o.observedGpu == 1) live1 += o.bytes;
        usedLive = true;
    }
    s.gpu0Used = usedLive ? live0 : gpu0Used;
    s.gpu1Used = usedLive ? live1 : gpu1Used;
    s.ramUsed = ramUsed;
    s.nvmeCache = nvmeCache;
    s.kvUsed = kvUsed;
    if (s.gpu0Budget == 0 && p.memory.vramBudget.present)
        s.gpu0Budget = p.memory.vramBudget.value.n;
    s.ramBudget = p.memory.ramBudget.present ? p.memory.ramBudget.value.n : 0;
    s.kvBudget = p.kv.gpuBudget.present ? p.kv.gpuBudget.value.n : 0;

    for (const auto& lr : p.placement.layerRanges) {
        ResourceMapItem it;
        it.name = "L" + std::to_string(lr.first.first) + "-" +
                  (lr.first.last < 0 ? "*" : std::to_string(lr.first.last));
        if (lr.second == DeviceKind::Gpu0) it.kind = ResidencyKind::Gpu0;
        else if (lr.second == DeviceKind::Gpu1) it.kind = ResidencyKind::Gpu1;
        else if (lr.second == DeviceKind::Stream)
            it.kind = ResidencyKind::NvmeStream;
        else it.kind = ResidencyKind::Ram;
        s.items.push_back(it);
    }
    for (const auto& o : report.observations) {
        ResourceMapItem it;
        it.name = o.name;
        it.bytes = o.bytes;
        it.hot = true;
        if (o.observedGpu == 0) it.kind = ResidencyKind::Gpu0;
        else if (o.observedGpu == 1) it.kind = ResidencyKind::Gpu1;
        else it.kind = ResidencyKind::NvmeStream;
        s.items.push_back(it);
    }
    for (const auto& pin : p.placement.pinned) {
        ResourceMapItem it;
        it.name = pin;
        it.kind = ResidencyKind::Pinned;
        it.pinned = true;
        s.items.push_back(it);
    }
    return s;
}

inline const char* KindName(ResidencyKind k) {
    switch (k) {
    case ResidencyKind::Gpu0: return "GPU0";
    case ResidencyKind::Gpu1: return "GPU1";
    case ResidencyKind::NvmeStream: return "STREAM";
    case ResidencyKind::Pinned: return "PIN";
    case ResidencyKind::Kv: return "KV";
    default: return "RAM";
    }
}

inline std::string FormatBar(uint64_t used, uint64_t bud, int width = 16) {
    if (bud == 0) return std::string(width, '-');
    const int fill =
        (int)((std::min)(1.0, (double)used / (double)bud) * width);
    return std::string(fill, '#') + std::string(width - fill, '.');
}

inline std::string FormatResourceMap(const ResourceMapSnapshot& s) {
    std::ostringstream o;
    auto gb = [](uint64_t n) { return n / (double)GB; };
    o << "RawrXD Resource Map  policy=" << s.policySha
      << " v" << s.policyVersion << "\n";
    o << "──────────────────────────────────\n";
    o << "GPU0  " << FormatBar(s.gpu0Used, s.gpu0Budget) << "  "
      << gb(s.gpu0Used) << " / " << gb(s.gpu0Budget) << " GB\n";
    o << "GPU1  " << FormatBar(s.gpu1Used, s.gpu1Budget) << "  "
      << gb(s.gpu1Used) << " / " << gb(s.gpu1Budget) << " GB\n";
    o << "RAM   " << FormatBar(s.ramUsed, s.ramBudget) << "  "
      << gb(s.ramUsed) << " / " << gb(s.ramBudget) << " GB\n";
    o << "NVMe  cache " << gb(s.nvmeCache) << " GB\n";
    o << "KV    " << FormatBar(s.kvUsed, s.kvBudget) << "  "
      << gb(s.kvUsed) << " / " << gb(s.kvBudget) << " GB\n\n";
    o << "Placement:\n";
    for (const auto& it : s.items) {
        o << "  " << it.name << " ───── " << KindName(it.kind);
        if (it.pinned) o << " [pinned]";
        o << "\n";
    }
    return o.str();
}

// Expert: pin pattern into session policy (fail-closed via store).
inline PolicyCommitResult PinFromMap(const std::string& pattern) {
    ExecutionPolicy d{};
    d.placement.pinned = ActivePolicy().placement.pinned;
    d.placement.pinned.push_back(pattern);
    return ApplySessionDelta(d, "resource-map-pin");
}

inline PolicyCommitResult MoveLayers(const LayerRange& range, DeviceKind dest) {
    ExecutionPolicy d{};
    d.placement.layerRanges = ActivePolicy().placement.layerRanges;
    d.placement.layerRanges.push_back({range, dest});
    return ApplySessionDelta(d, "resource-map-move");
}

} // namespace Exec
} // namespace Deep2
