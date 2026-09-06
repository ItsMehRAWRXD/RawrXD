// ============================================================================
// PolicyApply.hpp — map ActivePolicy → Elastic / Stream / NVMe / Session knobs
// Loader must honor these; never silently inflate past hard caps.
// ============================================================================
#pragma once

#include "ExecutionPolicyBridge.hpp"
#include "../ElasticResidencyManager.hpp"
#include "../StreamEngine.hpp"
#include "../NVMeStream.h"

#include <algorithm>
#include <cstdint>
#include <string>

namespace Deep2 {
namespace Exec {

inline ElasticResidencyConfig ElasticFromPolicy(const ExecutionPolicy& p) {
    ElasticResidencyConfig c{};
    const uint64_t vram = p.memory.vramBudget.present ? p.memory.vramBudget.value.n
                                                      : (16ULL << 30);
    const uint64_t ram = p.memory.ramBudget.present ? p.memory.ramBudget.value.n
                                                    : (40ULL << 30);

    const auto& vp = p.memory.vramParts;
    c.maxHotBytes = vp.weights.present ? vp.weights.value.n : (vram / 2);
    if (vp.streaming.present)
        c.maxHotBytes = (std::min)(c.maxHotBytes + vp.streaming.value.n, vram);

    if (p.memory.ram.weightCache.present)
        c.maxWarmCompressedBytes = p.memory.ram.weightCache.value.n;
    else
        c.maxWarmCompressedBytes = ram / 2;

    if (p.memory.ram.staging.present)
        c.maxWarmStagedBytes = p.memory.ram.staging.value.n;
    else
        c.maxWarmStagedBytes = (std::min)(c.maxWarmCompressedBytes / 8, 2ULL << 30);

    if (p.streaming.prefetchDepth.present)
        c.prefetchLookahead = static_cast<uint32_t>(
            (std::max)(0, p.streaming.prefetchDepth.value));
    else if (p.streaming.prefetch.present &&
             p.streaming.prefetch.value == PrefetchPolicy::Off)
        c.prefetchLookahead = 0;

    if (p.streaming.chunkSize.present && p.streaming.chunkSize.value.n > 0)
        c.nvmeReadGranularity = static_cast<size_t>(
            (std::min)(p.streaming.chunkSize.value.n, 64ULL << 20));

    c.useGhostCache = PolicyAllowsWorkAvoidance();
    c.useQuantizedGpuPath = true;
    return c;
}

inline StreamConfig StreamEngineFromPolicy(const ExecutionPolicy& p) {
    StreamConfig c{};
    if (p.memory.vramBudget.present)
        c.vramBudgetBytes = static_cast<size_t>(p.memory.vramBudget.value.n);
    if (p.streaming.chunkSize.present)
        c.chunkSizeBytes = p.streaming.chunkSize.value.n;
    if (p.memory.vramParts.streaming.present)
        c.cacheReserveBytes =
            static_cast<size_t>(p.memory.vramParts.streaming.value.n);
    c.reuseData = PolicyAllowsWorkAvoidance();
    c.hotpatchRelive = !p.hotpatch.enabled.present || p.hotpatch.enabled.value;
    c.undeadHop = c.hotpatchRelive;
    return c;
}

inline NVMeStreamConfig NVMeFromPolicy(const ExecutionPolicy& p,
                                       const std::string& modelPath) {
    NVMeStreamConfig c{};
    c.modelPath = modelPath;
    if (p.memory.ram.weightCache.present)
        c.maxResidentBytes = static_cast<size_t>(p.memory.ram.weightCache.value.n);
    else if (p.memory.ramBudget.present)
        c.maxResidentBytes = static_cast<size_t>(p.memory.ramBudget.value.n / 2);

    c.enablePrefetch = true;
    if (p.streaming.prefetch.present &&
        p.streaming.prefetch.value == PrefetchPolicy::Off)
        c.enablePrefetch = false;
    if (p.streaming.prefetchDepth.present)
        c.prefetchDepth = static_cast<size_t>(
            (std::max)(0, p.streaming.prefetchDepth.value));
    if (p.kv.pageSize.present && p.kv.pageSize.value.n > 0)
        c.pageSize = static_cast<size_t>(p.kv.pageSize.value.n);
    return c;
}

// llama.cpp-style count: layers on any GPU. -1 = all GPU if weightPolicy=Gpu.
inline int GpuLayersFromPolicy(const ExecutionPolicy& p, int totalLayers) {
    if (p.placement.weightPolicy.present) {
        if (p.placement.weightPolicy.value == WeightPolicy::Gpu)
            return -1;
        if (p.placement.weightPolicy.value == WeightPolicy::Cpu ||
            p.placement.weightPolicy.value == WeightPolicy::Stream)
            return 0;
    }
    if (p.placement.layerRanges.empty() || totalLayers <= 0)
        return 0;

    int gpuCount = 0;
    for (int L = 0; L < totalLayers; ++L) {
        DeviceKind d = DeviceKind::Host;
        bool hit = false;
        for (const auto& lr : p.placement.layerRanges) {
            const int last = (lr.first.last < 0) ? (totalLayers - 1) : lr.first.last;
            if (L >= lr.first.first && L <= last) {
                d = lr.second;
                hit = true;
            }
        }
        if (hit && (d == DeviceKind::Gpu0 || d == DeviceKind::Gpu1 ||
                    d == DeviceKind::Hybrid))
            ++gpuCount;
    }
    return gpuCount;
}

inline bool IsPinnedPattern(const ExecutionPolicy& p, const std::string& name) {
    for (const auto& pin : p.placement.pinned) {
        if (pin == name) return true;
        if (!pin.empty() && pin.back() == '*') {
            const std::string pref = pin.substr(0, pin.size() - 1);
            if (name.compare(0, pref.size(), pref) == 0) return true;
        }
    }
    return false;
}

} // namespace Exec
} // namespace Deep2
