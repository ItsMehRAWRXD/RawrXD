#pragma once
// ============================================================================
// Deep2MultiGpuLayerPlan.hpp — Batch 9 contiguous-layer placement plan
// Placement only. It NEVER claims arithmetic overlap for dependent layers.
// ============================================================================
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace Deep2 {

enum class MultiGpuSlotKind : uint8_t {
    GPU = 0,
    CPU = 1,
};

struct Deep2MultiGpuLayerPlan {
    bool active = false;
    bool hybrid = false;
    unsigned gpuSlotCount = 0;
    unsigned plannedCount = 0;

    std::vector<uint32_t> rangeLo;
    std::vector<uint32_t> rangeHi;
    std::vector<MultiGpuSlotKind> slotKind;
    std::vector<uint32_t> layerSlot;
    std::vector<uint8_t> layerExecuted;

    uint64_t totalLayers = 0;
    uint64_t totalWeight = 0;

    void clear() {
        active = false;
        hybrid = false;
        gpuSlotCount = 0;
        plannedCount = 0;
        rangeLo.clear();
        rangeHi.clear();
        slotKind.clear();
        layerSlot.clear();
        layerExecuted.clear();
        totalLayers = 0;
        totalWeight = 0;
    }

    bool configure(size_t layers,
                   const std::vector<uint64_t>& gpuCapacityBytes,
                   bool allowCpuTail = false,
                   uint32_t cpuTailLayers = 0) {
        clear();
        if (layers == 0 || gpuCapacityBytes.empty()) return false;

        std::vector<uint64_t> caps;
        caps.reserve(gpuCapacityBytes.size());
        for (uint64_t c : gpuCapacityBytes)
            if (c != 0) caps.push_back(c);
        if (caps.empty()) return false;

        const size_t gpuN = std::min(layers, caps.size());
        caps.resize(gpuN);

        size_t gpuLayers = layers;
        if (allowCpuTail && cpuTailLayers > 0 && cpuTailLayers < layers)
            gpuLayers = layers - cpuTailLayers;
        if (gpuLayers < gpuN) gpuLayers = gpuN;

        uint64_t capSum = 0;
        for (uint64_t c : caps) {
            if (capSum > std::numeric_limits<uint64_t>::max() - c) return false;
            capSum += c;
        }
        if (!capSum) return false;

        std::vector<size_t> count(gpuN, 1);
        size_t remaining = gpuLayers - gpuN;

        // Largest-remainder proportional assignment. For rawr's 32 GB + 16 GB
        // pair this naturally tends toward about 2:1 layers, while guaranteeing
        // every selected GPU at least one layer.
        std::vector<long double> frac(gpuN, 0.0L);
        size_t allocated = 0;
        for (size_t i = 0; i < gpuN; ++i) {
            const long double exact =
                static_cast<long double>(remaining) *
                static_cast<long double>(caps[i]) /
                static_cast<long double>(capSum);
            const size_t base = static_cast<size_t>(exact);
            count[i] += base;
            allocated += base;
            frac[i] = exact - static_cast<long double>(base);
        }
        for (size_t n = allocated; n < remaining; ++n) {
            size_t best = 0;
            for (size_t i = 1; i < gpuN; ++i)
                if (frac[i] > frac[best]) best = i;
            ++count[best];
            frac[best] = -1.0L;
        }

        gpuSlotCount = static_cast<unsigned>(gpuN);
        plannedCount = gpuSlotCount + ((layers > gpuLayers) ? 1u : 0u);
        active = gpuSlotCount != 0;
        hybrid = plannedCount > gpuSlotCount;
        totalLayers = layers;

        rangeLo.resize(plannedCount);
        rangeHi.resize(plannedCount);
        slotKind.resize(plannedCount, MultiGpuSlotKind::GPU);
        layerSlot.resize(layers, UINT32_MAX);
        layerExecuted.assign(layers, 0);

        uint32_t cursor = 0;
        for (unsigned s = 0; s < gpuSlotCount; ++s) {
            rangeLo[s] = cursor;
            rangeHi[s] = cursor + static_cast<uint32_t>(count[s]) - 1u;
            for (uint32_t l = rangeLo[s]; l <= rangeHi[s] && l < layers; ++l)
                layerSlot[l] = s;
            cursor = rangeHi[s] + 1u;
        }

        if (hybrid) {
            const unsigned s = gpuSlotCount;
            slotKind[s] = MultiGpuSlotKind::CPU;
            rangeLo[s] = cursor;
            rangeHi[s] = static_cast<uint32_t>(layers - 1);
            for (uint32_t l = rangeLo[s]; l <= rangeHi[s]; ++l)
                layerSlot[l] = s;
        }

        return active && cursor <= layers;
    }

    // Dense decode is sequential across layers, so capacity-proportional
    // assignment can badly imbalance cards with similar bandwidth but
    // different VRAM sizes.  This planner targets equal *time* using
    // throughput weights, while refusing assignments that exceed the
    // supplied per-GPU resident byte capacities.
    bool configureThroughputBalanced(
        const std::vector<uint64_t>& layerBytes,
        const std::vector<uint64_t>& gpuCapacityBytes,
        const std::vector<double>& throughputWeight)
    {
        clear();
        const size_t layers = layerBytes.size();
        if (!layers || gpuCapacityBytes.empty()) return false;

        const size_t gpuN = std::min(layers, gpuCapacityBytes.size());
        if (!gpuN) return false;

        std::vector<double> speed(gpuN, 1.0);
        for (size_t i = 0; i < gpuN && i < throughputWeight.size(); ++i)
            if (throughputWeight[i] > 0.0) speed[i] = throughputWeight[i];

        long double totalSpeed = 0.0L;
        uint64_t bytesTotal = 0;
        for (size_t i = 0; i < gpuN; ++i) totalSpeed += speed[i];
        for (uint64_t b : layerBytes) {
            if (bytesTotal > std::numeric_limits<uint64_t>::max() - b)
                return false;
            bytesTotal += b;
        }
        if (totalSpeed <= 0.0L || !bytesTotal) return false;

        gpuSlotCount = static_cast<unsigned>(gpuN);
        plannedCount = gpuSlotCount;
        active = true;
        hybrid = false;
        totalLayers = layers;
        totalWeight = bytesTotal;
        rangeLo.resize(gpuN);
        rangeHi.resize(gpuN);
        slotKind.assign(gpuN, MultiGpuSlotKind::GPU);
        layerSlot.assign(layers, UINT32_MAX);
        layerExecuted.assign(layers, 0);

        size_t cursor = 0;
        uint64_t prefixBytes = 0;
        long double prefixSpeed = 0.0L;

        for (size_t s = 0; s < gpuN; ++s) {
            rangeLo[s] = static_cast<uint32_t>(cursor);

            if (s + 1 == gpuN) {
                rangeHi[s] = static_cast<uint32_t>(layers - 1);
            } else {
                prefixSpeed += speed[s];
                const long double target =
                    static_cast<long double>(bytesTotal) *
                    prefixSpeed / totalSpeed;

                const size_t maxEnd = layers - (gpuN - s - 1) - 1;
                size_t end = cursor;
                uint64_t running = prefixBytes;
                while (end < maxEnd &&
                       static_cast<long double>(running + layerBytes[end]) < target) {
                    running += layerBytes[end];
                    ++end;
                }

                // Choose the nearer side of the target when legal.
                if (end > cursor) {
                    const long double before =
                        static_cast<long double>(running);
                    const long double after =
                        static_cast<long double>(running + layerBytes[end]);
                    if ((target - before) <= (after - target))
                        --end;
                }
                rangeHi[s] = static_cast<uint32_t>(end);
            }

            uint64_t slotBytes = 0;
            for (uint32_t l = rangeLo[s]; l <= rangeHi[s]; ++l) {
                layerSlot[l] = static_cast<uint32_t>(s);
                slotBytes += layerBytes[l];
            }

            // 80% resident budget matches the default GPU cache policy.
            const uint64_t cap = (gpuCapacityBytes[s] / 10u) * 8u;
            if (slotBytes > cap) {
                clear();
                return false;
            }

            prefixBytes += slotBytes;
            cursor = static_cast<size_t>(rangeHi[s]) + 1;
        }
        return cursor == layers;
    }

    std::vector<uint32_t> planLayers(size_t n) const {
        std::vector<uint32_t> out;
        const size_t lim = std::min(n, layerSlot.size());
        out.reserve(lim);
        for (size_t i = 0; i < lim; ++i) out.push_back(layerSlot[i]);
        return out;
    }
};

inline bool Deep2MultiGpu_SlotIsCpu(
    const Deep2MultiGpuLayerPlan& p, int slot) noexcept
{
    return slot < 0 ||
           static_cast<size_t>(slot) >= p.slotKind.size() ||
           p.slotKind[static_cast<size_t>(slot)] == MultiGpuSlotKind::CPU;
}

inline void Deep2MultiGpu_MarkLayerExecuted(
    Deep2MultiGpuLayerPlan& p, uint32_t layer) noexcept
{
    if (layer < p.layerExecuted.size()) p.layerExecuted[layer] = 1;
}

inline bool Deep2MultiGpu_AllLayersExecuted(
    const Deep2MultiGpuLayerPlan& p) noexcept
{
    if (!p.active || p.layerExecuted.empty()) return false;
    for (uint8_t v : p.layerExecuted) if (!v) return false;
    return true;
}

} // namespace Deep2
