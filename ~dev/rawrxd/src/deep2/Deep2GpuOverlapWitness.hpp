#pragma once
// ============================================================================
// Deep2GpuOverlapWitness.hpp — Batch 9 temporal overlap proof
// Cross-device authority uses calibrated Vulkan timestamps only.
// Host envelope overlap is informational and cannot mint calibrated authority.
// ============================================================================
#include "vulkan_compute.h"
#include <algorithm>
#include <cstdint>
#include <vector>

namespace Deep2 {

struct GpuOverlapWitness {
    uint64_t epoch = 0;
    uint64_t calibratedOverlapNs = 0;
    uint64_t hostEnvelopeOverlapNs = 0;
    uint64_t device0ModelNs = 0;
    uint64_t device1ModelNs = 0;
    uint64_t materialBytes0 = 0;
    uint64_t materialBytes1 = 0;
    uint32_t pairCount = 0;
    bool calibrated = false;
    bool sameEpoch = false;
    bool materialModelWork = false;
    bool computeVsTransfer = false;

    bool authoritativeTemporalOverlap() const noexcept {
        return calibrated && sameEpoch && materialModelWork &&
               calibratedOverlapNs > 0;
    }
};

inline uint64_t Deep2IntervalOverlapNs(
    uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1) noexcept
{
    if (a1 <= a0 || b1 <= b0) return 0;
    const uint64_t lo = std::max(a0,b0);
    const uint64_t hi = std::min(a1,b1);
    return hi > lo ? hi - lo : 0;
}

inline GpuOverlapWitness Deep2Gpu_MeasureOverlap(
    const VulkanCompute& a, const VulkanCompute& b, uint64_t epoch)
{
    GpuOverlapWitness w{};
    w.epoch = epoch;
    const auto ia = a.RecentIntervals(epoch);
    const auto ib = b.RecentIntervals(epoch);
    w.sameEpoch = !ia.empty() && !ib.empty();

    for (const auto& x : ia) {
        if (x.kind == GpuWorkKind::CapabilityProbe) continue;
        if (x.kind == GpuWorkKind::ModelCompute)
            w.device0ModelNs += x.calibratedDurationNs();
        w.materialBytes0 += x.bytes;

        for (const auto& y : ib) {
            if (y.kind == GpuWorkKind::CapabilityProbe) continue;
            ++w.pairCount;

            const uint64_t hostOverlap = Deep2IntervalOverlapNs(
                x.hostSubmitNs,x.hostCompleteNs,
                y.hostSubmitNs,y.hostCompleteNs);
            w.hostEnvelopeOverlapNs += hostOverlap;

            if (x.calibrated && y.calibrated) {
                const uint64_t gpuOverlap = Deep2IntervalOverlapNs(
                    x.gpuStartNs,x.gpuEndNs,
                    y.gpuStartNs,y.gpuEndNs);
                w.calibratedOverlapNs += gpuOverlap;
                if (gpuOverlap) w.calibrated = true;
            }

            if ((x.kind == GpuWorkKind::ModelCompute &&
                 y.kind == GpuWorkKind::ModelTransfer) ||
                (x.kind == GpuWorkKind::ModelTransfer &&
                 y.kind == GpuWorkKind::ModelCompute))
                w.computeVsTransfer = true;

            if (x.kind == GpuWorkKind::ModelCompute ||
                x.kind == GpuWorkKind::ModelTransfer ||
                y.kind == GpuWorkKind::ModelCompute ||
                y.kind == GpuWorkKind::ModelTransfer)
                w.materialModelWork = true;
        }
    }

    for (const auto& y : ib) {
        if (y.kind == GpuWorkKind::CapabilityProbe) continue;
        if (y.kind == GpuWorkKind::ModelCompute)
            w.device1ModelNs += y.calibratedDurationNs();
        w.materialBytes1 += y.bytes;
    }

    return w;
}

} // namespace Deep2
