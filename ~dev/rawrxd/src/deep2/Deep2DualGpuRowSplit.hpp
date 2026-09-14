#pragma once
// Deep2DualGpuRowSplit.hpp — simultaneous independent GEMV row partitions.
#include "Deep2Engine.h"
#include "Deep2GpuOverlapWitness.hpp"
#include "Deep2RowSplitPlan.hpp"
#include "vulkan_compute.h"
#include <cstddef>
#include <cstdint>

namespace Deep2 {

struct RowSplitReceipt {
    bool valid = false;
    bool gpu0 = false;
    bool gpu1 = false;
    bool hostMerge = false;
    uint32_t rows0 = 0;
    uint32_t rows1 = 0;
    uint64_t calibratedOverlapNs = 0;
    uint64_t hostEnvelopeOverlapNs = 0;
};

bool Deep2BuildGpuWeightView(
    const WeightTensor& wt,
    uint32_t rowBegin,
    uint32_t rowCount,
    GpuWeightView& out) noexcept;

bool Deep2RunDualGpuRowSplit(
    VulkanCompute& g0,
    VulkanCompute& g1,
    const WeightTensor& wt,
    const float* input,
    float* output,
    uint64_t epoch,
    RowSplitReceipt* receipt = nullptr);

} // namespace Deep2
