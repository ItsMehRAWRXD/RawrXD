#pragma once
// Deep2DualGpuRowSplit.hpp — simultaneous independent GEMV row partitions.
#include "Deep2Engine.h"
#include "Deep2GpuOverlapWitness.hpp"
#include "Deep2RowSplitPlan.hpp"
#include "vulkan_compute.h"
#include <cstddef>
#include <cstdint>

namespace Deep2 {
struct DualAsyncFanIn {
    uint64_t wallNs=0;
    uint64_t gpu0Ns=0;
    uint64_t gpu1Ns=0;
    uint64_t overlapNs=0;
    uint64_t hostSpinNs=0;
};

bool Deep2WaitDualQ4KFanIn(
    VulkanCompute& g0,VulkanCompute::Q4KAsyncTicket& t0,
    VulkanCompute& g1,VulkanCompute::Q4KAsyncTicket& t1,
    DualAsyncFanIn& out);

struct CachedDualRowPlan {
    RowSplitPlan split{};
    GpuWeightView gpu0{};
    GpuWeightView gpu1{};
    bool valid=false;
};

const CachedDualRowPlan* Deep2GetCachedDualRowPlan(
    const WeightTensor& wt,VulkanCompute& g0,VulkanCompute& g1);

// B4_LMHEAD_PERMANENT_RESIDENCY_001 helper: compute the CURRENT split
// geometry and build per-device weight views WITHOUT dispatching. Used by
// the lmHead pin path so pinning always matches the live split.
bool Deep2ProbeRowSplitViews(const WeightTensor& wt,
                              VulkanCompute& g0, VulkanCompute& g1,
                              GpuWeightView& out0, GpuWeightView& out1);

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

// Group 2-3 independent GEMVs that share one input activation.
// outputs[i] receives the full host-visible result for weights[i].
bool Deep2RunDualGpuRowSplitGroup(
    VulkanCompute& g0,
    VulkanCompute& g1,
    const WeightTensor* const* weights,
    float* const* outputs,
    size_t count,
    const float* input,
    uint32_t inputCount,
    uint64_t epoch,
    RowSplitReceipt* receipt = nullptr);

bool Deep2RunDualGpuRowSplitBatch4(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor& wt,
    const float* inputBatch,float* outputBatch,
    uint32_t batch,uint64_t epoch,
    RowSplitReceipt* receipt=nullptr);
bool Deep2RunDualGpuRowSplitBatch4PrimaryAssembled(
    VulkanCompute& primary,VulkanCompute& secondary,
    const WeightTensor& wt,const float* inputBatch,
    uint32_t batch,uint64_t epoch,
    VulkanCompute::DeviceBuf** fullOutput=nullptr);

bool Deep2RunDualGpuRowSplitBatchTop1(
    VulkanCompute& g0,VulkanCompute& g1,const WeightTensor& wt,
    const float* inputBatch,uint32_t batch,
    uint32_t* outToken,float* outValue,uint64_t epoch);
bool Deep2RunDualGpuColumnSplitBatch4(
    VulkanCompute& g0,VulkanCompute& g1,const WeightTensor& wt,
    const float* inputBatch,float* outputBatch,
    uint32_t batch,uint64_t epoch);
bool Deep2RunDualGpuColumnSplitBatch4PrimaryResident(
    VulkanCompute& primary,VulkanCompute& secondary,
    const WeightTensor& wt,const float* inputBatch,
    VulkanCompute::DeviceBuf& primaryOutput,
    uint32_t batch,uint64_t epoch);

bool Deep2RunDualGpuRowSplitBatchGroupQ4K(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor* const* weights,float* const* outputs,size_t weightCount,
    const float* inputBatch,uint32_t batch,uint64_t epoch);

struct DualRowTimingCounters {
    uint64_t calls = 0;
    uint64_t singleCalls = 0;
    uint64_t groupCalls = 0;

    uint64_t totalWallNs = 0;

    uint64_t executorWallNs = 0;
    uint64_t lane0HostEnvelopeNs = 0;
    uint64_t lane1HostEnvelopeNs = 0;
    uint64_t laneCriticalNs = 0;

    uint64_t hostMergeNs = 0;
    uint64_t overlapProbeNs = 0;
};

void Deep2ResetDualRowTiming() noexcept;
DualRowTimingCounters Deep2GetDualRowTiming() noexcept;

} // namespace Deep2
