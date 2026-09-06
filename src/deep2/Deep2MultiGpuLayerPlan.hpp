// Deep2MultiGpuLayerPlan.hpp — contiguous layer placement + real exec tracking
#pragma once
#include "Deep2DeviceManager.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct MultiGpuLayerPlan {
    unsigned openedCount = 0;     // VkDevices opened
    unsigned plannedCount = 0;    // slots with layer ranges (GPU + optional CPU)
    unsigned gpuSlotCount = 0;    // first gpuSlotCount slots are accelerators
    unsigned executingCount = 0;  // slots with real layer work observed
    unsigned layersExecuted = 0;  // forwardLayer completions on plan
    unsigned numLayers = 0;
    int layerDevice[256]{};       // layer -> slot
    uint8_t layerExecuted[256]{}; // 1 once forwardLayer finished for layer
    uint32_t slotLayerExecs[8]{}; // forwardLayer hits per slot
    uint64_t slotComputeOps[8]{}; // filled by cert from GEMV counters
    int openIndexes[8]{};
    char stableId[8][64]{};
    char name[8][128]{};
    unsigned score[8]{};
    uint64_t vramBytes[8]{};
    uint32_t rangeLo[8]{};
    uint32_t rangeHi[8]{};
    uint8_t isCpuSlot[8]{};
    bool active = false;
    bool hybrid = false; // CPU participates as planned compute
};

bool Deep2MultiGpu_BuildContiguousPlan(
    const DeviceManagerSnapshot& snap,
    unsigned numLayers,
    uint64_t bytesPerLayerEstimate,
    MultiGpuLayerPlan& out) noexcept;

// Steal trailing layers onto a planned CPU slot (hybrid). cpuLayers=0 → ~10%.
bool Deep2MultiGpu_AttachPlannedCpu(
    MultiGpuLayerPlan& plan,
    unsigned cpuLayers) noexcept;

int Deep2MultiGpu_SlotForLayer(const MultiGpuLayerPlan& plan, unsigned layer) noexcept;
bool Deep2MultiGpu_SlotIsCpu(const MultiGpuLayerPlan& plan, int slot) noexcept;

void Deep2MultiGpu_MarkLayerExecuted(MultiGpuLayerPlan& plan, unsigned layer) noexcept;
void Deep2MultiGpu_EmitPlanWitnesses(FILE* f, const MultiGpuLayerPlan& plan) noexcept;

} // namespace Deep2
