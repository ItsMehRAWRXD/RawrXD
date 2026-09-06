// Deep2MultiGpuLayerPlan.hpp — contiguous layer placement (no SKU hard-codes)
#pragma once
#include "Deep2DeviceManager.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct MultiGpuLayerPlan {
    unsigned openedCount = 0;     // VkDevices opened
    unsigned plannedCount = 0;    // slots with layer ranges
    unsigned executingCount = 0;  // filled by runtime after decode
    unsigned numLayers = 0;
    int layerDevice[256]{};       // layer -> slot [0..planned)
    int openIndexes[8]{};         // DXGI / DeviceManager indices
    char stableId[8][64]{};
    char name[8][128]{};
    unsigned score[8]{};
    uint64_t vramBytes[8]{};
    uint32_t rangeLo[8]{};
    uint32_t rangeHi[8]{};        // inclusive
    bool active = false;
};

// Contiguous split by relative score, then clamp to VRAM headroom.
// Requires snap.plan with openIndexes already selected (e.g. ALL / user list).
bool Deep2MultiGpu_BuildContiguousPlan(
    const DeviceManagerSnapshot& snap,
    unsigned numLayers,
    uint64_t bytesPerLayerEstimate,
    MultiGpuLayerPlan& out) noexcept;

int Deep2MultiGpu_SlotForLayer(const MultiGpuLayerPlan& plan, unsigned layer) noexcept;

void Deep2MultiGpu_EmitPlanWitnesses(FILE* f, const MultiGpuLayerPlan& plan) noexcept;

} // namespace Deep2
