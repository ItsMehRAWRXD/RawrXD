// vulkan_weight_policy.cpp — STREAMER_GPU_DYNAMIC_WINDOW_001 slot policy
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#include <cstdlib>

namespace CPUInference {

size_t VulkanCompute::ForwardArenaReserveBytes(uint32_t hidden, uint32_t inter,
    uint32_t nHeads, uint32_t nKv, uint32_t headDim, uint32_t maxSeq, uint32_t nLayers)
{
    if (!nLayers) nLayers = 1;
    const uint32_t kvDim = nKv * headDim;
    const size_t hb = (size_t)hidden * 4u;
    const size_t ib = (size_t)inter * 4u;
    const size_t qb = (size_t)nHeads * headDim * 4u;
    const size_t kb = (size_t)kvDim * 4u;
    const size_t cb = (size_t)nLayers * maxSeq * kvDim * 4u;
    return 6u * hb + 2u * qb + 2u * kb + 3u * ib + 2u * cb;
}

bool VulkanCompute::ChooseWeightWindow(size_t maxPacked, size_t envBudget, uint32_t envSlots,
                                       size_t arenaReserve, size_t deviceHeap,
                                       uint32_t& slotCount, size_t& usableOut)
{
    slotCount = 0; usableOut = 0;
    if (maxPacked == 0) return false;
    size_t usable = envBudget ? envBudget : ((size_t)512 << 20);
    if (deviceHeap) {
        size_t head = deviceHeap / 20u;
        if (head < ((size_t)64 << 20)) head = (size_t)64 << 20;
        if (head > ((size_t)256 << 20)) head = (size_t)256 << 20;
        size_t cap = deviceHeap;
        if (cap > arenaReserve) cap -= arenaReserve; else cap = 0;
        if (cap > head) cap -= head; else cap = 0;
        if (usable > cap) usable = cap;
    }
    usableOut = usable;
    if (envSlots) {
        if (envSlots < kWeightMinSlots || envSlots > kWeightMaxSlots) return false;
        if ((uint64_t)envSlots * maxPacked > usable) return false;
        slotCount = envSlots;
        return true;
    }
    uint32_t n = (uint32_t)(usable / maxPacked);
    if (n > kWeightMaxSlots) n = kWeightMaxSlots;
    if (n < kWeightMinSlots) return false;
    if ((uint64_t)n * maxPacked > usable) return false;
    slotCount = n;
    return true;
}

#if RAWR_VULKAN_AVAILABLE
size_t VulkanCompute::DeviceLocalHeapBytes() const {
    size_t best = 0;
    const auto& mp = device_info_.memory_props;
    for (uint32_t i = 0; i < mp.memoryHeapCount; ++i) {
        if (mp.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            const size_t s = (size_t)mp.memoryHeaps[i].size;
            if (s > best) best = s;
        }
    }
    return best;
}

bool VulkanCompute::ApplyWeightWindowPolicy(size_t maxPacked, size_t envBudget,
                                            uint32_t envSlots, size_t arenaReserve)
{
    uint32_t n = 0; size_t usable = 0;
    const size_t heap = DeviceLocalHeapBytes();
    if (!ChooseWeightWindow(maxPacked, envBudget, envSlots, arenaReserve, heap, n, usable))
        return false;
    ww_slots_auto_ = (envSlots == 0);
    ww_usable_budget_ = usable;
    ww_arena_reserve_ = arenaReserve;
    ww_device_heap_ = heap;
    if (ww_active_ && ww_slot_bytes_ == maxPacked && ww_slot_count_ == n &&
        ww_budget_bytes_ == usable)
        return true;
    if (fused_cmd_) { ++ww_growth_after_init_; return false; }
    if (ww_active_) {
        ReleaseWeightWindow();
        ww_init_done_ = false;
        ww_slot_allocs_ = 0;
        ww_stream_bytes_total_ = 0;
    }
    return EnsureWeightWindow(maxPacked, n, usable);
}
#endif

} // namespace CPUInference
