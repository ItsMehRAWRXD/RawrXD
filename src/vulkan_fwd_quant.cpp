// vulkan_fwd_quant.cpp — packed quant GEMV into bounded weight slots
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <cstdlib>

namespace CPUInference {

bool VulkanCompute::DispatchGemvQuant(int ggmlType, const void* packed, size_t bytes,
                                      DeviceBuf& in, DeviceBuf& out,
                                      uint32_t rows, uint32_t cols) {
    VkPipeline pipe = nullptr; uint64_t* ops = nullptr;
    if (!SelectPackedPipe(ggmlType, pipe, ops) || !packed || !in.buffer || !out.buffer || !bytes)
        return false;
    ++gemv_attempts_;
    VkBuffer wbuf = nullptr;
    if (!ww_active_ || bytes > ww_slot_bytes_) {
        size_t budget = ww_budget_bytes_ ? ww_budget_bytes_ : ((size_t)512 << 20);
        uint32_t nSlots = ww_slot_count_ ? ww_slot_count_ : 8;
        size_t slotB = bytes > ww_slot_bytes_ ? bytes
                       : (ww_slot_bytes_ ? ww_slot_bytes_ : bytes);
        if (!EnsureWeightWindow(slotB, nSlots, budget)) return false;
    }
    if (!StreamWeightToSlot(packed, bytes, wbuf)) return false;
    size_t range = (bytes + 3u) & ~size_t(3);
    if (ww_slot_bytes_ && range > ww_slot_bytes_) range = ww_slot_bytes_;
    if (!BindGemvStorage(wbuf, range, in.buffer, (size_t)cols * 4, out.buffer,
                         (size_t)rows * 4, pipe, rows, cols, (rows + 63u) / 64u))
        return false;
    if (ops) ++(*ops);
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
