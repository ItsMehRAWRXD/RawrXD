// vulkan_fwd_quant.cpp — packed quant GEMV (stream slots or pin-resident)
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <cstdlib>

namespace CPUInference {

bool VulkanCompute::DispatchGemvQuant(int ggmlType, const void* packed, size_t bytes,
                                      DeviceBuf& in, DeviceBuf& out,
                                      uint32_t rows, uint32_t cols,
                                      uint64_t pinKey) {
    VkPipeline pipe = nullptr; uint64_t* ops = nullptr;
    if (!SelectPackedPipe(ggmlType, pipe, ops) || !in.buffer || !out.buffer ||
        !bytes)
        return false;
    /* Pin-hit may omit host packed (HOST_BYTES_FOR_HIT=0). */
    if (!packed &&
        !(pinKey && WantWeightPin() &&
          HasPinnedGemvWeight(pinKey, bytes, rows, cols)))
        return false;
    ++gemv_attempts_;
    VkBuffer wbuf = nullptr;
    if (WantWeightPin()) {
        uint64_t key = pinKey;
        if (!key && packed)
            key = (uint64_t)WeightContentFingerprint(packed, bytes) ^
                  ((uint64_t)rows * 0x100000001b3ull) ^
                  ((uint64_t)cols * 0xcbf29ce484222325ull) ^
                  ((uint64_t)bytes * 0x9e3779b97f4a7c15ull);
        if (!EnsurePinnedPackedWeight(packed, bytes, rows, cols, wbuf, key))
            return false;
    } else {
        if (!packed) return false;
        if (!ww_active_ || bytes > ww_slot_bytes_) {
            size_t budget =
                ww_budget_bytes_ ? ww_budget_bytes_ : ((size_t)512 << 20);
            uint32_t nSlots = ww_slot_count_ ? ww_slot_count_ : 8;
            size_t slotB = bytes > ww_slot_bytes_ ? bytes
                           : (ww_slot_bytes_ ? ww_slot_bytes_ : bytes);
            if (!EnsureWeightWindow(slotB, nSlots, budget)) return false;
        }
        if (!StreamWeightToSlot(packed, bytes, wbuf)) return false;
    }
    size_t range = (bytes + 3u) & ~size_t(3);
    if (!WantWeightPin() && ww_slot_bytes_ && range > ww_slot_bytes_)
        range = ww_slot_bytes_;
    if (!BindGemvStorage(wbuf, range, in.buffer, (size_t)cols * 4, out.buffer,
                         (size_t)rows * 4, pipe, rows, cols,
                         (rows + 63u) / 64u))
        return false;
    if (ops) ++(*ops);
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
