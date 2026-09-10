// K2QbGemvDirectHost.hpp — PATH_A D2H window; PATH_B skips q_b host copy
#pragma once
#include "K2QbHostShrinkD2h.hpp"
#include "K2MLA_PathB.hpp"
#include "vulkan_compute.h"
#include <cstdint>

namespace Deep2 {

inline bool K2_QbGemvToHostOrShrink(
    CPUInference::VulkanCompute* vc, const void* wQb, size_t wBytes,
    CPUInference::VulkanCompute::DeviceBuf& aIn,
    CPUInference::VulkanCompute::DeviceBuf& aOut,
    CPUInference::VulkanCompute::DeviceBuf& normBuf, bool haveNorm,
    uint32_t qBCols, uint32_t qLora, float eps, uint64_t pkB, bool shrink,
    uint32_t heads, uint32_t prodHead, uint32_t hostHead, size_t hostOutB) {
    const VkBuffer hostOut = vc->GemvHostOutBuffer();
    VkBuffer qDev = nullptr;
    if (haveNorm) {
        if (!vc->DispatchRmsNorm(aOut, normBuf, aIn, qLora, eps)) return false;
        if (!vc->DispatchGemvPacked(wQb, wBytes, aIn, aOut, qBCols, qLora, pkB))
            return false;
        qDev = aOut.buffer;
    } else {
        if (!vc->DispatchGemvPacked(wQb, wBytes, aOut, aIn, qBCols, qLora, pkB))
            return false;
        qDev = aIn.buffer;
    }
    if (PathBWanted()) {
        PathB_NoteQDev(haveNorm ? aOut : aIn, (size_t)qBCols * 4ull);
        if (PathB_QDev()) {
            (void)qDev; (void)hostOut; (void)hostOutB; (void)shrink;
            (void)heads; (void)prodHead; (void)hostHead;
            return true; // q stashed DEVICE_LOCAL — no q_b D2H
        }
        // stash failed → PATH_A host window
    }
    if (shrink)
        return K2_QbHostShrinkRecordCopies(vc, qDev, hostOut, heads, prodHead,
                                           hostHead);
    (void)hostOutB;
    return vc->RecordCopy(qDev, hostOut, 0, 0, (VkDeviceSize)qBCols * 4ull);
}

} // namespace Deep2
