// K2QbHostShrinkD2h.cpp — PATH_A: record only host-consumed q_b spans
#include "K2QbHostShrinkD2h.hpp"
#include "../runtime/QbHostReadbackWindow.hpp"

namespace Deep2 {

bool K2_QbHostShrinkRecordCopies(CPUInference::VulkanCompute* vc, VkBuffer qOut,
                                 VkBuffer hostOut, uint32_t heads,
                                 uint32_t prodHead, uint32_t hostHead) {
    if (!vc || !qOut || !hostOut || !heads || !hostHead || hostHead > prodHead)
        return false;
    for (uint32_t h = 0; h < heads; ++h) {
        const VkDeviceSize src = (VkDeviceSize)h * prodHead * 4ull;
        const VkDeviceSize dst = (VkDeviceSize)h * hostHead * 4ull;
        const VkDeviceSize nb = (VkDeviceSize)hostHead * 4ull;
        if (!vc->RecordCopy(qOut, hostOut, src, dst, nb)) return false;
    }
    return true;
}

void K2_QbHostShrinkNoteReceipt(uint64_t beforeBytes, uint64_t afterBytes,
                                uint64_t fenceUs) {
    rawrxd::runtime::QbHostReadbackReceipt rec{};
    rec.beforeBytes = beforeBytes;
    rec.afterBytes = afterBytes;
    rec.afterFenceNs = fenceUs * 1000ull;
    rec.d2hLegal = true;
    rec.productPath = true;
    rawrxd::runtime::QbHostReadback_Note(rec);
}

} // namespace Deep2
