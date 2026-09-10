// K2QbHostShrinkD2h.hpp — PATH_A packed D2H record helpers
#pragma once
#include "vulkan_compute.h"
#include <cstdint>

namespace Deep2 {

bool K2_QbHostShrinkRecordCopies(CPUInference::VulkanCompute* vc, VkBuffer qOut,
                                 VkBuffer hostOut, uint32_t heads,
                                 uint32_t prodHead, uint32_t hostHead);

void K2_QbHostShrinkNoteReceipt(uint64_t beforeBytes, uint64_t afterBytes,
                                uint64_t fenceUs);

} // namespace Deep2
