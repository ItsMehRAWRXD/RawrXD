// ============================================================================
// flash_attention_vulkan_fp8.h — Parallel Vulkan + FP8 attention dispatch
// ============================================================================
// Intentionally separate from flash_attention_bridge.h (FP32 CPU path).
// Buffers are VkBuffer handles; push constants carry shapes + FP8 scales.
//
// RDNA 3: verify driver exposes the capabilities you compile for; WMMA FP8 is
// toolchain/driver-specific — validate fused kernels against host FP8 decode.
// ============================================================================

#pragma once

#include <cstdint>

extern "C" {
typedef struct VkBuffer_T* VkBuffer;
}

namespace RawrXD
{

/// Push constants for FP8 attention (match GLSL layout when binding pipeline).
struct FlashAttentionFP8PushConstants
{
    uint32_t seqLenM = 0;
    uint32_t seqLenN = 0;
    uint32_t headDim = 0;
    uint32_t numHeads = 0;
    uint32_t numKVHeads = 0;
    float qScale = 1.f;
    float kScale = 1.f;
    float vScale = 1.f;
};

bool DispatchFlashAttentionVulkanFP8(VkBuffer qBuffer, VkBuffer kBuffer, VkBuffer vBuffer, VkBuffer oBuffer,
                                     const FlashAttentionFP8PushConstants& constants);

}  // namespace RawrXD
