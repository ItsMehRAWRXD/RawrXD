// vulkan_fwd_cmdpool.cpp — recycled fused command buffers (no hotpath alloc)
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE

namespace CPUInference {

bool VulkanCompute::EnsureFusedPool() {
    if (fused_pool_ready_) return true;
    if (!device_ || !command_pool_) return false;
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 4;
    if (vkAllocateCommandBuffers(device_, &cai, fused_pool_) != VK_SUCCESS)
        return false;
    VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    fi.flags = VK_FENCE_CREATE_SIGNALED_BIT;
    for (uint32_t i = 0; i < 4; ++i) {
        if (vkCreateFence(device_, &fi, nullptr, &fused_fence_[i]) != VK_SUCCESS)
            return false;
    }
    fused_pool_ready_ = true;
    fused_cb_allocs_ += 4;
    return true;
}

bool VulkanCompute::SubmitFusedPool(VkCommandBuffer cmd, uint32_t idx) {
    if (!cmd || idx >= 4) return false;
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    vkResetFences(device_, 1, &fused_fence_[idx]);
    if (vkQueueSubmit(compute_queue_, 1, &si, fused_fence_[idx]) != VK_SUCCESS)
        return false;
    if (vkWaitForFences(device_, 1, &fused_fence_[idx], VK_TRUE,
                        30ull * 1000000000ull) != VK_SUCCESS)
        return false;
    ++op_submits_;
    return true;
}

bool VulkanCompute::BeginFusedLayer() {
    if (!device_ || fused_cmd_) return false;
    if (!EnsureFusedPool()) return false;
    const uint32_t i = fused_pool_i_;
    if (vkWaitForFences(device_, 1, &fused_fence_[i], VK_TRUE,
                        30ull * 1000000000ull) != VK_SUCCESS)
        return false;
    vkResetCommandBuffer(fused_pool_[i], 0);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(fused_pool_[i], &bi);
    fused_cmd_ = fused_pool_[i];
    fused_cmd_idx_ = i;
    fused_pool_i_ = (i + 1u) & 3u;
    ++fused_cb_reuses_;
    gemv_ds_cursor_ = 0;
    swiglu_ds_cursor_ = 0;
    saxpy_ds_cursor_ = 0;
    rms_use_ = 0;
    add_use_ = 0;
    ResetWeightWindowLayerCursor();
    return true;
}

bool VulkanCompute::FlushFusedRestart() {
    if (!fused_cmd_) return false;
    vkEndCommandBuffer(fused_cmd_);
    const uint32_t idx = fused_cmd_idx_;
    VkCommandBuffer cmd = fused_cmd_;
    fused_cmd_ = nullptr;
    if (!SubmitFusedPool(cmd, idx)) return false;
    ++layer_submits_;
    return BeginFusedLayer();
}

bool VulkanCompute::EndFusedLayer() {
    if (!fused_cmd_) return false;
    vkEndCommandBuffer(fused_cmd_);
    const uint32_t idx = fused_cmd_idx_;
    VkCommandBuffer cmd = fused_cmd_;
    fused_cmd_ = nullptr;
    const bool ok = SubmitFusedPool(cmd, idx);
    if (ok) ++layer_submits_;
    ResetWeightWindowLayerCursor();
    return ok;
}

} // namespace CPUInference
#endif
