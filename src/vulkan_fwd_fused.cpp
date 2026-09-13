// vulkan_fwd_fused.cpp — one command buffer per transformer layer
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "GpuTransferCounters.hpp"

namespace CPUInference {

bool VulkanCompute::FusedBarrier() {
    if (!fused_cmd_) return false;
    VkMemoryBarrier mb{};
    mb.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    mb.srcAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT |
                       VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_TRANSFER_WRITE_BIT;
    mb.dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT |
                       VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_TRANSFER_WRITE_BIT;
    vkCmdPipelineBarrier(fused_cmd_,
        VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT | VK_PIPELINE_STAGE_TRANSFER_BIT,
        VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT | VK_PIPELINE_STAGE_TRANSFER_BIT,
        0, 1, &mb, 0, nullptr, 0, nullptr);
    return true;
}

VkDescriptorSet VulkanCompute::NextGemvDs() {
    if (gemv_ds_n_ == 0) return gemv_ds_;
    VkDescriptorSet ds = gemv_ds_arr_[gemv_ds_cursor_ % gemv_ds_n_];
    ++gemv_ds_cursor_;
    ++gemv_desc_reuses_;
    return ds;
}

VkDescriptorSet VulkanCompute::NextSwigluDs() {
    if (swiglu_ds_n_ == 0) return swiglu_ds_;
    VkDescriptorSet ds = swiglu_ds_arr_[swiglu_ds_cursor_ % swiglu_ds_n_];
    ++swiglu_ds_cursor_;
    return ds;
}

VkDescriptorSet VulkanCompute::NextSaxpyDs() {
    if (saxpy_ds_n_ == 0) return saxpy_ds_;
    VkDescriptorSet ds = saxpy_ds_arr_[saxpy_ds_cursor_ % saxpy_ds_n_];
    ++saxpy_ds_cursor_;
    return ds;
}

bool VulkanCompute::EnsureFusedAuxDs() {
    if (!device_ || !swiglu_pool_ || !swiglu_dsl_ || !saxpy_pool_ || !saxpy_dsl_)
        return false;
    if (swiglu_ds_n_ >= 16 && saxpy_ds_n_ >= 16) return true;
    if (swiglu_ds_ && swiglu_ds_n_ == 0) {
        swiglu_ds_arr_[0] = swiglu_ds_;
        swiglu_ds_n_ = 1;
        VkDescriptorSetLayout layouts[15];
        for (int i = 0; i < 15; ++i) layouts[i] = swiglu_dsl_;
        VkDescriptorSetAllocateInfo dai{};
        dai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        dai.descriptorPool = swiglu_pool_;
        dai.descriptorSetCount = 15;
        dai.pSetLayouts = layouts;
        if (vkAllocateDescriptorSets(device_, &dai, &swiglu_ds_arr_[1]) !=
            VK_SUCCESS)
            return false;
        swiglu_ds_n_ = 16;
    }
    if (saxpy_ds_ && saxpy_ds_n_ == 0) {
        saxpy_ds_arr_[0] = saxpy_ds_;
        saxpy_ds_n_ = 1;
        VkDescriptorSetLayout layouts[15];
        for (int i = 0; i < 15; ++i) layouts[i] = saxpy_dsl_;
        VkDescriptorSetAllocateInfo dai{};
        dai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        dai.descriptorPool = saxpy_pool_;
        dai.descriptorSetCount = 15;
        dai.pSetLayouts = layouts;
        if (vkAllocateDescriptorSets(device_, &dai, &saxpy_ds_arr_[1]) !=
            VK_SUCCESS)
            return false;
        saxpy_ds_n_ = 16;
    }
    return swiglu_ds_n_ >= 16 && saxpy_ds_n_ >= 16;
}

bool VulkanCompute::RecordCompute(VkPipeline pipe, VkPipelineLayout layout,
                                  VkDescriptorSet ds, const void* pc,
                                  uint32_t pcBytes, uint32_t groupsX) {
    if (!pipe || !layout || !ds) return false;
    auto rec = [&](VkCommandBuffer cmd) {
        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, layout,
                                0, 1, &ds, 0, nullptr);
        if (pc && pcBytes)
            vkCmdPushConstants(cmd, layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, pcBytes, pc);
        vkCmdDispatch(cmd, groupsX, 1, 1);
    };
    if (fused_cmd_) { rec(fused_cmd_); return FusedBarrier(); }
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    rec(cmd);
    vkEndCommandBuffer(cmd);
    return SubmitOne(cmd);
}

bool VulkanCompute::RecordCopy(VkBuffer src, VkBuffer dst, VkDeviceSize srcOff,
                               VkDeviceSize dstOff, VkDeviceSize bytes) {
    if (!src || !dst || !bytes) return false;
    auto rec = [&](VkCommandBuffer cmd) {
        VkBufferCopy c{};
        c.srcOffset = srcOff; c.dstOffset = dstOff; c.size = bytes;
        vkCmdCopyBuffer(cmd, src, dst, 1, &c);
        Deep2::GpuTransfer_NoteCopy((uint64_t)bytes, Deep2::GpuCopyKind::Weight);
    };
    if (fused_cmd_) { rec(fused_cmd_); ++xfer_records_; return FusedBarrier(); }
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    rec(cmd);
    vkEndCommandBuffer(cmd);
    ++xfer_records_;
    ++xfer_submits_;
    return SubmitOne(cmd);
}

} // namespace CPUInference
#endif
