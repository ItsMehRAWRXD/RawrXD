#include "ocean_field.hpp"
#include "vulkan_renderer.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>

float oceanGpuReadback(VulkanRenderer& renderer, VkPipeline pipeline, VkPipelineLayout layout, VkDescriptorSet sets[2], VkDeviceMemory memory, int n, const std::vector<Cx>& cpu) {
    VkDevice device = renderer.getDevice();
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    VkCommandBufferAllocateInfo cmdInfo{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cmdInfo.commandPool = renderer.getCommandPool();
    cmdInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cmdInfo.commandBufferCount = 1;
    vkAllocateCommandBuffers(device, &cmdInfo, &cmd);
    VkCommandBufferBeginInfo begin{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    vkBeginCommandBuffer(cmd, &begin);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    for (int pass = 0; pass < 2; ++pass) {
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, layout, 0, 1, &sets[pass], 0, nullptr);
        int push[2] = {n, pass};
        vkCmdPushConstants(cmd, layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 8, push);
        vkCmdDispatch(cmd, static_cast<uint32_t>(n / 8), static_cast<uint32_t>(n / 8), 1);
        VkMemoryBarrier barrier{VK_STRUCTURE_TYPE_MEMORY_BARRIER};
        barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &barrier, 0, nullptr, 0, nullptr);
    }
    vkEndCommandBuffer(cmd);
    VkSubmitInfo submit{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &cmd;
    vkQueueSubmit(renderer.getGraphicsQueue(), 1, &submit, VK_NULL_HANDLE);
    vkQueueWaitIdle(renderer.getGraphicsQueue());
    vkFreeCommandBuffers(device, renderer.getCommandPool(), 1, &cmd);
    void* mapped = nullptr;
    vkMapMemory(device, memory, 0, sizeof(Cx) * static_cast<size_t>(n * n), 0, &mapped);
    auto* gpu = static_cast<Cx*>(mapped);
    float maxError = 0;
    for (int i = 0; i < n * n; ++i) maxError = std::max(maxError, std::fabs(gpu[i].r - cpu[i].r) + std::fabs(gpu[i].i - cpu[i].i));
    vkUnmapMemory(device, memory);
    std::cout << "[OCEAN] gpu_error=" << maxError << std::endl;
    return maxError;
}
