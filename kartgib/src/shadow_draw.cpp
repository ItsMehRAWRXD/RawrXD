#include "vulkan_renderer.hpp"

void VulkanRenderer::destroyShadowResources() {
    if (device_ == VK_NULL_HANDLE) return;
    if (timeQuery_ != VK_NULL_HANDLE) vkDestroyQueryPool(device_, timeQuery_, nullptr);
    if (shadowPipeline_ != VK_NULL_HANDLE) vkDestroyPipeline(device_, shadowPipeline_, nullptr);
    if (shadowLayout_ != VK_NULL_HANDLE) vkDestroyPipelineLayout(device_, shadowLayout_, nullptr);
    if (shadowVertModule_ != VK_NULL_HANDLE) vkDestroyShaderModule(device_, shadowVertModule_, nullptr);
    if (shadowFragModule_ != VK_NULL_HANDLE) vkDestroyShaderModule(device_, shadowFragModule_, nullptr);
    if (shadowFramebuffer_ != VK_NULL_HANDLE) vkDestroyFramebuffer(device_, shadowFramebuffer_, nullptr);
    if (shadowPass_ != VK_NULL_HANDLE) vkDestroyRenderPass(device_, shadowPass_, nullptr);
    if (shadowSampler_ != VK_NULL_HANDLE) vkDestroySampler(device_, shadowSampler_, nullptr);
    if (shadowView_ != VK_NULL_HANDLE) vkDestroyImageView(device_, shadowView_, nullptr);
    if (shadowImage_ != VK_NULL_HANDLE) vkDestroyImage(device_, shadowImage_, nullptr);
    if (shadowMemory_ != VK_NULL_HANDLE) vkFreeMemory(device_, shadowMemory_, nullptr);
    timeQuery_ = VK_NULL_HANDLE;
    shadowPipeline_ = VK_NULL_HANDLE;
    shadowLayout_ = VK_NULL_HANDLE;
    shadowVertModule_ = VK_NULL_HANDLE;
    shadowFragModule_ = VK_NULL_HANDLE;
    shadowFramebuffer_ = VK_NULL_HANDLE;
    shadowPass_ = VK_NULL_HANDLE;
    shadowSampler_ = VK_NULL_HANDLE;
    shadowView_ = VK_NULL_HANDLE;
    shadowImage_ = VK_NULL_HANDLE;
    shadowMemory_ = VK_NULL_HANDLE;
}

void VulkanRenderer::recordShadowPass(VkCommandBuffer cmd, VkBuffer vertexBuffer,
    VkBuffer indexBuffer, uint32_t indexCount, const UniformBufferObject& ubo) {
    VkClearValue clear{};
    clear.depthStencil = {1.0f, 0};
    VkRenderPassBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    begin.renderPass = shadowPass_;
    begin.framebuffer = shadowFramebuffer_;
    begin.renderArea.extent = {2048, 2048};
    begin.clearValueCount = 1;
    begin.pClearValues = &clear;
    vkCmdBeginRenderPass(cmd, &begin, VK_SUBPASS_CONTENTS_INLINE);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, shadowPipeline_);
    VkDeviceSize offsets[] = {0};
    vkCmdBindVertexBuffers(cmd, 0, 1, &vertexBuffer, offsets);
    vkCmdBindIndexBuffer(cmd, indexBuffer, 0, VK_INDEX_TYPE_UINT32);
    for (int c = 0; c < 4; ++c) {
        VkViewport viewport{};
        viewport.x = static_cast<float>((c & 1) * 1024);
        viewport.y = static_cast<float>((c >> 1) * 1024);
        viewport.width = 1024.0f;
        viewport.height = 1024.0f;
        viewport.maxDepth = 1.0f;
        vkCmdSetViewport(cmd, 0, 1, &viewport);
        VkRect2D scissor{};
        scissor.offset = { (c & 1) * 1024, (c >> 1) * 1024 };
        scissor.extent = {1024, 1024};
        vkCmdSetScissor(cmd, 0, 1, &scissor);
        vkCmdPushConstants(cmd, shadowLayout_, VK_SHADER_STAGE_VERTEX_BIT, 0, sizeof(float) * 16,
            ubo.cascadeVp[c]);
        vkCmdDrawIndexed(cmd, indexCount, 1, 0, 0, 0);
    }
    vkCmdEndRenderPass(cmd);
}

void VulkanRenderer::collectGpuTime() {
    if (timeQuery_ == VK_NULL_HANDLE) return;
    uint64_t stamps[2] = {};
    VkResult result = vkGetQueryPoolResults(device_, timeQuery_, 0, 2, sizeof(stamps), stamps,
        sizeof(uint64_t), VK_QUERY_RESULT_64_BIT);
    if (result == VK_SUCCESS && stamps[1] > stamps[0]) {
        lastGpuMs_ = static_cast<float>((stamps[1] - stamps[0]) * static_cast<double>(timestampPeriod_) / 1.0e6);
    }
}
