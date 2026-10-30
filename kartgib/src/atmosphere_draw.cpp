#include "vulkan_renderer.hpp"
#include "atmosphere_push.hpp"
#include <stdexcept>
#include <vector>

void VulkanRenderer::destroyAtmospherePipeline() {
    if (atmospherePipeline_ != VK_NULL_HANDLE) {
        vkDestroyPipeline(device_, atmospherePipeline_, nullptr);
        atmospherePipeline_ = VK_NULL_HANDLE;
    }
    if (atmospherePipelineLayout_ != VK_NULL_HANDLE) {
        vkDestroyPipelineLayout(device_, atmospherePipelineLayout_, nullptr);
        atmospherePipelineLayout_ = VK_NULL_HANDLE;
    }
    if (atmosphereVertShaderModule_ != VK_NULL_HANDLE) {
        vkDestroyShaderModule(device_, atmosphereVertShaderModule_, nullptr);
        atmosphereVertShaderModule_ = VK_NULL_HANDLE;
    }
    if (atmosphereFragShaderModule_ != VK_NULL_HANDLE) {
        vkDestroyShaderModule(device_, atmosphereFragShaderModule_, nullptr);
        atmosphereFragShaderModule_ = VK_NULL_HANDLE;
    }
}

void VulkanRenderer::drawAtmosphere(float timeSeconds) {
    AtmospherePush push{};
    push.width = static_cast<float>(swapchainExtent_.width);
    push.height = static_cast<float>(swapchainExtent_.height);
    push.sunX = 0.55f;
    push.sunY = 0.38f;
    push.sunZ = 0.20f;
    push.time = timeSeconds;
    vkCmdBindPipeline(commandBuffers_[currentFrame_], VK_PIPELINE_BIND_POINT_GRAPHICS, atmospherePipeline_);
    VkViewport viewport{};
    viewport.width = push.width;
    viewport.height = push.height;
    viewport.maxDepth = 1.0f;
    vkCmdSetViewport(commandBuffers_[currentFrame_], 0, 1, &viewport);
    VkRect2D scissor{};
    scissor.extent = swapchainExtent_;
    vkCmdSetScissor(commandBuffers_[currentFrame_], 0, 1, &scissor);
    vkCmdPushConstants(commandBuffers_[currentFrame_], atmospherePipelineLayout_,
        VK_SHADER_STAGE_FRAGMENT_BIT, 0, sizeof(push), &push);
    vkCmdDraw(commandBuffers_[currentFrame_], 3, 1, 0, 0);
}

void VulkanRenderer::allocateFrameDescriptors() {
    descriptorSets_.assign(MAX_FRAMES_IN_FLIGHT, VK_NULL_HANDLE);
    std::vector<VkDescriptorSetLayout> layouts(MAX_FRAMES_IN_FLIGHT, descriptorSetLayout_);
    VkDescriptorSetAllocateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    info.descriptorPool = descriptorPool_;
    info.descriptorSetCount = MAX_FRAMES_IN_FLIGHT;
    info.pSetLayouts = layouts.data();
    if (vkAllocateDescriptorSets(device_, &info, descriptorSets_.data()) != VK_SUCCESS) {
        throw std::runtime_error("Failed to allocate frame descriptors");
    }
}

void VulkanRenderer::writeFrameDescriptor(const UniformBuffer& ubo) {
    VkDescriptorBufferInfo bufferInfo{};
    bufferInfo.buffer = ubo.buffer;
    bufferInfo.range = sizeof(UniformBufferObject);
    VkWriteDescriptorSet write{};
    write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    write.dstSet = descriptorSets_[currentFrame_];
    write.descriptorCount = 1;
    write.descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
    write.pBufferInfo = &bufferInfo;
    VkDescriptorImageInfo imageInfo{};
    imageInfo.sampler = shadowSampler_;
    imageInfo.imageView = shadowView_;
    imageInfo.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    VkWriteDescriptorSet imageWrite{};
    imageWrite.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    imageWrite.dstSet = descriptorSets_[currentFrame_];
    imageWrite.dstBinding = 1;
    imageWrite.descriptorCount = 1;
    imageWrite.descriptorType = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
    imageWrite.pImageInfo = &imageInfo;
    VkWriteDescriptorSet writes[2] = {write, imageWrite};
    vkUpdateDescriptorSets(device_, shadowSampler_ != VK_NULL_HANDLE ? 2u : 1u, writes, 0, nullptr);
}
