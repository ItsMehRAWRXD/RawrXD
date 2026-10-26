#include "vulkan_renderer.hpp"
#include <iostream>
#include <stdexcept>

void VulkanRenderer::setG04Sample(bool enable, bool skipAtmosphere, const char* label) {
    g04Sample_ = enable;
    g04SkipAtmosphere_ = skipAtmosphere;
    g04Label_ = label != nullptr ? label : "frame";
    std::cout << "[G04] Pixel sample armed label=" << g04Label_ << std::endl;
}

void VulkanRenderer::recordG04Readback(VkCommandBuffer cmd, uint32_t imageIndex) {
    if (!swapchainTransferSrc_) {
        std::cout << "[G04] Readback blocked: swapchain lacks TRANSFER_SRC" << std::endl;
        g04Sample_ = false;
        return;
    }
    if (g04Buffer_ != VK_NULL_HANDLE || swapchainExtent_.width == 0 || swapchainExtent_.height == 0) {
        return;
    }
    g04Width_ = swapchainExtent_.width;
    g04Height_ = swapchainExtent_.height;
    VkDeviceSize bytes = static_cast<VkDeviceSize>(g04Width_) * g04Height_ * 4;
    createBuffer(bytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
        g04Buffer_, g04Memory_);

    VkImageMemoryBarrier toSrc{};
    toSrc.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    toSrc.srcAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    toSrc.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    toSrc.oldLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    toSrc.newLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
    toSrc.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    toSrc.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    toSrc.image = swapchainImages_[imageIndex];
    toSrc.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    toSrc.subresourceRange.levelCount = 1;
    toSrc.subresourceRange.layerCount = 1;
    vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, nullptr, 0, nullptr, 1, &toSrc);

    VkBufferImageCopy region{};
    region.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    region.imageSubresource.layerCount = 1;
    region.imageExtent = {g04Width_, g04Height_, 1};
    vkCmdCopyImageToBuffer(cmd, swapchainImages_[imageIndex],
        VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, g04Buffer_, 1, &region);

    VkImageMemoryBarrier toPresent = toSrc;
    toPresent.srcAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    toPresent.dstAccessMask = 0;
    toPresent.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
    toPresent.newLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT,
        VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0, 0, nullptr, 0, nullptr, 1, &toPresent);
    std::cout << "[G04] Readback copy recorded " << g04Width_ << "x" << g04Height_ << std::endl;
}
