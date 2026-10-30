#include "vulkan_renderer.hpp"
#include <stdexcept>

void VulkanRenderer::createShadowResources() {
    VkImageCreateInfo image{};
    image.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    image.imageType = VK_IMAGE_TYPE_2D;
    image.extent = {2048, 2048, 1};
    image.mipLevels = 1; image.arrayLayers = 1; image.format = VK_FORMAT_D32_SFLOAT;
    image.tiling = VK_IMAGE_TILING_OPTIMAL; image.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    image.usage = VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT | VK_IMAGE_USAGE_SAMPLED_BIT;
    image.samples = VK_SAMPLE_COUNT_1_BIT;
    if (vkCreateImage(device_, &image, nullptr, &shadowImage_) != VK_SUCCESS) {
        throw std::runtime_error("Failed to create shadow image");
    }
    VkMemoryRequirements mem{};
    vkGetImageMemoryRequirements(device_, shadowImage_, &mem);
    VkMemoryAllocateInfo alloc{};
    alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc.allocationSize = mem.size;
    alloc.memoryTypeIndex = findMemoryType(mem.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (vkAllocateMemory(device_, &alloc, nullptr, &shadowMemory_) != VK_SUCCESS) {
        throw std::runtime_error("Failed to allocate shadow image");
    }
    vkBindImageMemory(device_, shadowImage_, shadowMemory_, 0);
    VkImageViewCreateInfo view{};
    view.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    view.image = shadowImage_;
    view.viewType = VK_IMAGE_VIEW_TYPE_2D;
    view.format = VK_FORMAT_D32_SFLOAT;
    view.subresourceRange.aspectMask = VK_IMAGE_ASPECT_DEPTH_BIT;
    view.subresourceRange.levelCount = 1;
    view.subresourceRange.layerCount = 1;
    if (vkCreateImageView(device_, &view, nullptr, &shadowView_) != VK_SUCCESS) {
        throw std::runtime_error("Failed to create shadow view");
    }
    VkSamplerCreateInfo sampler{};
    sampler.sType = VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;
    sampler.magFilter = VK_FILTER_LINEAR;
    sampler.minFilter = VK_FILTER_LINEAR;
    sampler.addressModeU = sampler.addressModeV = sampler.addressModeW = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    if (vkCreateSampler(device_, &sampler, nullptr, &shadowSampler_) != VK_SUCCESS) {
        throw std::runtime_error("Failed to create shadow sampler");
    }
    VkAttachmentDescription depth{};
    depth.format = VK_FORMAT_D32_SFLOAT;
    depth.samples = VK_SAMPLE_COUNT_1_BIT;
    depth.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    depth.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    depth.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    depth.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    depth.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    depth.finalLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    VkAttachmentReference ref{0, VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL};
    VkSubpassDescription sub{};
    sub.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    sub.pDepthStencilAttachment = &ref;
    VkSubpassDependency dep{};
    dep.srcSubpass = 0;
    dep.dstSubpass = VK_SUBPASS_EXTERNAL;
    dep.srcStageMask = VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT;
    dep.dstStageMask = VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT;
    dep.srcAccessMask = VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
    dep.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    VkRenderPassCreateInfo pass{};
    pass.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    pass.attachmentCount = 1;
    pass.pAttachments = &depth;
    pass.subpassCount = 1;
    pass.pSubpasses = &sub;
    pass.dependencyCount = 1;
    pass.pDependencies = &dep;
    if (vkCreateRenderPass(device_, &pass, nullptr, &shadowPass_) != VK_SUCCESS) {
        throw std::runtime_error("Failed to create shadow render pass");
    }
    VkFramebufferCreateInfo fb{};
    fb.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
    fb.renderPass = shadowPass_;
    fb.attachmentCount = 1;
    fb.pAttachments = &shadowView_;
    fb.width = 2048;
    fb.height = 2048;
    fb.layers = 1;
    if (vkCreateFramebuffer(device_, &fb, nullptr, &shadowFramebuffer_) != VK_SUCCESS) {
        throw std::runtime_error("Failed to create shadow framebuffer");
    }
    VkQueryPoolCreateInfo query{};
    query.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
    query.queryType = VK_QUERY_TYPE_TIMESTAMP;
    query.queryCount = 2;
    if (vkCreateQueryPool(device_, &query, nullptr, &timeQuery_) != VK_SUCCESS) {
        throw std::runtime_error("Failed to create timestamp query pool");
    }
    VkPhysicalDeviceProperties props{};
    vkGetPhysicalDeviceProperties(physicalDevice_, &props);
    timestampPeriod_ = props.limits.timestampPeriod;
    createShadowPipeline();
}
