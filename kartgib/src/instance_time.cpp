#include "vulkan_renderer.hpp"

void VulkanRenderer::collectProductTime() {
    if (productQuery_ == VK_NULL_HANDLE || instCount_ == 0) return;
    uint64_t stamps[2] = {};
    if (vkGetQueryPoolResults(device_, productQuery_, 0, 2, sizeof(stamps), stamps, 8,
        VK_QUERY_RESULT_64_BIT) != VK_SUCCESS) return;
    instGpuMs_ = static_cast<float>(stamps[1] - stamps[0]) * timestampPeriod_ / 1.0e6f;
}

void VulkanRenderer::destroyProductPipeline() {
    if (device_ == VK_NULL_HANDLE) return;
    if (productQuery_) vkDestroyQueryPool(device_, productQuery_, nullptr);
    if (productPipeline_) vkDestroyPipeline(device_, productPipeline_, nullptr);
    VkBuffer bufs[] = {grassVb_, grassIb_, hudVb_, hudIb_, instVb_};
    VkDeviceMemory mems[] = {grassMem_, grassIndexMem_, hudMem_, hudIndexMem_, instMem_};
    for (int i = 0; i < 5; ++i) {
        if (bufs[i]) vkDestroyBuffer(device_, bufs[i], nullptr);
        if (mems[i]) vkFreeMemory(device_, mems[i], nullptr);
    }
    productQuery_ = VK_NULL_HANDLE;
    productPipeline_ = VK_NULL_HANDLE;
    grassVb_ = grassIb_ = hudVb_ = hudIb_ = instVb_ = VK_NULL_HANDLE;
    grassMem_ = VK_NULL_HANDLE;
    grassIndexMem_ = VK_NULL_HANDLE;
    hudMem_ = VK_NULL_HANDLE;
    hudIndexMem_ = VK_NULL_HANDLE;
    instMem_ = VK_NULL_HANDLE;
}

void VulkanRenderer::noteCpuMs(float ms) {
    if (cpuCount_ == 0) cpuMinMs_ = cpuMaxMs_ = ms;
    else { if (ms < cpuMinMs_) cpuMinMs_ = ms; if (ms > cpuMaxMs_) cpuMaxMs_ = ms; }
    cpuSumMs_ += ms; ++cpuCount_;
}
