#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <vulkan/vulkan.h>
#ifdef _WIN32
#include <vulkan/vulkan_win32.h>
#endif
#include <vector>
#include <stdexcept>

class VulkanCompute {
private:
    VkInstance instance_;
    VkPhysicalDevice physicalDevice_;
    VkDevice device_;
    VkQueue computeQueue_;
    VkCommandPool commandPool_;
    VkCommandPool commandBufferPool_;
    std::vector<VkCommandBuffer> availableCommandBuffers_;
    uint32_t queueFamilyIndex_;
    
    bool CreateInstance();
    bool PickPhysicalDevice();
    bool CreateLogicalDevice();
    bool CreateCommandPool();
    void CleanupResources();
    
public:
    VulkanCompute();
    ~VulkanCompute();
    
    bool Initialize();
    void Cleanup();
    
    VkCommandBuffer AllocateCommandBuffer();
    void FreeCommandBuffer(VkCommandBuffer buffer);
    VkResult SubmitComputeCommand(VkCommandBuffer buffer, VkFence fence = VK_NULL_HANDLE);
    
    VkDevice GetDevice() const { return device_; }
    VkQueue GetComputeQueue() const { return computeQueue_; }
    uint32_t GetQueueFamilyIndex() const { return queueFamilyIndex_; }
};
