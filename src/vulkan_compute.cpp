#include "vulkan_compute.h"
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <algorithm>

#if RAWR_VULKAN_AVAILABLE && defined(_WIN32)
#include <vulkan/vulkan_win32.h>
#endif

VulkanCompute::VulkanCompute() 
    : instance_(VK_NULL_HANDLE)
    , physicalDevice_(VK_NULL_HANDLE)
    , device_(VK_NULL_HANDLE)
    , computeQueue_(VK_NULL_HANDLE)
    , commandPool_(VK_NULL_HANDLE)
    , commandBufferPool_(VK_NULL_HANDLE)
    , queueFamilyIndex_(0)
{
}

VulkanCompute::~VulkanCompute() {
    Cleanup();
}

bool VulkanCompute::Initialize() {
    try {
        if (!CreateInstance()) throw std::runtime_error("Failed to create Vulkan instance");
        if (!PickPhysicalDevice()) throw std::runtime_error("Failed to find suitable GPU");
        if (!CreateLogicalDevice()) throw std::runtime_error("Failed to create logical device");
        if (!CreateCommandPool()) throw std::runtime_error("Failed to create command pool");
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "VulkanCompute initialization failed: " << e.what() << std::endl;
        Cleanup();
        return false;
    }
}

void VulkanCompute::Cleanup() {
    CleanupResources();
}

void VulkanCompute::CleanupResources() {
    if (device_ != VK_NULL_HANDLE) {
        vkDeviceWaitIdle(device_);
        
        for (auto buffer : availableCommandBuffers_) {
            vkFreeCommandBuffers(device_, commandPool_, 1, &buffer);
        }
        availableCommandBuffers_.clear();
        
        if (commandPool_ != VK_NULL_HANDLE) {
            vkDestroyCommandPool(device_, commandPool_, nullptr);
            commandPool_ = VK_NULL_HANDLE;
        }
        
        if (commandBufferPool_ != VK_NULL_HANDLE) {
            vkDestroyCommandPool(device_, commandBufferPool_, nullptr);
            commandBufferPool_ = VK_NULL_HANDLE;
        }
        
        vkDestroyDevice(device_, nullptr);
        device_ = VK_NULL_HANDLE;
    }
    
    if (instance_ != VK_NULL_HANDLE) {
        vkDestroyInstance(instance_, nullptr);
        instance_ = VK_NULL_HANDLE;
    }
    
    physicalDevice_ = VK_NULL_HANDLE;
    computeQueue_ = VK_NULL_HANDLE;
    queueFamilyIndex_ = 0;
}

VkCommandBuffer VulkanCompute::AllocateCommandBuffer() {
    if (device_ == VK_NULL_HANDLE || commandPool_ == VK_NULL_HANDLE) {
        return VK_NULL_HANDLE;
    }
    
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = commandPool_;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    
    VkCommandBuffer commandBuffer;
    VkResult result = vkAllocateCommandBuffers(device_, &allocInfo, &commandBuffer);
    
    if (result == VK_SUCCESS) {
        availableCommandBuffers_.push_back(commandBuffer);
        return commandBuffer;
    }
    
    return VK_NULL_HANDLE;
}

void VulkanCompute::FreeCommandBuffer(VkCommandBuffer buffer) {
    if (buffer == VK_NULL_HANDLE || device_ == VK_NULL_HANDLE || commandPool_ == VK_NULL_HANDLE) {
        return;
    }
    
    auto it = std::find(availableCommandBuffers_.begin(), availableCommandBuffers_.end(), buffer);
    if (it != availableCommandBuffers_.end()) {
        vkFreeCommandBuffers(device_, commandPool_, 1, &buffer);
        availableCommandBuffers_.erase(it);
    }
}

VkResult VulkanCompute::SubmitComputeCommand(VkCommandBuffer buffer, VkFence fence) {
    if (buffer == VK_NULL_HANDLE || device_ == VK_NULL_HANDLE) {
        return VK_ERROR_INITIALIZATION_FAILED;
    }
    
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &buffer;
    
    return vkQueueSubmit(computeQueue_, 1, &submitInfo, fence);
}

bool VulkanCompute::CreateInstance() {
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD Compute";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_2;
    
    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;
    
#ifdef _DEBUG
    const char* validationLayers[] = { "VK_LAYER_KHRONOS_validation" };
    createInfo.enabledLayerCount = 1;
    createInfo.ppEnabledLayerNames = validationLayers;
#endif
    
    const char* extensions[] = { VK_KHR_SURFACE_EXTENSION_NAME };
#ifdef _WIN32
    extensions[0] = VK_KHR_WIN32_SURFACE_EXTENSION_NAME;
#endif
    createInfo.enabledExtensionCount = 1;
    createInfo.ppEnabledExtensionNames = extensions;
    
    return vkCreateInstance(&createInfo, nullptr, &instance_) == VK_SUCCESS;
}

bool VulkanCompute::PickPhysicalDevice() {
    if (instance_ == VK_NULL_HANDLE) return false;
    
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance_, &deviceCount, nullptr);
    
    if (deviceCount == 0) {
        std::cerr << "Failed to find GPUs with Vulkan support!" << std::endl;
        return false;
    }
    
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance_, &deviceCount, devices.data());
    
    for (const auto& device : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(device, &props);
        
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            physicalDevice_ = device;
            return true;
        }
    }
    
    physicalDevice_ = devices[0];
    return true;
}

bool VulkanCompute::CreateLogicalDevice() {
    if (physicalDevice_ == VK_NULL_HANDLE) return false;
    
    uint32_t queueFamilyCount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice_, &queueFamilyCount, nullptr);
    
    std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
    vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice_, &queueFamilyCount, queueFamilies.data());
    
    int32_t computeFamilyIndex = -1;
    for (uint32_t i = 0; i < queueFamilyCount; ++i) {
        if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            computeFamilyIndex = static_cast<int32_t>(i);
            break;
        }
    }
    
    if (computeFamilyIndex == -1) {
        for (uint32_t i = 0; i < queueFamilyCount; ++i) {
            if (queueFamilies[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
                computeFamilyIndex = static_cast<int32_t>(i);
                break;
            }
        }
    }
    
    if (computeFamilyIndex == -1) return false;
    queueFamilyIndex_ = static_cast<uint32_t>(computeFamilyIndex);
    
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueInfo{};
    queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = queueFamilyIndex_;
    queueInfo.queueCount = 1;
    queueInfo.pQueuePriorities = &queuePriority;
    
    VkPhysicalDeviceFeatures deviceFeatures{};
    const char* deviceExtensions[] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };
    
    VkDeviceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    createInfo.queueCreateInfoCount = 1;
    createInfo.pQueueCreateInfos = &queueInfo;
    createInfo.pEnabledFeatures = &deviceFeatures;
    createInfo.enabledExtensionCount = 1;
    createInfo.ppEnabledExtensionNames = deviceExtensions;
    
#ifdef _DEBUG
    const char* validationLayers[] = { "VK_LAYER_KHRONOS_validation" };
    createInfo.enabledLayerCount = 1;
    createInfo.ppEnabledLayerNames = validationLayers;
#endif
    
    if (vkCreateDevice(physicalDevice_, &createInfo, nullptr, &device_) != VK_SUCCESS) {
        return false;
    }
    
    vkGetDeviceQueue(device_, queueFamilyIndex_, 0, &computeQueue_);
    return true;
}

bool VulkanCompute::CreateCommandPool() {
    if (device_ == VK_NULL_HANDLE || queueFamilyIndex_ >= VK_MAX_MEMORY_TYPES) {
        return false;
    }
    
    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = queueFamilyIndex_;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    
    return vkCreateCommandPool(device_, &poolInfo, nullptr, &commandPool_) == VK_SUCCESS;
}
