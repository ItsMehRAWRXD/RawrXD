// ============================================================================
// vulkan_runtime_loader.hpp - Runtime Vulkan Loader
// ============================================================================
// Zero-dependency runtime loading of vulkan-1.dll
// No Vulkan SDK required at build time
// ============================================================================

#pragma once

#include <windows.h>
#include <cstdint>
#include <cstddef>

// Minimal Vulkan types (ABI-compatible)
typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;
typedef uint32_t VkResult;

// Handle types
VK_DEFINE_HANDLE(VkInstance)
VK_DEFINE_HANDLE(VkPhysicalDevice)
VK_DEFINE_HANDLE(VkDevice)
VK_DEFINE_HANDLE(VkQueue)
VK_DEFINE_HANDLE(VkCommandBuffer)
VK_DEFINE_HANDLE(VkPipeline)
VK_DEFINE_HANDLE(VkShaderModule)
VK_DEFINE_HANDLE(VkBuffer)
VK_DEFINE_HANDLE(VkDeviceMemory)
VK_DEFINE_HANDLE(VkDescriptorSet)
VK_DEFINE_HANDLE(VkDescriptorSetLayout)
VK_DEFINE_HANDLE(VkDescriptorPool)
VK_DEFINE_HANDLE(VkCommandPool)
VK_DEFINE_HANDLE(VkFence)
VK_DEFINE_HANDLE(VkSemaphore)

// Result codes
#define VK_SUCCESS 0
#define VK_NOT_READY 1
#define VK_TIMEOUT 2
#define VK_EVENT_SET 3
#define VK_EVENT_RESET 4
#define VK_INCOMPLETE 5
#define VK_ERROR_OUT_OF_HOST_MEMORY -1
#define VK_ERROR_OUT_OF_DEVICE_MEMORY -2
#define VK_ERROR_INITIALIZATION_FAILED -3
#define VK_ERROR_DEVICE_LOST -4
#define VK_ERROR_MEMORY_MAP_FAILED -5
#define VK_ERROR_LAYER_NOT_PRESENT -6
#define VK_ERROR_EXTENSION_NOT_PRESENT -7
#define VK_ERROR_FEATURE_NOT_PRESENT -8
#define VK_ERROR_INCOMPATIBLE_DRIVER -9

// Structure types
#define VK_STRUCTURE_TYPE_APPLICATION_INFO 0
#define VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO 1
#define VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO 2
#define VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO 3

// Queue flags
#define VK_QUEUE_GRAPHICS_BIT 0x00000001
#define VK_QUEUE_COMPUTE_BIT 0x00000002
#define VK_QUEUE_TRANSFER_BIT 0x00000004

namespace RawrXD {
namespace GPU {

// ============================================================================
// Vulkan Function Pointer Types
// ============================================================================

typedef VkResult (*PFN_vkCreateInstance)(const void* pCreateInfo, const void* pAllocator, VkInstance* pInstance);
typedef void (*PFN_vkDestroyInstance)(VkInstance instance, const void* pAllocator);
typedef VkResult (*PFN_vkEnumeratePhysicalDevices)(VkInstance instance, uint32_t* pPhysicalDeviceCount, VkPhysicalDevice* pPhysicalDevices);
typedef void (*PFN_vkGetPhysicalDeviceProperties)(VkPhysicalDevice physicalDevice, void* pProperties);
typedef void (*PFN_vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice physicalDevice, uint32_t* pQueueFamilyPropertyCount, void* pQueueFamilyProperties);
typedef VkResult (*PFN_vkCreateDevice)(VkPhysicalDevice physicalDevice, const void* pCreateInfo, const void* pAllocator, VkDevice* pDevice);
typedef void (*PFN_vkDestroyDevice)(VkDevice device, const void* pAllocator);
typedef void (*PFN_vkGetDeviceQueue)(VkDevice device, uint32_t queueFamilyIndex, uint32_t queueIndex, VkQueue* pQueue);
typedef VkResult (*PFN_vkCreateBuffer)(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkBuffer* pBuffer);
typedef void (*PFN_vkDestroyBuffer)(VkDevice device, VkBuffer buffer, const void* pAllocator);
typedef VkResult (*PFN_vkAllocateMemory)(VkDevice device, const void* pAllocateInfo, const void* pAllocator, VkDeviceMemory* pMemory);
typedef void (*PFN_vkFreeMemory)(VkDevice device, VkDeviceMemory memory, const void* pAllocator);
typedef VkResult (*PFN_vkBindBufferMemory)(VkDevice device, VkBuffer buffer, VkDeviceMemory memory, VkDeviceSize memoryOffset);
typedef void* (*PFN_vkMapMemory)(VkDevice device, VkDeviceMemory memory, VkDeviceSize offset, VkDeviceSize size, VkFlags flags);
typedef void (*PFN_vkUnmapMemory)(VkDevice device, VkDeviceMemory memory);
typedef VkResult (*PFN_vkFlushMappedMemoryRanges)(VkDevice device, uint32_t memoryRangeCount, const void* pMemoryRanges);
typedef VkResult (*PFN_vkInvalidateMappedMemoryRanges)(VkDevice device, uint32_t memoryRangeCount, const void* pMemoryRanges);
typedef VkResult (*PFN_vkCreateShaderModule)(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkShaderModule* pShaderModule);
typedef void (*PFN_vkDestroyShaderModule)(VkDevice device, VkShaderModule shaderModule, const void* pAllocator);
typedef VkResult (*PFN_vkCreatePipelineLayout)(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkPipeline* pPipelineLayout);
typedef VkResult (*PFN_vkCreateComputePipelines)(VkDevice device, VkPipelineCache pipelineCache, uint32_t createInfoCount, const void* pCreateInfos, const void* pAllocator, VkPipeline* pPipelines);
typedef void (*PFN_vkDestroyPipeline)(VkDevice device, VkPipeline pipeline, const void* pAllocator);
typedef VkResult (*PFN_vkAllocateCommandBuffers)(VkDevice device, const void* pAllocateInfo, VkCommandBuffer* pCommandBuffers);
typedef void (*PFN_vkFreeCommandBuffers)(VkDevice device, VkCommandPool commandPool, uint32_t commandBufferCount, const VkCommandBuffer* pCommandBuffers);
typedef VkResult (*PFN_vkCreateCommandPool)(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkCommandPool* pCommandPool);
typedef void (*PFN_vkDestroyCommandPool)(VkDevice device, VkCommandPool commandPool, const void* pAllocator);
typedef VkResult (*PFN_vkResetCommandPool)(VkDevice device, VkCommandPool commandPool, VkFlags flags);
typedef VkResult (*PFN_vkBeginCommandBuffer)(VkCommandBuffer commandBuffer, const void* pBeginInfo);
typedef VkResult (*PFN_vkEndCommandBuffer)(VkCommandBuffer commandBuffer);
typedef void (*PFN_vkCmdBindPipeline)(VkCommandBuffer commandBuffer, uint32_t pipelineBindPoint, VkPipeline pipeline);
typedef void (*PFN_vkCmdDispatch)(VkCommandBuffer commandBuffer, uint32_t groupCountX, uint32_t groupCountY, uint32_t groupCountZ);
typedef void (*PFN_vkCmdBindDescriptorSets)(VkCommandBuffer commandBuffer, uint32_t pipelineBindPoint, VkPipelineLayout layout, uint32_t firstSet, uint32_t descriptorSetCount, const VkDescriptorSet* pDescriptorSets, uint32_t dynamicOffsetCount, const uint32_t* pDynamicOffsets);
typedef VkResult (*PFN_vkQueueSubmit)(VkQueue queue, uint32_t submitCount, const void* pSubmits, VkFence fence);
typedef VkResult (*PFN_vkQueueWaitIdle)(VkQueue queue);
typedef VkResult (*PFN_vkDeviceWaitIdle)(VkDevice device);
typedef VkResult (*PFN_vkCreateFence)(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkFence* pFence);
typedef void (*PFN_vkDestroyFence)(VkDevice device, VkFence fence, const void* pAllocator);
typedef VkResult (*PFN_vkResetFences)(VkDevice device, uint32_t fenceCount, const VkFence* pFences);
typedef VkResult (*PFN_vkWaitForFences)(VkDevice device, uint32_t fenceCount, const VkFence* pFences, VkBool32 waitAll, uint64_t timeout);
typedef VkResult (*PFN_vkCreateDescriptorSetLayout)(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkDescriptorSetLayout* pSetLayout);
typedef void (*PFN_vkDestroyDescriptorSetLayout)(VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const void* pAllocator);
typedef VkResult (*PFN_vkCreateDescriptorPool)(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkDescriptorPool* pDescriptorPool);
typedef void (*PFN_vkDestroyDescriptorPool)(VkDevice device, VkDescriptorPool descriptorPool, const void* pAllocator);
typedef VkResult (*PFN_vkAllocateDescriptorSets)(VkDevice device, const void* pAllocateInfo, VkDescriptorSet* pDescriptorSets);
typedef VkResult (*PFN_vkFreeDescriptorSets)(VkDevice device, VkDescriptorPool descriptorPool, uint32_t descriptorSetCount, const VkDescriptorSet* pDescriptorSets);
typedef void (*PFN_vkUpdateDescriptorSets)(VkDevice device, uint32_t descriptorWriteCount, const void* pDescriptorWrites, uint32_t descriptorCopyCount, const void* pDescriptorCopies);

// ============================================================================
// Vulkan Capabilities Info
// ============================================================================
struct VulkanCapabilities {
    bool runtimeAvailable = false;
    bool instanceCreated = false;
    bool deviceCreated = false;
    uint32_t apiVersion = 0;
    uint32_t driverVersion = 0;
    uint32_t vendorID = 0;
    uint32_t deviceID = 0;
    uint64_t deviceMemory = 0;
    uint32_t computeQueueFamily = UINT32_MAX;
    char deviceName[256] = {};
    
    // Feature flags
    bool supportsCompute = false;
    bool supportsLargeBuffers = false;
    bool supportsShaderFloat64 = false;
    uint32_t maxWorkGroupSize[3] = {};
    uint32_t maxComputeWorkGroupInvocations = 0;
};

// ============================================================================
// Runtime Vulkan Loader
// ============================================================================
class VulkanRuntimeLoader {
public:
    VulkanRuntimeLoader();
    ~VulkanRuntimeLoader();

    // Load Vulkan at runtime
    bool Load();
    void Unload();
    bool IsLoaded() const;

    // Initialize Vulkan (create instance, device, etc.)
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;

    // Get capabilities
    const VulkanCapabilities& GetCapabilities() const { return capabilities_; }
    bool HasComputeSupport() const;

    // GPU Memory info
    uint64_t GetAvailableMemory() const;
    uint64_t GetTotalMemory() const;

    // Error handling
    const char* GetLastError() const { return lastError_; }
    const char* GetVulkanResultString(VkResult result) const;

    // Direct function access (for advanced usage)
    PFN_vkCreateInstance vkCreateInstance = nullptr;
    PFN_vkDestroyInstance vkDestroyInstance = nullptr;
    PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices = nullptr;
    PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties = nullptr;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties vkGetPhysicalDeviceQueueFamilyProperties = nullptr;
    PFN_vkCreateDevice vkCreateDevice = nullptr;
    PFN_vkDestroyDevice vkDestroyDevice = nullptr;
    PFN_vkGetDeviceQueue vkGetDeviceQueue = nullptr;
    PFN_vkCreateBuffer vkCreateBuffer = nullptr;
    PFN_vkDestroyBuffer vkDestroyBuffer = nullptr;
    PFN_vkAllocateMemory vkAllocateMemory = nullptr;
    PFN_vkFreeMemory vkFreeMemory = nullptr;
    PFN_vkBindBufferMemory vkBindBufferMemory = nullptr;
    PFN_vkMapMemory vkMapMemory = nullptr;
    PFN_vkUnmapMemory vkUnmapMemory = nullptr;
    PFN_vkFlushMappedMemoryRanges vkFlushMappedMemoryRanges = nullptr;
    PFN_vkInvalidateMappedMemoryRanges vkInvalidateMappedMemoryRanges = nullptr;
    PFN_vkCreateShaderModule vkCreateShaderModule = nullptr;
    PFN_vkDestroyShaderModule vkDestroyShaderModule = nullptr;
    PFN_vkCreatePipelineLayout vkCreatePipelineLayout = nullptr;
    PFN_vkCreateComputePipelines vkCreateComputePipelines = nullptr;
    PFN_vkDestroyPipeline vkDestroyPipeline = nullptr;
    PFN_vkAllocateCommandBuffers vkAllocateCommandBuffers = nullptr;
    PFN_vkFreeCommandBuffers vkFreeCommandBuffers = nullptr;
    PFN_vkCreateCommandPool vkCreateCommandPool = nullptr;
    PFN_vkDestroyCommandPool vkDestroyCommandPool = nullptr;
    PFN_vkResetCommandPool vkResetCommandPool = nullptr;
    PFN_vkBeginCommandBuffer vkBeginCommandBuffer = nullptr;
    PFN_vkEndCommandBuffer vkEndCommandBuffer = nullptr;
    PFN_vkCmdBindPipeline vkCmdBindPipeline = nullptr;
    PFN_vkCmdDispatch vkCmdDispatch = nullptr;
    PFN_vkCmdBindDescriptorSets vkCmdBindDescriptorSets = nullptr;
    PFN_vkQueueSubmit vkQueueSubmit = nullptr;
    PFN_vkQueueWaitIdle vkQueueWaitIdle = nullptr;
    PFN_vkDeviceWaitIdle vkDeviceWaitIdle = nullptr;
    PFN_vkCreateFence vkCreateFence = nullptr;
    PFN_vkDestroyFence vkDestroyFence = nullptr;
    PFN_vkResetFences vkResetFences = nullptr;
    PFN_vkWaitForFences vkWaitForFences = nullptr;
    PFN_vkCreateDescriptorSetLayout vkCreateDescriptorSetLayout = nullptr;
    PFN_vkDestroyDescriptorSetLayout vkDestroyDescriptorSetLayout = nullptr;
    PFN_vkCreateDescriptorPool vkCreateDescriptorPool = nullptr;
    PFN_vkDestroyDescriptorPool vkDestroyDescriptorPool = nullptr;
    PFN_vkAllocateDescriptorSets vkAllocateDescriptorSets = nullptr;
    PFN_vkFreeDescriptorSets vkFreeDescriptorSets = nullptr;
    PFN_vkUpdateDescriptorSets vkUpdateDescriptorSets = nullptr;

private:
    HMODULE hVulkan_ = nullptr;
    VkInstance instance_ = nullptr;
    VkPhysicalDevice physicalDevice_ = nullptr;
    VkDevice device_ = nullptr;
    VkQueue computeQueue_ = nullptr;
    uint32_t computeQueueFamilyIndex_ = UINT32_MAX;
    VulkanCapabilities capabilities_;
    char lastError_[256] = {};

    void SetError(const char* msg);
    bool LoadFunctions();
    bool SelectPhysicalDevice();
    bool CreateLogicalDevice();
};

// ============================================================================
// Global Access
// ============================================================================
VulkanRuntimeLoader* GetVulkanLoader();
bool InitializeVulkanRuntime();
void ShutdownVulkanRuntime();
bool IsVulkanAvailable();

// ============================================================================
// Convenience Functions
// ============================================================================
bool VulkanComputeAvailable();
uint64_t GetVulkanAvailableMemory();
const char* GetVulkanDeviceName();

} // namespace GPU
} // namespace RawrXD
