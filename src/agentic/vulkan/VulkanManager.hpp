#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <fstream>

// Forward declare Vulkan types to avoid pulling in vulkan.h
typedef struct VkInstance_T* VkInstance;
typedef struct VkPhysicalDevice_T* VkPhysicalDevice;
typedef struct VkDevice_T* VkDevice;
typedef struct VkQueue_T* VkQueue;
typedef struct VkCommandPool_T* VkCommandPool;
typedef struct VkDescriptorPool_T* VkDescriptorPool;
typedef struct VkBuffer_T* VkBuffer;
typedef struct VkDeviceMemory_T* VkDeviceMemory;
typedef struct VkPipelineLayout_T* VkPipelineLayout;
typedef struct VkPipeline_T* VkPipeline;
typedef struct VkDescriptorSetLayout_T* VkDescriptorSetLayout;
typedef struct VkDescriptorSet_T* VkDescriptorSet;
typedef struct VkFence_T* VkFence;
typedef struct VkCommandBuffer_T* VkCommandBuffer;

namespace RawrXD::Agentic::Vulkan {

/// Vulkan device context for distributed compute
struct VulkanContext {
    VkInstance instance = nullptr;
    VkPhysicalDevice physicalDevice = nullptr;
    VkDevice device = nullptr;
    VkQueue computeQueue = nullptr;
    VkCommandPool commandPool = nullptr;
    VkDescriptorPool descriptorPool = nullptr;
    
    // Memory type indices
    uint32_t hostVisibleMemoryType = 0;
    uint32_t deviceLocalMemoryType = 0;
    uint32_t coherentMemoryType = 0;
    
    // FSM resources
    VkBuffer fsmBuffer = nullptr;
    VkDeviceMemory fsmMemory = nullptr;
    uint64_t fsmDeviceAddress = 0;
    
    VkBuffer bitmaskBuffer = nullptr;
    VkDeviceMemory bitmaskMemory = nullptr;
    void* bitmaskMappedPtr = nullptr;
    
    VkBuffer logitsBuffer = nullptr;
    VkBuffer outputBuffer = nullptr;
    
    // Pipeline
    VkPipelineLayout pipelineLayout = nullptr;
    VkPipeline pipeline = nullptr;
    VkDescriptorSetLayout descriptorSetLayout = nullptr;
    VkDescriptorSet descriptorSet = nullptr;
    
    // Synchronization
    VkFence fence = nullptr;
    VkCommandBuffer commandBuffer = nullptr;
    
    // Workgroup configuration
    uint32_t workgroupSizeX = 256;
    uint32_t workgroupSizeY = 1;
    uint32_t workgroupSizeZ = 1;
};

/// Vulkan initialization and management
class VulkanManager {
public:
    /// Initialize Vulkan context
    static bool initialize(VulkanContext& context, bool enableValidation = false);
    
    /// Shutdown Vulkan context
    static void shutdown(VulkanContext& context);
    
    /// Create FSM resources (GPU buffers for tool parsing)
    static bool createFSMResources(VulkanContext& context, const void* fsmTable, size_t tableSize);
    
    /// Update bitmask (zero-copy via mapped memory)
    static bool updateBitmask(VulkanContext& context, const void* bitmask, size_t size);
    
    /// Dispatch compute shader (tool parsing on GPU)
    static bool dispatchCompute(VulkanContext& context, uint32_t vocabSize, uint32_t currentState);
    
    /// Wait for GPU completion
    static bool waitForCompletion(VulkanContext& context);
    
    /// Get GPU device name
    static std::string getDeviceName(const VulkanContext& context);
    
    /// Check Vulkan availability
    static bool isVulkanAvailable();
    
    /// Enumerate available Vulkan devices
    static std::vector<std::string> enumerateDevices(VulkanContext& context);
    
    /// Select specific device by index
    static bool selectDevice(VulkanContext& context, uint32_t deviceIndex);
    
    /// Get total device memory size
    static uint64_t getDeviceMemorySize(const VulkanContext& context);
    
    /// Get used device memory
    static uint64_t getDeviceMemoryUsed(const VulkanContext& context);
    
    /// Copy data between buffers
    static bool copyBuffer(VulkanContext& context, VkBuffer_T* srcBuffer, VkBuffer_T* dstBuffer, uint64_t size);
    
    /// Insert pipeline barrier
    static void cmdPipelineBarrier(VulkanContext& context, uint32_t srcStage, uint32_t dstStage, 
                                    VkBuffer_T* buffer, uint32_t srcAccess, uint32_t dstAccess);
    
    /// Wait for GPU completion with timeout
    static bool waitForCompletion(VulkanContext& context, uint64_t timeoutNs);
    
private:
    static bool createDevice(VulkanContext& context);
    static bool createCommandPool(VulkanContext& context);
    static bool createDescriptorPool(VulkanContext& context);
    static bool createPipeline(VulkanContext& context);
    static bool createPipeline(VulkanContext& context, const char* shaderPath);
    static bool updateDescriptorSet(VulkanContext& context, VkBuffer_T* buffer0, VkBuffer_T* buffer1, VkBuffer_T* buffer2);
    static uint32_t findMemoryType(const VulkanContext& context, uint32_t typeFilter, uint32_t properties);
    
    // Helper: Read SPIR-V binary file
    static std::vector<char> readFile(const std::string& filename);
};

} // namespace RawrXD::Agentic::Vulkan
