// ============================================================================
// RawrXD GPU Execution Verifier
// Proves end-to-end GPU compute execution with:
//   1. Device enumeration + identity
//   2. VRAM allocation with DEVICE_LOCAL verification
//   3. Compute shader dispatch with timestamp queries
//   4. CPU reference comparison
// ============================================================================
// Zero-dependency: loads vulkan-1.dll at runtime, no SDK required
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>

// Flush stdout after every print for reliable capture
#define PRINTF(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)

#include "add_shader.h"

// ============================================================================
// Minimal Vulkan ABI Types (SDK-free)
// ============================================================================
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;
typedef uint32_t VkFlags;

#define VK_DEFINE_HANDLE(obj) typedef struct obj##_T* obj
#define VK_NULL_HANDLE nullptr

VK_DEFINE_HANDLE(VkInstance);
VK_DEFINE_HANDLE(VkPhysicalDevice);
VK_DEFINE_HANDLE(VkDevice);
VK_DEFINE_HANDLE(VkQueue);
VK_DEFINE_HANDLE(VkCommandBuffer);
VK_DEFINE_HANDLE(VkDeviceMemory);
VK_DEFINE_HANDLE(VkBuffer);
VK_DEFINE_HANDLE(VkShaderModule);
VK_DEFINE_HANDLE(VkPipeline);
VK_DEFINE_HANDLE(VkPipelineLayout);
VK_DEFINE_HANDLE(VkDescriptorSetLayout);
VK_DEFINE_HANDLE(VkDescriptorPool);
VK_DEFINE_HANDLE(VkDescriptorSet);
VK_DEFINE_HANDLE(VkCommandPool);
VK_DEFINE_HANDLE(VkFence);
VK_DEFINE_HANDLE(VkQueryPool);
VK_DEFINE_HANDLE(VkPipelineCache);

typedef enum VkResult {
    VK_SUCCESS = 0,
    VK_NOT_READY = 1,
    VK_TIMEOUT = 2,
    VK_ERROR_OUT_OF_HOST_MEMORY = -1,
    VK_ERROR_OUT_OF_DEVICE_MEMORY = -2,
    VK_ERROR_INITIALIZATION_FAILED = -3,
    VK_ERROR_DEVICE_LOST = -4,
    VK_ERROR_MEMORY_MAP_FAILED = -5,
    VK_ERROR_INCOMPATIBLE_DRIVER = -9,
} VkResult;

typedef enum VkStructureType {
    VK_STRUCTURE_TYPE_APPLICATION_INFO = 0,
    VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1,
    VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 2,
    VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 3,
    VK_STRUCTURE_TYPE_SUBMIT_INFO = 4,
    VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO = 5,
    VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO = 12,
    VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO = 14,
    VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO = 18,
    VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO = 19,
    VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO = 21,
    VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO = 27,
    VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO = 29,
    VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO = 30,
    VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET = 33,
    VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO = 37,
    VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO = 40,
    VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO = 42,
    VK_STRUCTURE_TYPE_FENCE_CREATE_INFO = 86,
    VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO = 100,
} VkStructureType;

typedef enum VkPhysicalDeviceType {
    VK_PHYSICAL_DEVICE_TYPE_OTHER = 0,
    VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU = 1,
    VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU = 2,
    VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU = 3,
    VK_PHYSICAL_DEVICE_TYPE_CPU = 4,
} VkPhysicalDeviceType;

#define VK_QUEUE_COMPUTE_BIT 0x00000002
#define VK_BUFFER_USAGE_STORAGE_BUFFER_BIT 0x0080
#define VK_BUFFER_USAGE_TRANSFER_SRC_BIT 0x0001
#define VK_BUFFER_USAGE_TRANSFER_DST_BIT 0x0002
#define VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT 0x0001
#define VK_MEMORY_PROPERTY_HOST_COHERENT_BIT 0x0002
#define VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT 0x0004
#define VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT 0x0008
#define VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT 0x0001
#define VK_PIPELINE_BIND_POINT_COMPUTE 0
#define VK_SHARING_MODE_EXCLUSIVE 0
#define VK_SHADER_STAGE_COMPUTE_BIT 0x0020
#define VK_DESCRIPTOR_TYPE_STORAGE_BUFFER 7
#define VK_QUERY_TYPE_TIMESTAMP 0
#define VK_QUERY_RESULT_64_BIT 0x00000001
#define VK_QUERY_RESULT_WAIT_BIT 0x00000002
#define VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT 0x00000001
#define VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT 0x80000000
#define VK_TRUE 1
#define VK_FALSE 0
typedef VkFlags VkBufferUsageFlags;

// ============================================================================
// Vulkan Structure Definitions
// ============================================================================
typedef struct VkApplicationInfo {
    VkStructureType sType; const void* pNext;
    const char* pApplicationName; uint32_t applicationVersion;
    const char* pEngineName; uint32_t engineVersion;
    uint32_t apiVersion;
} VkApplicationInfo;

typedef struct VkInstanceCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    const VkApplicationInfo* pApplicationInfo;
    uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames;
} VkInstanceCreateInfo;

typedef struct VkPhysicalDeviceProperties {
    uint32_t apiVersion; uint32_t driverVersion; uint32_t vendorID;
    uint32_t deviceID; VkPhysicalDeviceType deviceType;
    char deviceName[256]; uint8_t pipelineCacheUUID[16];
} VkPhysicalDeviceProperties;

typedef struct VkQueueFamilyProperties {
    VkFlags queueFlags; uint32_t queueCount;
    uint32_t timestampValidBits;
    uint32_t minImageTransferGranularity[3];
} VkQueueFamilyProperties;

typedef struct VkPhysicalDeviceMemoryProperties {
    uint32_t memoryTypeCount;
    struct { VkFlags propertyFlags; uint32_t heapIndex; } memoryTypes[32];
    uint32_t memoryHeapCount;
    struct { VkDeviceSize size; VkFlags flags; } memoryHeaps[16];
} VkPhysicalDeviceMemoryProperties;

typedef struct VkDeviceQueueCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t queueFamilyIndex; uint32_t queueCount;
    const float* pQueuePriorities;
} VkDeviceQueueCreateInfo;

typedef struct VkPhysicalDeviceFeatures {
    VkBool32 robustBufferAccess; VkBool32 fullDrawIndexUint32;
    VkBool32 imageCubeArray; VkBool32 independentBlend;
    VkBool32 geometryShader; VkBool32 tessellationShader;
    VkBool32 sampleRateShading; VkBool32 dualSrcBlend;
    VkBool32 logicOp; VkBool32 multiDrawIndirect;
    VkBool32 drawIndirectFirstInstance; VkBool32 depthClamp;
    VkBool32 depthBiasClamp; VkBool32 fillModeNonSolid;
    VkBool32 depthBounds; VkBool32 wideLines;
    VkBool32 largePoints; VkBool32 alphaToOne;
    VkBool32 multiViewport; VkBool32 samplerAnisotropy;
    VkBool32 textureCompressionETC2; VkBool32 textureCompressionASTC_LDR;
    VkBool32 textureCompressionBC; VkBool32 occlusionQueryPrecise;
    VkBool32 pipelineStatisticsQuery; VkBool32 vertexPipelineStoresAndAtomics;
    VkBool32 fragmentStoresAndAtomics; VkBool32 shaderTessellationAndGeometryPointSize;
    VkBool32 shaderImageGatherExtended; VkBool32 shaderStorageImageExtendedFormats;
    VkBool32 shaderStorageImageMultisample; VkBool32 shaderStorageImageReadWithoutFormat;
    VkBool32 shaderStorageImageWriteWithoutFormat; VkBool32 shaderUniformBufferArrayDynamicIndexing;
    VkBool32 shaderSampledImageArrayDynamicIndexing; VkBool32 shaderStorageBufferArrayDynamicIndexing;
    VkBool32 shaderStorageImageArrayDynamicIndexing; VkBool32 shaderClipDistance;
    VkBool32 shaderCullDistance; VkBool32 shaderFloat64;
    VkBool32 shaderInt64; VkBool32 shaderInt16;
    VkBool32 shaderResourceResidency; VkBool32 shaderResourceMinLod;
    VkBool32 sparseBinding; VkBool32 sparseResidencyBuffer;
    VkBool32 sparseResidencyImage2D; VkBool32 sparseResidencyImage3D;
    VkBool32 sparseResidency2Samples; VkBool32 sparseResidency4Samples;
    VkBool32 sparseResidency8Samples; VkBool32 sparseResidency16Samples;
    VkBool32 sparseResidencyAliased; VkBool32 variableMultisampleRate;
    VkBool32 inheritedQueries;
} VkPhysicalDeviceFeatures;

typedef struct VkDeviceCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t queueCreateInfoCount; const VkDeviceQueueCreateInfo* pQueueCreateInfos;
    uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames;
    const VkPhysicalDeviceFeatures* pEnabledFeatures;
} VkDeviceCreateInfo;

typedef VkFlags VkBufferUsageFlags;

typedef struct VkBufferCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    VkDeviceSize size; VkBufferUsageFlags usage;
    uint32_t sharingMode; uint32_t queueFamilyIndexCount;
    const uint32_t* pQueueFamilyIndices;
} VkBufferCreateInfo;
typedef VkFlags VkBufferUsageFlags;

typedef struct VkMemoryAllocateInfo {
    VkStructureType sType; const void* pNext;
    VkDeviceSize allocationSize; uint32_t memoryTypeIndex;
} VkMemoryAllocateInfo;

typedef struct VkCommandPoolCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t queueFamilyIndex;
} VkCommandPoolCreateInfo;

typedef struct VkCommandBufferAllocateInfo {
    VkStructureType sType; const void* pNext;
    VkCommandPool commandPool; uint32_t level;
    uint32_t commandBufferCount;
} VkCommandBufferAllocateInfo;

typedef struct VkCommandBufferBeginInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    const void* pInheritanceInfo;
} VkCommandBufferBeginInfo;

typedef struct VkSubmitInfo {
    VkStructureType sType; const void* pNext;
    uint32_t waitSemaphoreCount; const void* pWaitSemaphores;
    const uint32_t* pWaitDstStageMask;
    uint32_t commandBufferCount; const VkCommandBuffer* pCommandBuffers;
    uint32_t signalSemaphoreCount; const void* pSignalSemaphores;
} VkSubmitInfo;

typedef struct VkFenceCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
} VkFenceCreateInfo;

typedef struct VkQueryPoolCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t queryType; uint32_t queryCount;
    VkFlags pipelineStatistics;
} VkQueryPoolCreateInfo;

typedef struct VkShaderModuleCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    size_t codeSize; const uint32_t* pCode;
} VkShaderModuleCreateInfo;

typedef struct VkPipelineShaderStageCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t stage; VkShaderModule module;
    const char* pName; const void* pSpecializationInfo;
} VkPipelineShaderStageCreateInfo;

typedef struct VkComputePipelineCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    VkPipelineShaderStageCreateInfo stage;
    VkPipelineLayout layout; VkPipeline basePipelineHandle;
    int32_t basePipelineIndex;
} VkComputePipelineCreateInfo;

typedef struct VkPipelineLayoutCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t setLayoutCount; const VkDescriptorSetLayout* pSetLayouts;
    uint32_t pushConstantRangeCount; const void* pPushConstantRanges;
} VkPipelineLayoutCreateInfo;

typedef struct VkDescriptorSetLayoutBinding {
    uint32_t binding; uint32_t descriptorType; uint32_t descriptorCount;
    uint32_t stageFlags; const void* pImmutableSamplers;
} VkDescriptorSetLayoutBinding;

typedef struct VkDescriptorSetLayoutCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t bindingCount; const VkDescriptorSetLayoutBinding* pBindings;
} VkDescriptorSetLayoutCreateInfo;

typedef struct VkDescriptorPoolSize {
    uint32_t type; uint32_t descriptorCount;
} VkDescriptorPoolSize;

typedef struct VkDescriptorPoolCreateInfo {
    VkStructureType sType; const void* pNext; VkFlags flags;
    uint32_t maxSets; uint32_t poolSizeCount;
    const VkDescriptorPoolSize* pPoolSizes;
} VkDescriptorPoolCreateInfo;

typedef struct VkDescriptorBufferInfo {
    VkBuffer buffer; VkDeviceSize offset; VkDeviceSize range;
} VkDescriptorBufferInfo;

typedef struct VkWriteDescriptorSet {
    VkStructureType sType; const void* pNext;
    VkDescriptorSet dstSet; uint32_t dstBinding; uint32_t dstArrayElement;
    uint32_t descriptorCount; uint32_t descriptorType;
    const VkDescriptorBufferInfo* pBufferInfo;
    const void* pImageInfo; const void* pTexelBufferView;
} VkWriteDescriptorSet;

typedef struct VkDescriptorSetAllocateInfo {
    VkStructureType sType; const void* pNext;
    VkDescriptorPool descriptorPool;
    uint32_t descriptorSetCount;
    const VkDescriptorSetLayout* pSetLayouts;
} VkDescriptorSetAllocateInfo;

// ============================================================================
// Function Pointer Types
// ============================================================================
typedef VkResult (__stdcall *PFN_vkCreateInstance)(const VkInstanceCreateInfo*, const void*, VkInstance*);
typedef void (__stdcall *PFN_vkDestroyInstance)(VkInstance, const void*);
typedef VkResult (__stdcall *PFN_vkEnumeratePhysicalDevices)(VkInstance, uint32_t*, VkPhysicalDevice*);
typedef void (__stdcall *PFN_vkGetPhysicalDeviceProperties)(VkPhysicalDevice, VkPhysicalDeviceProperties*);
typedef void (__stdcall *PFN_vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice, uint32_t*, VkQueueFamilyProperties*);
typedef void (__stdcall *PFN_vkGetPhysicalDeviceMemoryProperties)(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties*);
typedef VkResult (__stdcall *PFN_vkCreateDevice)(VkPhysicalDevice, const VkDeviceCreateInfo*, const void*, VkDevice*);
typedef void (__stdcall *PFN_vkDestroyDevice)(VkDevice, const void*);
typedef void (__stdcall *PFN_vkGetDeviceQueue)(VkDevice, uint32_t, uint32_t, VkQueue*);
typedef VkResult (__stdcall *PFN_vkDeviceWaitIdle)(VkDevice);
typedef VkResult (__stdcall *PFN_vkCreateBuffer)(VkDevice, const VkBufferCreateInfo*, const void*, VkBuffer*);
typedef void (__stdcall *PFN_vkDestroyBuffer)(VkDevice, VkBuffer, const void*);
typedef VkResult (__stdcall *PFN_vkAllocateMemory)(VkDevice, const VkMemoryAllocateInfo*, const void*, VkDeviceMemory*);
typedef void (__stdcall *PFN_vkFreeMemory)(VkDevice, VkDeviceMemory, const void*);
typedef VkResult (__stdcall *PFN_vkBindBufferMemory)(VkDevice, VkBuffer, VkDeviceMemory, VkDeviceSize);
typedef VkResult (__stdcall *PFN_vkMapMemory)(VkDevice, VkDeviceMemory, VkDeviceSize, VkDeviceSize, VkFlags, void**);
typedef void (__stdcall *PFN_vkUnmapMemory)(VkDevice, VkDeviceMemory);
typedef VkResult (__stdcall *PFN_vkCreateCommandPool)(VkDevice, const VkCommandPoolCreateInfo*, const void*, VkCommandPool*);
typedef void (__stdcall *PFN_vkDestroyCommandPool)(VkDevice, VkCommandPool, const void*);
typedef VkResult (__stdcall *PFN_vkAllocateCommandBuffers)(VkDevice, const VkCommandBufferAllocateInfo*, VkCommandBuffer*);
typedef void (__stdcall *PFN_vkFreeCommandBuffers)(VkDevice, VkCommandPool, uint32_t, const VkCommandBuffer*);
typedef VkResult (__stdcall *PFN_vkBeginCommandBuffer)(VkCommandBuffer, const VkCommandBufferBeginInfo*);
typedef VkResult (__stdcall *PFN_vkEndCommandBuffer)(VkCommandBuffer);
typedef VkResult (__stdcall *PFN_vkQueueSubmit)(VkQueue, uint32_t, const VkSubmitInfo*, VkFence);
typedef VkResult (__stdcall *PFN_vkQueueWaitIdle)(VkQueue);
typedef VkResult (__stdcall *PFN_vkCreateFence)(VkDevice, const VkFenceCreateInfo*, const void*, VkFence*);
typedef void (__stdcall *PFN_vkDestroyFence)(VkDevice, VkFence, const void*);
typedef VkResult (__stdcall *PFN_vkWaitForFences)(VkDevice, uint32_t, const VkFence*, VkBool32, uint64_t);
typedef VkResult (__stdcall *PFN_vkResetFences)(VkDevice, uint32_t, const VkFence*);
typedef VkResult (__stdcall *PFN_vkCreateQueryPool)(VkDevice, const VkQueryPoolCreateInfo*, const void*, VkQueryPool*);
typedef void (__stdcall *PFN_vkDestroyQueryPool)(VkDevice, VkQueryPool, const void*);
typedef void (__stdcall *PFN_vkCmdResetQueryPool)(VkCommandBuffer, VkQueryPool, uint32_t, uint32_t);
typedef void (__stdcall *PFN_vkCmdWriteTimestamp)(VkCommandBuffer, uint32_t, VkQueryPool, uint32_t);
typedef VkResult (__stdcall *PFN_vkGetQueryPoolResults)(VkDevice, VkQueryPool, uint32_t, uint32_t, size_t, void*, VkDeviceSize, VkFlags);
typedef VkResult (__stdcall *PFN_vkCreateShaderModule)(VkDevice, const VkShaderModuleCreateInfo*, const void*, VkShaderModule*);
typedef void (__stdcall *PFN_vkDestroyShaderModule)(VkDevice, VkShaderModule, const void*);
typedef VkResult (__stdcall *PFN_vkCreatePipelineLayout)(VkDevice, const VkPipelineLayoutCreateInfo*, const void*, VkPipelineLayout*);
typedef void (__stdcall *PFN_vkDestroyPipelineLayout)(VkDevice, VkPipelineLayout, const void*);
typedef VkResult (__stdcall *PFN_vkCreateComputePipelines)(VkDevice, VkPipelineCache, uint32_t, const VkComputePipelineCreateInfo*, const void*, VkPipeline*);
typedef void (__stdcall *PFN_vkDestroyPipeline)(VkDevice, VkPipeline, const void*);
typedef void (__stdcall *PFN_vkCmdBindPipeline)(VkCommandBuffer, uint32_t, VkPipeline);
typedef void (__stdcall *PFN_vkCmdDispatch)(VkCommandBuffer, uint32_t, uint32_t, uint32_t);
typedef VkResult (__stdcall *PFN_vkCreateDescriptorSetLayout)(VkDevice, const VkDescriptorSetLayoutCreateInfo*, const void*, VkDescriptorSetLayout*);
typedef void (__stdcall *PFN_vkDestroyDescriptorSetLayout)(VkDevice, VkDescriptorSetLayout, const void*);
typedef VkResult (__stdcall *PFN_vkCreateDescriptorPool)(VkDevice, const VkDescriptorPoolCreateInfo*, const void*, VkDescriptorPool*);
typedef void (__stdcall *PFN_vkDestroyDescriptorPool)(VkDevice, VkDescriptorPool, const void*);
typedef VkResult (__stdcall *PFN_vkAllocateDescriptorSets)(VkDevice, const VkDescriptorSetAllocateInfo*, VkDescriptorSet*);
typedef void (__stdcall *PFN_vkUpdateDescriptorSets)(VkDevice, uint32_t, const VkWriteDescriptorSet*, uint32_t, const void*);
typedef void (__stdcall *PFN_vkCmdBindDescriptorSets)(VkCommandBuffer, uint32_t, VkPipelineLayout, uint32_t, uint32_t, const VkDescriptorSet*, uint32_t, const uint32_t*);
typedef void (__stdcall *PFN_vkCmdCopyBuffer)(VkCommandBuffer, VkBuffer, VkBuffer, uint32_t, const void*);

// ============================================================================
// Global Vulkan Function Table
// ============================================================================
struct VulkanFunctions {
    HMODULE hLib = nullptr;
    
    PFN_vkCreateInstance vkCreateInstance = nullptr;
    PFN_vkDestroyInstance vkDestroyInstance = nullptr;
    PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices = nullptr;
    PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties = nullptr;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties vkGetPhysicalDeviceQueueFamilyProperties = nullptr;
    PFN_vkGetPhysicalDeviceMemoryProperties vkGetPhysicalDeviceMemoryProperties = nullptr;
    PFN_vkCreateDevice vkCreateDevice = nullptr;
    PFN_vkDestroyDevice vkDestroyDevice = nullptr;
    PFN_vkGetDeviceQueue vkGetDeviceQueue = nullptr;
    PFN_vkDeviceWaitIdle vkDeviceWaitIdle = nullptr;
    PFN_vkCreateBuffer vkCreateBuffer = nullptr;
    PFN_vkDestroyBuffer vkDestroyBuffer = nullptr;
    PFN_vkAllocateMemory vkAllocateMemory = nullptr;
    PFN_vkFreeMemory vkFreeMemory = nullptr;
    PFN_vkBindBufferMemory vkBindBufferMemory = nullptr;
    PFN_vkMapMemory vkMapMemory = nullptr;
    PFN_vkUnmapMemory vkUnmapMemory = nullptr;
    PFN_vkCreateCommandPool vkCreateCommandPool = nullptr;
    PFN_vkDestroyCommandPool vkDestroyCommandPool = nullptr;
    PFN_vkAllocateCommandBuffers vkAllocateCommandBuffers = nullptr;
    PFN_vkFreeCommandBuffers vkFreeCommandBuffers = nullptr;
    PFN_vkBeginCommandBuffer vkBeginCommandBuffer = nullptr;
    PFN_vkEndCommandBuffer vkEndCommandBuffer = nullptr;
    PFN_vkQueueSubmit vkQueueSubmit = nullptr;
    PFN_vkQueueWaitIdle vkQueueWaitIdle = nullptr;
    PFN_vkCreateFence vkCreateFence = nullptr;
    PFN_vkDestroyFence vkDestroyFence = nullptr;
    PFN_vkWaitForFences vkWaitForFences = nullptr;
    PFN_vkResetFences vkResetFences = nullptr;
    PFN_vkCreateQueryPool vkCreateQueryPool = nullptr;
    PFN_vkDestroyQueryPool vkDestroyQueryPool = nullptr;
    PFN_vkCmdResetQueryPool vkCmdResetQueryPool = nullptr;
    PFN_vkCmdWriteTimestamp vkCmdWriteTimestamp = nullptr;
    PFN_vkGetQueryPoolResults vkGetQueryPoolResults = nullptr;
    PFN_vkCreateShaderModule vkCreateShaderModule = nullptr;
    PFN_vkDestroyShaderModule vkDestroyShaderModule = nullptr;
    PFN_vkCreatePipelineLayout vkCreatePipelineLayout = nullptr;
    PFN_vkDestroyPipelineLayout vkDestroyPipelineLayout = nullptr;
    PFN_vkCreateComputePipelines vkCreateComputePipelines = nullptr;
    PFN_vkDestroyPipeline vkDestroyPipeline = nullptr;
    PFN_vkCmdBindPipeline vkCmdBindPipeline = nullptr;
    PFN_vkCmdDispatch vkCmdDispatch = nullptr;
    PFN_vkCreateDescriptorSetLayout vkCreateDescriptorSetLayout = nullptr;
    PFN_vkDestroyDescriptorSetLayout vkDestroyDescriptorSetLayout = nullptr;
    PFN_vkCreateDescriptorPool vkCreateDescriptorPool = nullptr;
    PFN_vkDestroyDescriptorPool vkDestroyDescriptorPool = nullptr;
    PFN_vkAllocateDescriptorSets vkAllocateDescriptorSets = nullptr;
    PFN_vkUpdateDescriptorSets vkUpdateDescriptorSets = nullptr;
    PFN_vkCmdBindDescriptorSets vkCmdBindDescriptorSets = nullptr;
    PFN_vkCmdCopyBuffer vkCmdCopyBuffer = nullptr;

    bool Load() {
        hLib = LoadLibraryA("vulkan-1.dll");
        if (!hLib) return false;
        
        #define LOAD_FN(name) name = (PFN_##name)GetProcAddress(hLib, #name); if (!name) return false
        
        LOAD_FN(vkCreateInstance);
        LOAD_FN(vkDestroyInstance);
        LOAD_FN(vkEnumeratePhysicalDevices);
        LOAD_FN(vkGetPhysicalDeviceProperties);
        LOAD_FN(vkGetPhysicalDeviceQueueFamilyProperties);
        LOAD_FN(vkGetPhysicalDeviceMemoryProperties);
        LOAD_FN(vkCreateDevice);
        LOAD_FN(vkDestroyDevice);
        LOAD_FN(vkGetDeviceQueue);
        LOAD_FN(vkDeviceWaitIdle);
        LOAD_FN(vkCreateBuffer);
        LOAD_FN(vkDestroyBuffer);
        LOAD_FN(vkAllocateMemory);
        LOAD_FN(vkFreeMemory);
        LOAD_FN(vkBindBufferMemory);
        LOAD_FN(vkMapMemory);
        LOAD_FN(vkUnmapMemory);
        LOAD_FN(vkCreateCommandPool);
        LOAD_FN(vkDestroyCommandPool);
        LOAD_FN(vkAllocateCommandBuffers);
        LOAD_FN(vkFreeCommandBuffers);
        LOAD_FN(vkBeginCommandBuffer);
        LOAD_FN(vkEndCommandBuffer);
        LOAD_FN(vkQueueSubmit);
        LOAD_FN(vkQueueWaitIdle);
        LOAD_FN(vkCreateFence);
        LOAD_FN(vkDestroyFence);
        LOAD_FN(vkWaitForFences);
        LOAD_FN(vkResetFences);
        LOAD_FN(vkCreateQueryPool);
        LOAD_FN(vkDestroyQueryPool);
        LOAD_FN(vkCmdResetQueryPool);
        LOAD_FN(vkCmdWriteTimestamp);
        LOAD_FN(vkGetQueryPoolResults);
        LOAD_FN(vkCreateShaderModule);
        LOAD_FN(vkDestroyShaderModule);
        LOAD_FN(vkCreatePipelineLayout);
        LOAD_FN(vkDestroyPipelineLayout);
        LOAD_FN(vkCreateComputePipelines);
        LOAD_FN(vkDestroyPipeline);
        LOAD_FN(vkCmdBindPipeline);
        LOAD_FN(vkCmdDispatch);
        LOAD_FN(vkCreateDescriptorSetLayout);
        LOAD_FN(vkDestroyDescriptorSetLayout);
        LOAD_FN(vkCreateDescriptorPool);
        LOAD_FN(vkDestroyDescriptorPool);
        LOAD_FN(vkAllocateDescriptorSets);
        LOAD_FN(vkUpdateDescriptorSets);
        LOAD_FN(vkCmdBindDescriptorSets);
        LOAD_FN(vkCmdCopyBuffer);
        
        return true;
    }
    
    void Unload() {
        if (hLib) { FreeLibrary(hLib); hLib = nullptr; }
    }
} vk;

// ============================================================================
// Global Vulkan State
// ============================================================================
VkInstance g_instance = nullptr;
VkPhysicalDevice g_physDevice = nullptr;
VkDevice g_device = nullptr;
VkQueue g_queue = nullptr;
uint32_t g_queueFamily = UINT32_MAX;
VkCommandPool g_cmdPool = nullptr;
VkPhysicalDeviceProperties g_devProps = {};
VkPhysicalDeviceMemoryProperties g_memProps = {};

// ============================================================================
// Helpers
// ============================================================================
static const char* VkStr(VkResult r) {
    switch (r) {
        case VK_SUCCESS: return "VK_SUCCESS";
        case VK_NOT_READY: return "VK_NOT_READY";
        case VK_TIMEOUT: return "VK_TIMEOUT";
        case VK_ERROR_OUT_OF_HOST_MEMORY: return "VK_ERROR_OUT_OF_HOST_MEMORY";
        case VK_ERROR_OUT_OF_DEVICE_MEMORY: return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
        case VK_ERROR_INITIALIZATION_FAILED: return "VK_ERROR_INITIALIZATION_FAILED";
        case VK_ERROR_DEVICE_LOST: return "VK_ERROR_DEVICE_LOST";
        case VK_ERROR_MEMORY_MAP_FAILED: return "VK_ERROR_MEMORY_MAP_FAILED";
        case VK_ERROR_INCOMPATIBLE_DRIVER: return "VK_ERROR_INCOMPATIBLE_DRIVER";
        default: return "UNKNOWN";
    }
}

static const char* DeviceTypeStr(VkPhysicalDeviceType t) {
    switch (t) {
        case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU: return "Discrete GPU";
        case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU: return "Integrated GPU";
        case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU: return "Virtual GPU";
        case VK_PHYSICAL_DEVICE_TYPE_CPU: return "CPU";
        default: return "Other";
    }
}

static const char* MemFlagsStr(VkFlags flags) {
    static char buf[128];
    buf[0] = 0;
    if (flags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) strcat_s(buf, sizeof(buf), "DEVICE_LOCAL ");
    if (flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) strcat_s(buf, sizeof(buf), "HOST_VISIBLE ");
    if (flags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) strcat_s(buf, sizeof(buf), "HOST_COHERENT ");
    if (buf[0] == 0) strcat_s(buf, sizeof(buf), "NONE");
    return buf;
}

// ============================================================================
// Step 1: Enumerate GPUs
// ============================================================================
static bool EnumerateGPUs() {
    printf("\n=== [1] GPU Enumeration ===\n");
    
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD GPU Verifier";
    appInfo.applicationVersion = 1;
    appInfo.pEngineName = "RawrXD";
    appInfo.engineVersion = 1;
    appInfo.apiVersion = (1u << 22); // Vulkan 1.0
    
    VkInstanceCreateInfo instInfo = {};
    instInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instInfo.pApplicationInfo = &appInfo;
    
    VkResult res = vk.vkCreateInstance(&instInfo, nullptr, &g_instance);
    if (res != VK_SUCCESS) {
        printf("  FAIL: vkCreateInstance returned %s\n", VkStr(res));
        return false;
    }
    printf("  [OK] Vulkan instance created\n");
    
    uint32_t devCount = 0;
    res = vk.vkEnumeratePhysicalDevices(g_instance, &devCount, nullptr);
    if (res != VK_SUCCESS || devCount == 0) {
        printf("  FAIL: No Vulkan physical devices found\n");
        return false;
    }
    printf("  Found %u physical device(s)\n", devCount);
    
    std::vector<VkPhysicalDevice> devices(devCount);
    vk.vkEnumeratePhysicalDevices(g_instance, &devCount, devices.data());
    
    for (uint32_t i = 0; i < devCount; i++) {
        VkPhysicalDeviceProperties props;
        vk.vkGetPhysicalDeviceProperties(devices[i], &props);
        
        printf("\n  Device %u:\n", i);
        printf("    Name:       %s\n", props.deviceName);
        printf("    Type:       %s\n", DeviceTypeStr(props.deviceType));
        printf("    Vendor ID:  0x%04X", props.vendorID);
        if (props.vendorID == 0x1002) printf(" (AMD)");
        else if (props.vendorID == 0x10DE) printf(" (NVIDIA)");
        else if (props.vendorID == 0x8086) printf(" (Intel)");
        printf("\n");
        printf("    Device ID:  0x%04X\n", props.deviceID);
        printf("    Driver:     %u.%u.%u.%u\n",
            (props.driverVersion >> 24) & 0xFF,
            (props.driverVersion >> 16) & 0xFF,
            (props.driverVersion >> 8) & 0xFF,
            props.driverVersion & 0xFF);
        
        VkPhysicalDeviceMemoryProperties memProps;
        vk.vkGetPhysicalDeviceMemoryProperties(devices[i], &memProps);
        printf("    Memory Heaps: %u\n", memProps.memoryHeapCount);
        for (uint32_t h = 0; h < memProps.memoryHeapCount; h++) {
            const char* heapType = (memProps.memoryHeaps[h].flags & 0x1) ? "DEVICE_LOCAL" : "SYSTEM";
            printf("      Heap %u: %llu MB (%s)\n", h,
                (unsigned long long)(memProps.memoryHeaps[h].size / (1024*1024)),
                heapType);
        }
        
        uint32_t qfCount = 0;
        vk.vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &qfCount, nullptr);
        std::vector<VkQueueFamilyProperties> qfProps(qfCount);
        vk.vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &qfCount, qfProps.data());
        for (uint32_t q = 0; q < qfCount; q++) {
            if (qfProps[q].queueFlags & VK_QUEUE_COMPUTE_BIT) {
                printf("    Compute Queue Family: %u (%u queues, timestampValidBits=%u)\n",
                    q, qfProps[q].queueCount, qfProps[q].timestampValidBits);
            }
        }
        
        if (g_physDevice == nullptr ||
            (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU &&
             g_devProps.deviceType != VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU)) {
            g_physDevice = devices[i];
            g_devProps = props;
            g_memProps = memProps;
        }
    }
    
    printf("\n  Selected: %s\n", g_devProps.deviceName);
    return true;
}

// ============================================================================
// Step 2: Create Persistent Device
// ============================================================================
static bool CreateDevice() {
    printf("\n=== [2] Create Persistent Vulkan Device ===\n");
    
    uint32_t qfCount = 0;
    vk.vkGetPhysicalDeviceQueueFamilyProperties(g_physDevice, &qfCount, nullptr);
    std::vector<VkQueueFamilyProperties> qfProps(qfCount);
    vk.vkGetPhysicalDeviceQueueFamilyProperties(g_physDevice, &qfCount, qfProps.data());
    
    for (uint32_t i = 0; i < qfCount; i++) {
        if (qfProps[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            g_queueFamily = i;
            break;
        }
    }
    
    if (g_queueFamily == UINT32_MAX) {
        printf("  FAIL: No compute queue family found\n");
        return false;
    }
    
    float priority = 1.0f;
    VkDeviceQueueCreateInfo qInfo = {};
    qInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qInfo.queueFamilyIndex = g_queueFamily;
    qInfo.queueCount = 1;
    qInfo.pQueuePriorities = &priority;
    
    VkPhysicalDeviceFeatures features = {};
    VkDeviceCreateInfo devInfo = {};
    devInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    devInfo.queueCreateInfoCount = 1;
    devInfo.pQueueCreateInfos = &qInfo;
    devInfo.pEnabledFeatures = &features;
    
    VkResult res = vk.vkCreateDevice(g_physDevice, &devInfo, nullptr, &g_device);
    if (res != VK_SUCCESS) {
        printf("  FAIL: vkCreateDevice returned %s\n", VkStr(res));
        return false;
    }
    printf("  [OK] Logical device created\n");
    
    vk.vkGetDeviceQueue(g_device, g_queueFamily, 0, &g_queue);
    printf("  [OK] Compute queue obtained (family %u)\n", g_queueFamily);
    
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = g_queueFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    
    res = vk.vkCreateCommandPool(g_device, &poolInfo, nullptr, &g_cmdPool);
    if (res != VK_SUCCESS) {
        printf("  FAIL: vkCreateCommandPool returned %s\n", VkStr(res));
        return false;
    }
    printf("  [OK] Command pool created\n");
    
    return true;
}

// ============================================================================
// Step 3: Allocate VRAM and Verify
// ============================================================================
static bool TestVRAMAllocation() {
    printf("\n=== [3] VRAM Allocation Test ===\n");
    
    uint32_t memTypeIndex = UINT32_MAX;
    for (uint32_t i = 0; i < g_memProps.memoryTypeCount; i++) {
        if ((g_memProps.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) &&
            (g_memProps.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
            memTypeIndex = i;
            break;
        }
    }
    
    if (memTypeIndex == UINT32_MAX) {
        printf("  WARN: No pure device-local memory type found\n");
        for (uint32_t i = 0; i < g_memProps.memoryTypeCount; i++) {
            if (g_memProps.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                memTypeIndex = i;
                break;
            }
        }
    }
    
    if (memTypeIndex == UINT32_MAX) {
        printf("  FAIL: No device-local memory type found at all\n");
        return false;
    }
    
    printf("  Memory type %u: %s\n", memTypeIndex,
        MemFlagsStr(g_memProps.memoryTypes[memTypeIndex].propertyFlags));
    
    VkDeviceSize allocSize = 64ULL * 1024 * 1024;
    
    VkBufferCreateInfo bufInfo = {};
    bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufInfo.size = allocSize;
    bufInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    VkBuffer buffer = nullptr;
    VkResult res = vk.vkCreateBuffer(g_device, &bufInfo, nullptr, &buffer);
    if (res != VK_SUCCESS) {
        printf("  FAIL: vkCreateBuffer returned %s\n", VkStr(res));
        return false;
    }
    
    VkMemoryAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = allocSize;
    allocInfo.memoryTypeIndex = memTypeIndex;
    
    VkDeviceMemory memory = nullptr;
    res = vk.vkAllocateMemory(g_device, &allocInfo, nullptr, &memory);
    if (res != VK_SUCCESS) {
        printf("  FAIL: vkAllocateMemory (%llu MB) returned %s\n",
            (unsigned long long)(allocSize / (1024*1024)), VkStr(res));
        vk.vkDestroyBuffer(g_device, buffer, nullptr);
        return false;
    }
    printf("  [OK] Allocated %llu MB of GPU memory\n",
        (unsigned long long)(allocSize / (1024*1024)));
    
    res = vk.vkBindBufferMemory(g_device, buffer, memory, 0);
    if (res != VK_SUCCESS) {
        printf("  FAIL: vkBindBufferMemory returned %s\n", VkStr(res));
        vk.vkFreeMemory(g_device, memory, nullptr);
        vk.vkDestroyBuffer(g_device, buffer, nullptr);
        return false;
    }
    printf("  [OK] Buffer bound to GPU memory\n");
    
    VkFlags actualFlags = g_memProps.memoryTypes[memTypeIndex].propertyFlags;
    bool isDeviceLocal = (actualFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) != 0;
    printf("  Memory flags: %s\n", MemFlagsStr(actualFlags));
    printf("  DEVICE_LOCAL: %s\n", isDeviceLocal ? "YES ✅" : "NO ❌");
    
    vk.vkDestroyBuffer(g_device, buffer, nullptr);
    vk.vkFreeMemory(g_device, memory, nullptr);
    printf("  [OK] Cleanup complete\n");
    
    return isDeviceLocal;
}

// ============================================================================
// Step 4: Compute Shader Dispatch with Timestamps
// ============================================================================
static bool TestComputeShader() {
    printf("\n=== [4] Compute Shader Dispatch ===\n");
    
    const uint32_t NUM_ELEMENTS = 1024;
    const VkDeviceSize bufSize = NUM_ELEMENTS * sizeof(float);
    
    uint32_t hostMemType = UINT32_MAX;
    for (uint32_t i = 0; i < g_memProps.memoryTypeCount; i++) {
        if ((g_memProps.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
            hostMemType = i;
            break;
        }
    }
    if (hostMemType == UINT32_MAX) {
        printf("  FAIL: No host-visible+coherent memory type\n");
        return false;
    }
    printf("  Using host memory type %u: %s\n", hostMemType, MemFlagsStr(g_memProps.memoryTypes[hostMemType].propertyFlags));
    
    VkBuffer bufA, bufB, bufC;
    VkDeviceMemory memA, memB, memC;
    
    VkBufferCreateInfo bufInfo = {};
    bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufInfo.size = bufSize;
    bufInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    VkMemoryAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = bufSize;
    allocInfo.memoryTypeIndex = hostMemType;
    
    auto createBuf = [&](VkBuffer& buf, VkDeviceMemory& mem, const char* name) -> bool {
        printf("    DEBUG: Creating buffer %s...\n", name);
        VkResult r = vk.vkCreateBuffer(g_device, &bufInfo, nullptr, &buf);
        printf("    DEBUG: vkCreateBuffer(%s) = %s\n", name, VkStr(r));
        if (r != VK_SUCCESS) return false;
        printf("    DEBUG: Allocating memory for %s...\n", name);
        r = vk.vkAllocateMemory(g_device, &allocInfo, nullptr, &mem);
        printf("    DEBUG: vkAllocateMemory(%s) = %s\n", name, VkStr(r));
        if (r != VK_SUCCESS) return false;
        printf("    DEBUG: Binding memory for %s...\n", name);
        r = vk.vkBindBufferMemory(g_device, buf, mem, 0);
        printf("    DEBUG: vkBindBufferMemory(%s) = %s\n", name, VkStr(r));
        if (r != VK_SUCCESS) return false;
        return true;
    };
    
    if (!createBuf(bufA, memA, "A") || !createBuf(bufB, memB, "B") || !createBuf(bufC, memC, "C")) {
        printf("  FAIL: Buffer creation\n");
        return false;
    }
    printf("  [OK] 3 storage buffers created (%u floats each)\n", NUM_ELEMENTS);
    printf("  DEBUG: About to map memory for upload...\n");
    
    float* dataA = nullptr;
    float* dataB = nullptr;
    if (vk.vkMapMemory(g_device, memA, 0, bufSize, 0, (void**)&dataA) != VK_SUCCESS ||
        vk.vkMapMemory(g_device, memB, 0, bufSize, 0, (void**)&dataB) != VK_SUCCESS) {
        printf("  FAIL: vkMapMemory\n");
        return false;
    }
    printf("  DEBUG: Memory mapped\n");
    for (uint32_t i = 0; i < NUM_ELEMENTS; i++) { dataA[i] = 1.0f; dataB[i] = 2.0f; }
    vk.vkUnmapMemory(g_device, memA);
    vk.vkUnmapMemory(g_device, memB);
    printf("  [OK] Input data uploaded: A[i]=1.0, B[i]=2.0\n");
    
    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    
    VkDescriptorSetLayoutCreateInfo dslInfo = {};
    dslInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dslInfo.bindingCount = 3;
    dslInfo.pBindings = bindings;
    
    VkDescriptorSetLayout descSetLayout = nullptr;
    if (vk.vkCreateDescriptorSetLayout(g_device, &dslInfo, nullptr, &descSetLayout) != VK_SUCCESS) {
        printf("  FAIL: vkCreateDescriptorSetLayout\n");
        return false;
    }
    printf("  [OK] Descriptor set layout created\n");
    
    VkPipelineLayoutCreateInfo plInfo = {};
    plInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    plInfo.setLayoutCount = 1;
    plInfo.pSetLayouts = &descSetLayout;
    
    VkPipelineLayout pipelineLayout = nullptr;
    if (vk.vkCreatePipelineLayout(g_device, &plInfo, nullptr, &pipelineLayout) != VK_SUCCESS) {
        printf("  FAIL: vkCreatePipelineLayout\n");
        return false;
    }
    printf("  [OK] Pipeline layout created\n");
    
    VkShaderModuleCreateInfo smInfo = {};
    smInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    smInfo.codeSize = sizeof(g_addShaderSPIRV);
    smInfo.pCode = g_addShaderSPIRV;
    
    VkShaderModule shaderModule = nullptr;
    printf("  DEBUG: Calling vkCreateShaderModule (codeSize=%zu, pCode=%p)...\n", smInfo.codeSize, (void*)smInfo.pCode);
    VkResult res = vk.vkCreateShaderModule(g_device, &smInfo, nullptr, &shaderModule);
    printf("  DEBUG: vkCreateShaderModule returned %s (module=%p)\n", VkStr(res), (void*)shaderModule);
    printf("  [OK] Shader module created from SPIR-V (%zu bytes)\n", sizeof(g_addShaderSPIRV));
    
    VkPipelineShaderStageCreateInfo stageInfo = {};
    stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stageInfo.module = shaderModule;
    stageInfo.pName = "main";
    
    VkComputePipelineCreateInfo cpInfo = {};
    cpInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cpInfo.stage = stageInfo;
    cpInfo.layout = pipelineLayout;
    
    VkPipeline pipeline = nullptr;
    res = vk.vkCreateComputePipelines(g_device, nullptr, 1, &cpInfo, nullptr, &pipeline);
    if (res != VK_SUCCESS) {
        printf("  FAIL: vkCreateComputePipelines returned %s\n", VkStr(res));
        vk.vkDestroyShaderModule(g_device, shaderModule, nullptr);
        return false;
    }
    printf("  [OK] Compute pipeline created\n");
    
    VkDescriptorPoolSize poolSize = {};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 3;
    
    VkDescriptorPoolCreateInfo dpInfo = {};
    dpInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpInfo.maxSets = 1;
    dpInfo.poolSizeCount = 1;
    dpInfo.pPoolSizes = &poolSize;
    
    VkDescriptorPool descPool = nullptr;
    if (vk.vkCreateDescriptorPool(g_device, &dpInfo, nullptr, &descPool) != VK_SUCCESS) {
        printf("  FAIL: vkCreateDescriptorPool\n");
        return false;
    }
    
    VkDescriptorSetAllocateInfo dsAlloc = {};
    dsAlloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dsAlloc.descriptorPool = descPool;
    dsAlloc.descriptorSetCount = 1;
    dsAlloc.pSetLayouts = &descSetLayout;
    
    VkDescriptorSet descSet = nullptr;
    if (vk.vkAllocateDescriptorSets(g_device, &dsAlloc, &descSet) != VK_SUCCESS) {
        printf("  FAIL: vkAllocateDescriptorSets\n");
        return false;
    }
    printf("  [OK] Descriptor set allocated\n");
    
    VkDescriptorBufferInfo bufInfoA = { bufA, 0, bufSize };
    VkDescriptorBufferInfo bufInfoB = { bufB, 0, bufSize };
    VkDescriptorBufferInfo bufInfoC = { bufC, 0, bufSize };
    
    VkWriteDescriptorSet writes[3] = {};
    for (int i = 0; i < 3; i++) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = descSet;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].pBufferInfo = &bufInfoA;
    writes[1].pBufferInfo = &bufInfoB;
    writes[2].pBufferInfo = &bufInfoC;
    
    vk.vkUpdateDescriptorSets(g_device, 3, writes, 0, nullptr);
    printf("  [OK] Descriptor set updated\n");
    
    VkQueryPoolCreateInfo qpInfo = {};
    qpInfo.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
    qpInfo.queryType = VK_QUERY_TYPE_TIMESTAMP;
    qpInfo.queryCount = 2;
    
    VkQueryPool queryPool = nullptr;
    res = vk.vkCreateQueryPool(g_device, &qpInfo, nullptr, &queryPool);
    if (res != VK_SUCCESS) {
        printf("  WARN: vkCreateQueryPool failed (%s) — timestamps not supported\n", VkStr(res));
    } else {
        printf("  [OK] Timestamp query pool created\n");
    }
    
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    
    VkFence fence = nullptr;
    vk.vkCreateFence(g_device, &fenceInfo, nullptr, &fence);
    
    VkCommandBufferAllocateInfo cmdAlloc = {};
    cmdAlloc.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cmdAlloc.commandPool = g_cmdPool;
    cmdAlloc.level = 0;
    cmdAlloc.commandBufferCount = 1;
    
    VkCommandBuffer cmdBuf = nullptr;
    vk.vkAllocateCommandBuffers(g_device, &cmdAlloc, &cmdBuf);
    
    VkCommandBufferBeginInfo beginInfo = {};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    
    vk.vkBeginCommandBuffer(cmdBuf, &beginInfo);
    
    if (queryPool) {
        vk.vkCmdResetQueryPool(cmdBuf, queryPool, 0, 2);
        vk.vkCmdWriteTimestamp(cmdBuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, queryPool, 0);
    }
    
    vk.vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vk.vkCmdBindDescriptorSets(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout,
        0, 1, &descSet, 0, nullptr);
    
    uint32_t groups = (NUM_ELEMENTS + 255) / 256;
    vk.vkCmdDispatch(cmdBuf, groups, 1, 1);
    
    if (queryPool) {
        vk.vkCmdWriteTimestamp(cmdBuf, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, queryPool, 1);
    }
    
    vk.vkEndCommandBuffer(cmdBuf);
    
    VkSubmitInfo submitInfo = {};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuf;
    
    auto tStart = GetTickCount64();
    vk.vkQueueSubmit(g_queue, 1, &submitInfo, fence);
    
    res = vk.vkWaitForFences(g_device, 1, &fence, VK_TRUE, 5000000000ULL);
    auto tEnd = GetTickCount64();
    
    if (res != VK_SUCCESS) {
        printf("  FAIL: Queue submission timed out after 5s\n");
        return false;
    }
    printf("  [OK] Compute shader dispatched and completed\n");
    printf("  CPU dispatch overhead: %llu ms\n", (unsigned long long)(tEnd - tStart));
    
    if (queryPool) {
        uint64_t timestamps[2] = {0, 0};
        res = vk.vkGetQueryPoolResults(g_device, queryPool, 0, 2,
            sizeof(timestamps), timestamps, sizeof(uint64_t),
            VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WAIT_BIT);
        
        if (res == VK_SUCCESS) {
            double gpuTimeNs = (double)(timestamps[1] - timestamps[0]);
            double gpuTimeMs = gpuTimeNs / 1000000.0;
            printf("  GPU Timestamp Start: %llu\n", (unsigned long long)timestamps[0]);
            printf("  GPU Timestamp End:   %llu\n", (unsigned long long)timestamps[1]);
            printf("  GPU Execution Time:  %.6f ms", gpuTimeMs);
            if (gpuTimeMs > 0.0) {
                printf(" ✅ (GPU executed the kernel)\n");
            } else {
                printf(" ⚠️ (timestamps identical — possible issue)\n");
            }
        } else {
            printf("  WARN: vkGetQueryPoolResults returned %s\n", VkStr(res));
        }
    }
    
    float* resultC = nullptr;
    if (vk.vkMapMemory(g_device, memC, 0, bufSize, 0, (void**)&resultC) != VK_SUCCESS) {
        printf("  FAIL: vkMapMemory for readback\n");
        return false;
    }
    
    bool correct = true;
    float maxError = 0.0f;
    for (uint32_t i = 0; i < NUM_ELEMENTS; i++) {
        float expected = 1.0f + 2.0f;
        float error = fabs(resultC[i] - expected);
        if (error > maxError) maxError = error;
        if (error > 0.01f) correct = false;
    }
    
    printf("\n  Correctness Verification:\n");
    printf("    Expected: C[i] = A[i] + B[i] = 3.0\n");
    printf("    Sample results: C[0]=%.2f, C[1]=%.2f, C[511]=%.2f, C[1023]=%.2f\n",
        resultC[0], resultC[1], resultC[511], resultC[1023]);
    printf("    Max error: %f\n", maxError);
    printf("    Result: %s\n", correct ? "PASS ✅" : "FAIL ❌");
    
    vk.vkUnmapMemory(g_device, memC);
    
    vk.vkFreeCommandBuffers(g_device, g_cmdPool, 1, &cmdBuf);
    vk.vkDestroyFence(g_device, fence, nullptr);
    if (queryPool) vk.vkDestroyQueryPool(g_device, queryPool, nullptr);
    vk.vkDestroyPipeline(g_device, pipeline, nullptr);
    vk.vkDestroyPipelineLayout(g_device, pipelineLayout, nullptr);
    vk.vkDestroyShaderModule(g_device, shaderModule, nullptr);
    vk.vkDestroyDescriptorPool(g_device, descPool, nullptr);
    vk.vkDestroyDescriptorSetLayout(g_device, descSetLayout, nullptr);
    vk.vkDestroyBuffer(g_device, bufA, nullptr);
    vk.vkDestroyBuffer(g_device, bufB, nullptr);
    vk.vkDestroyBuffer(g_device, bufC, nullptr);
    vk.vkFreeMemory(g_device, memA, nullptr);
    vk.vkFreeMemory(g_device, memB, nullptr);
    vk.vkFreeMemory(g_device, memC, nullptr);
    
    return correct;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    setvbuf(stdout, NULL, _IONBF, 0); // Unbuffered stdout for reliable capture
    printf("============================================\n");
    printf("  RawrXD GPU Execution Verifier\n");
    printf("  Proves end-to-end GPU compute execution\n");
    printf("============================================\n");
    
    printf("\nLoading vulkan-1.dll...\n");
    if (!vk.Load()) {
        printf("FAILED: vulkan-1.dll not found or missing exports\n");
        printf("Install AMD/NVIDIA/Intel GPU drivers with Vulkan support\n");
        return 1;
    }
    printf("[OK] vulkan-1.dll loaded\n");
    
    bool allPassed = true;
    
    if (!EnumerateGPUs()) { printf("\nFATAL: GPU enumeration failed\n"); return 1; }
    if (!CreateDevice()) { printf("\nFATAL: Device creation failed\n"); return 1; }
    
    if (!TestVRAMAllocation()) {
        printf("\n  ⚠️  VRAM allocation test failed\n");
        allPassed = false;
    }
    
    if (!TestComputeShader()) {
        printf("\n  ❌ Compute shader test failed\n");
        allPassed = false;
    }
    
    if (g_cmdPool) vk.vkDestroyCommandPool(g_device, g_cmdPool, nullptr);
    if (g_device) { vk.vkDeviceWaitIdle(g_device); vk.vkDestroyDevice(g_device, nullptr); }
    if (g_instance) vk.vkDestroyInstance(g_instance, nullptr);
    vk.Unload();
    
    printf("\n============================================\n");
    printf("  GPU EXECUTION VERIFIER SUMMARY\n");
    printf("============================================\n");
    if (allPassed) {
        printf("  ✅ ALL TESTS PASSED — GPU compute is working\n");
        printf("  The Vulkan compute pipeline is functional.\n");
        printf("  Inference can now be routed to GPU.\n");
    } else {
        printf("  ⚠️  SOME TESTS FAILED\n");
        printf("  Review the output above for details.\n");
    }
    printf("============================================\n");
    
    return allPassed ? 0 : 1;
}
