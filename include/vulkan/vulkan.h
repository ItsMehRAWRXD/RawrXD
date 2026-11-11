#pragma once
// Vulkan header resolution.
//
// This file previously shadowed <vulkan/vulkan.h> with a stub that declared
// only opaque handles. That made src/vulkan_compute.cpp uncompilable in the
// main build: the stub provides no Vk*CreateInfo structs, no vk* entry points,
// and several VK_STRUCTURE_TYPE_* macros with values that disagree with the
// real specification.
//
// Resolution order:
//   1. If the build defines RAWXRD_VULKAN_SDK_HEADER (CMake sets this to the
//      absolute path of the installed SDK header when Vulkan is found), and
//      that file actually exists, include the real Vulkan header.
//   2. Otherwise fall back to the dependency-free stub below, so builds
//      without a Vulkan SDK still configure.
//
// The SDK path is used absolutely rather than as <vulkan/vulkan.h>, because
// that spelling would resolve back to this file.

#if defined(RAWXRD_VULKAN_SDK_HEADER)
#  if defined(__has_include)
#    if __has_include(RAWXRD_VULKAN_SDK_HEADER)
#      include RAWXRD_VULKAN_SDK_HEADER
#      define RAWXRD_USING_REAL_VULKAN_HEADER 1
#    endif
#  elif !defined(_MSC_VER)
#    include RAWXRD_VULKAN_SDK_HEADER
#    define RAWXRD_USING_REAL_VULKAN_HEADER 1
#  endif
#endif

#ifndef RAWXRD_USING_REAL_VULKAN_HEADER

// ---------------------------------------------------------------------------
// Dependency-free fallback. This is only reached when no Vulkan SDK header is
// available. Code that calls vk* entry points will not compile in this mode;
// that is intentional and is why the real header must be preferred above.
// ---------------------------------------------------------------------------
#include <cstdint>

// Opaque handle types - forward declare struct, then typedef pointer
struct VkInstance_T; typedef struct VkInstance_T* VkInstance;
struct VkPhysicalDevice_T; typedef struct VkPhysicalDevice_T* VkPhysicalDevice;
struct VkDevice_T; typedef struct VkDevice_T* VkDevice;
struct VkQueue_T; typedef struct VkQueue_T* VkQueue;
struct VkCommandBuffer_T; typedef struct VkCommandBuffer_T* VkCommandBuffer;
struct VkFence_T; typedef struct VkFence_T* VkFence;
struct VkSemaphore_T; typedef struct VkSemaphore_T* VkSemaphore;
struct VkBuffer_T; typedef struct VkBuffer_T* VkBuffer;
struct VkDeviceMemory_T; typedef struct VkDeviceMemory_T* VkDeviceMemory;
struct VkShaderModule_T; typedef struct VkShaderModule_T* VkShaderModule;
struct VkPipelineLayout_T; typedef struct VkPipelineLayout_T* VkPipelineLayout;
struct VkPipeline_T; typedef struct VkPipeline_T* VkPipeline;
struct VkDescriptorSetLayout_T; typedef struct VkDescriptorSetLayout_T* VkDescriptorSetLayout;
struct VkDescriptorPool_T; typedef struct VkDescriptorPool_T* VkDescriptorPool;
struct VkDescriptorSet_T; typedef struct VkDescriptorSet_T* VkDescriptorSet;
struct VkSampler_T; typedef struct VkSampler_T* VkSampler;
struct VkImage_T; typedef struct VkImage_T* VkImage;
struct VkImageView_T; typedef struct VkImageView_T* VkImageView;
struct VkRenderPass_T; typedef struct VkRenderPass_T* VkRenderPass;
struct VkFramebuffer_T; typedef struct VkFramebuffer_T* VkFramebuffer;
struct VkQueryPool_T; typedef struct VkQueryPool_T* VkQueryPool;
struct VkAccelerationStructureKHR_T; typedef struct VkAccelerationStructureKHR_T* VkAccelerationStructureKHR;
struct VkEvent_T; typedef struct VkEvent_T* VkEvent;
struct VkQueryPool_T; typedef struct VkQueryPool_T* VkQueryPool;
struct VkCommandPool_T; typedef struct VkCommandPool_T* VkCommandPool;

#define VK_NULL_HANDLE 0

typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;
typedef uint32_t VkSampleCountFlagBits;

typedef struct VkPhysicalDeviceProperties {
    uint32_t apiVersion;
    uint32_t driverVersion;
    uint32_t vendorID;
    uint32_t deviceID;
    int32_t deviceType;
    char deviceName[256];
    uint8_t pipelineCacheUUID[16];
    uint32_t limits[100];
    uint32_t sparseProperties[10];
} VkPhysicalDeviceProperties;

typedef struct VkPhysicalDeviceMemoryProperties {
    uint32_t memoryTypeCount;
    uint32_t memoryTypes[32];
    uint32_t memoryHeapCount;
    uint32_t memoryHeaps[16];
} VkPhysicalDeviceMemoryProperties;

typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;
typedef uint32_t VkSampleCountFlagBits;

typedef uint32_t VkShaderStageFlagBits;
typedef uint32_t VkPipelineStageFlagBits;
typedef uint32_t VkAccessFlagBits;
typedef uint32_t VkImageLayout;
typedef uint32_t VkBufferUsageFlagBits;
typedef uint32_t VkMemoryPropertyFlagBits;
typedef uint32_t VkCommandBufferLevel;
typedef uint32_t VkCommandBufferUsageFlagBits;
typedef uint32_t VkFenceCreateFlagBits;
typedef uint32_t VkPipelineBindPoint;
typedef uint32_t VkStructureType;
typedef int32_t VkResult;
typedef uint32_t VkQueueFlags;
typedef uint32_t VkMemoryHeapFlagBits;
typedef uint32_t VkMemoryTypeFlagBits;

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
#define VK_ERROR_TOO_MANY_OBJECTS -10
#define VK_ERROR_FORMAT_NOT_SUPPORTED -11
#define VK_ERROR_FRAGMENTED_POOL -12
#define VK_ERROR_UNKNOWN -13

#define VK_STRUCTURE_TYPE_APPLICATION_INFO 0
#define VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO 1
#define VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO 2
#define VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO 3
#define VK_STRUCTURE_TYPE_SUBMIT_INFO 4
#define VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO 5
#define VK_STRUCTURE_TYPE_FENCE_CREATE_INFO 6
#define VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO 7
#define VK_STRUCTURE_TYPE_EVENT_CREATE_INFO 8
#define VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO 9
#define VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO 10
#define VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO 11
#define VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO 12
#define VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO 13
#define VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO 14
#define VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO 14
#define VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO 15
#define VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO 15
#define VK_STRUCTURE_TYPE_PIPELINE_TESSELLATION_STATE_CREATE_INFO 16
#define VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO 17
#define VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO 18
#define VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO 19
#define VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO 20
#define VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO 21
#define VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO 21
#define VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO 22
#define VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO 23
#define VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO 23
#define VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO 24
#define VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO 25
#define VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO 26
#define VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO 27
#define VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET 28
#define VK_STRUCTURE_TYPE_COPY_DESCRIPTOR_SET 28

#define VK_MAKE_VERSION(major, minor, patch) \
    (((major) << 22) | ((minor) << 12) | (patch))

#define VK_VERSION_MAJOR(version) ((version) >> 22)
#define VK_VERSION_MINOR(version) (((version) >> 12) & 0x3ff)
#define VK_VERSION_PATCH(version) ((version) & 0xfff)

#define VK_API_VERSION_1_0 ((1 << 22) | (0 << 12) | 0)
#define VK_API_VERSION_1_1 ((1 << 22) | (1 << 12) | 0)
#define VK_API_VERSION_1_2 ((1 << 22) | (2 << 12) | 0)
#define VK_API_VERSION_1_3 ((1 << 22) | (3 << 12) | 0)

#define VK_API_VERSION VK_API_VERSION_1_0


typedef uint32_t VkMemoryPropertyFlags;
typedef uint32_t VkMemoryHeapFlags;
typedef uint32_t VkMemoryTypeFlags;
typedef uint32_t VkQueueFlags;
typedef uint32_t VkShaderStageFlags;
typedef uint32_t VkPipelineStageFlags;
typedef uint32_t VkAccessFlags;
typedef uint32_t VkBufferUsageFlags;
typedef uint32_t VkImageUsageFlags;
typedef uint32_t VkImageCreateFlags;
typedef uint32_t VkMemoryPropertyFlags;
typedef uint32_t VkMemoryHeapFlags;
typedef uint32_t VkMemoryTypeFlags;
typedef uint32_t VkQueueFlags;
typedef uint32_t VkShaderStageFlags;
typedef uint32_t VkPipelineStageFlags;
typedef uint32_t VkAccessFlags;
typedef uint32_t VkBufferUsageFlags;
typedef uint32_t VkImageUsageFlags;
typedef uint32_t VkImageCreateFlags;
typedef uint32_t VkCommandBufferUsageFlags;
typedef uint32_t VkQueryControlFlags;
typedef uint32_t VkCommandPoolCreateFlags;
typedef uint32_t VkCommandBufferResetFlags;
typedef uint32_t VkFenceCreateFlags;
typedef uint32_t VkSemaphoreCreateFlags;
typedef uint32_t VkEventCreateFlags;
typedef uint32_t VkQueryPoolCreateFlags;
typedef uint32_t VkBufferCreateFlags;
typedef uint32_t VkImageCreateFlags;
typedef uint32_t VkImageViewCreateFlags;
typedef uint32_t VkPipelineCreateFlags;
typedef uint32_t VkPipelineLayoutCreateFlags;
typedef uint32_t VkDescriptorSetLayoutCreateFlags;
typedef uint32_t VkDescriptorPoolCreateFlags;
typedef uint32_t VkSamplerCreateFlags;
typedef uint32_t VkQueryPoolCreateFlags;
typedef uint32_t VkRenderPassCreateFlags;
typedef uint32_t VkFramebufferCreateFlags;
typedef uint32_t VkCommandPoolCreateFlags;
typedef uint32_t VkCommandBufferAllocateFlags;
typedef uint32_t VkPipelineLayoutCreateFlags;
typedef uint32_t VkPipelineShaderStageCreateFlags;
typedef uint32_t VkPipelineVertexInputStateCreateFlags;
typedef uint32_t VkPipelineInputAssemblyStateCreateFlags;
typedef uint32_t VkPipelineTessellationStateCreateFlags;
typedef uint32_t VkPipelineViewportStateCreateFlags;
typedef uint32_t VkPipelineRasterizationStateCreateFlags;
typedef uint32_t VkPipelineMultisampleStateCreateFlags;
typedef uint32_t VkPipelineDepthStencilStateCreateFlags;
typedef uint32_t VkPipelineColorBlendStateCreateFlags;
typedef uint32_t VkPipelineDynamicStateCreateFlags;
typedef uint32_t VkPipelineLayoutCreateFlags;
typedef uint32_t VkDescriptorSetLayoutCreateFlags;
typedef uint32_t VkDescriptorPoolCreateFlags;
typedef uint32_t VkDescriptorSetAllocateFlags;
typedef uint32_t VkDescriptorSetLayoutBindingFlags;
typedef uint32_t VkSamplerCreateFlags;
typedef uint32_t VkQueryPoolCreateFlags;
typedef uint32_t VkRenderPassCreateFlags;
typedef uint32_t VkFramebufferCreateFlags;
typedef uint32_t VkCommandPoolCreateFlags;
typedef uint32_t VkCommandBufferAllocateFlags;
typedef uint32_t VkPipelineLayoutCreateFlags;
typedef uint32_t VkPipelineShaderStageCreateFlags;
typedef uint32_t VkPipelineVertexInputStateCreateFlags;
typedef uint32_t VkPipelineInputAssemblyStateCreateFlags;
typedef uint32_t VkPipelineTessellationStateCreateFlags;
typedef uint32_t VkPipelineViewportStateCreateFlags;
typedef uint32_t VkPipelineRasterizationStateCreateFlags;
typedef uint32_t VkPipelineMultisampleStateCreateFlags;
typedef uint32_t VkPipelineDepthStencilStateCreateFlags;
typedef uint32_t VkPipelineColorBlendStateCreateFlags;
typedef uint32_t VkPipelineDynamicStateCreateFlags;

#endif // !RAWXRD_USING_REAL_VULKAN_HEADER
