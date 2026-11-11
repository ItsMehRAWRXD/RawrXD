// ============================================================================
// Production Vulkan Benchmark - Dynamic Loading
// ============================================================================
// Loads Vulkan at runtime - no need for SDK
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <cmath>
#include <cstring>
#include <windows.h>

// Vulkan function pointers
typedef uint32_t VkResult;
typedef uint64_t VkDeviceSize;
typedef uint64_t VkDeviceAddress;
typedef uint64_t VkFlags;
typedef uint64_t VkDeviceMemory;
typedef uint64_t VkBuffer;
typedef uint64_t VkCommandBuffer;
typedef uint64_t VkQueue;
typedef uint64_t VkCommandPool;
typedef uint64_t VkDevice;
typedef uint64_t VkPhysicalDevice;
typedef uint64_t VkInstance;
typedef uint64_t VkShaderModule;
typedef uint64_t VkPipeline;
typedef uint64_t VkPipelineLayout;
typedef uint64_t VkDescriptorSetLayout;
typedef uint64_t VkDescriptorPool;
typedef uint64_t VkDescriptorSet;
typedef uint64_t VkFence;
typedef uint64_t VkSemaphore;

#define VK_NULL_HANDLE 0ULL
#define VK_SUCCESS 0
#define VK_ERROR_INITIALIZATION_FAILED -3

// Device type
#define VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU 1
#define VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU 2

// Vendor IDs
#define VK_VENDOR_ID_AMD 0x1002
#define VK_VENDOR_ID_NVIDIA 0x10DE
#define VK_VENDOR_ID_INTEL 0x8086

// Queue flags
#define VK_QUEUE_COMPUTE_BIT 0x00000002

// Memory properties
#define VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT 0x00000001
#define VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT 0x00000002
#define VK_MEMORY_PROPERTY_HOST_COHERENT_BIT 0x00000004

// Buffer usage
#define VK_BUFFER_USAGE_STORAGE_BUFFER_BIT 0x00000020
#define VK_BUFFER_USAGE_TRANSFER_SRC_BIT 0x00000001
#define VK_BUFFER_USAGE_TRANSFER_DST_BIT 0x00000002

// Shader stage
#define VK_SHADER_STAGE_COMPUTE_BIT 0x00000020

// Descriptor type
#define VK_DESCRIPTOR_TYPE_STORAGE_BUFFER 0

// Pipeline bind point
#define VK_PIPELINE_BIND_POINT_COMPUTE 0

// Fence
#define VK_FENCE_CREATE_SIGNALED_BIT 0x00000001

// Wait
#define VK_TRUE 1
#define VK_FALSE 0
#define VK_WHOLE_SIZE (~0ULL)

struct VkApplicationInfo {
    uint32_t sType;
    const void* pNext;
    const char* pApplicationName;
    uint32_t applicationVersion;
    const char* pEngineName;
    uint32_t engineVersion;
    uint32_t apiVersion;
};

struct VkInstanceCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    const VkApplicationInfo* pApplicationInfo;
    uint32_t enabledLayerCount;
    const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char* const* ppEnabledExtensionNames;
};

struct VkPhysicalDeviceProperties {
    uint32_t apiVersion;
    uint32_t driverVersion;
    uint32_t vendorID;
    uint32_t deviceID;
    uint32_t deviceType;
    char deviceName[256];
    uint8_t pipelineCacheUUID[16];
    // ... more fields
};

struct VkPhysicalDeviceMemoryProperties {
    uint32_t memoryTypeCount;
    struct {
        VkFlags propertyFlags;
        uint32_t heapIndex;
    } memoryTypes[32];
    uint32_t memoryHeapCount;
    struct {
        VkDeviceSize size;
        VkFlags flags;
    } memoryHeaps[16];
};

struct VkQueueFamilyProperties {
    VkFlags queueFlags;
    uint32_t queueCount;
    uint32_t timestampValidBits;
    VkDeviceSize minImageTransferGranularity;
};

struct VkDeviceQueueCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    uint32_t queueFamilyIndex;
    uint32_t queueCount;
    const float* pQueuePriorities;
};

struct VkDeviceCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    uint32_t queueCreateInfoCount;
    const VkDeviceQueueCreateInfo* pQueueCreateInfos;
    uint32_t enabledLayerCount;
    const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char* const* ppEnabledExtensionNames;
    const void* pEnabledFeatures;
};

struct VkCommandPoolCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    uint32_t queueFamilyIndex;
};

struct VkCommandBufferAllocateInfo {
    uint32_t sType;
    const void* pNext;
    VkCommandPool commandPool;
    uint32_t level;
    uint32_t commandBufferCount;
};

struct VkBufferCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    VkDeviceSize size;
    VkFlags usage;
    uint32_t sharingMode;
    uint32_t queueFamilyIndexCount;
    const uint32_t* pQueueFamilyIndices;
};

struct VkMemoryAllocateInfo {
    uint32_t sType;
    const void* pNext;
    VkDeviceSize allocationSize;
    uint32_t memoryTypeIndex;
};

struct VkShaderModuleCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    size_t codeSize;
    const uint32_t* pCode;
};

struct VkDescriptorSetLayoutBinding {
    uint32_t binding;
    uint32_t descriptorType;
    uint32_t descriptorCount;
    VkFlags stageFlags;
    const void* pImmutableSamplers;
};

struct VkDescriptorSetLayoutCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    uint32_t bindingCount;
    const VkDescriptorSetLayoutBinding* pBindings;
};

struct VkPipelineLayoutCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    uint32_t setLayoutCount;
    const VkDescriptorSetLayout* pSetLayouts;
    uint32_t pushConstantRangeCount;
    const void* pPushConstantRanges;
};

struct VkComputePipelineCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    uint32_t stage_sType;
    VkFlags stage_flags;
    uint32_t stage_stage;
    VkShaderModule stage_module;
    const char* stage_pName;
    const void* stage_pSpecializationInfo;
    VkPipelineLayout layout;
    VkPipeline basePipelineHandle;
    int32_t basePipelineIndex;
};

struct VkDescriptorPoolSize {
    uint32_t type;
    uint32_t descriptorCount;
};

struct VkDescriptorPoolCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    uint32_t maxSets;
    uint32_t poolSizeCount;
    const VkDescriptorPoolSize* pPoolSizes;
};

struct VkDescriptorSetAllocateInfo {
    uint32_t sType;
    const void* pNext;
    VkDescriptorPool descriptorPool;
    uint32_t descriptorSetCount;
    const VkDescriptorSetLayout* pSetLayouts;
};

struct VkDescriptorBufferInfo {
    VkBuffer buffer;
    VkDeviceSize offset;
    VkDeviceSize range;
};

struct VkWriteDescriptorSet {
    uint32_t sType;
    const void* pNext;
    VkDescriptorSet dstSet;
    uint32_t dstBinding;
    uint32_t dstArrayElement;
    uint32_t descriptorCount;
    uint32_t descriptorType;
    const void* pImageInfo;
    const VkDescriptorBufferInfo* pBufferInfo;
    const void* pTexelBufferView;
};

struct VkCommandBufferBeginInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
    const void* pInheritanceInfo;
};

struct VkSubmitInfo {
    uint32_t sType;
    const void* pNext;
    uint32_t waitSemaphoreCount;
    const VkSemaphore* pWaitSemaphores;
    const uint32_t* pWaitDstStageMask;
    uint32_t commandBufferCount;
    const VkCommandBuffer* pCommandBuffers;
    uint32_t signalSemaphoreCount;
    const VkSemaphore* pSignalSemaphores;
};

struct VkFenceCreateInfo {
    uint32_t sType;
    const void* pNext;
    VkFlags flags;
};

struct VkMemoryRequirements {
    VkDeviceSize size;
    VkDeviceSize alignment;
    uint32_t memoryTypeBits;
};

// Function pointers
typedef VkResult (*PFN_vkCreateInstance)(const VkInstanceCreateInfo*, const void*, VkInstance*);
typedef void (*PFN_vkDestroyInstance)(VkInstance);
typedef VkResult (*PFN_vkEnumeratePhysicalDevices)(VkInstance, uint32_t*, VkPhysicalDevice*);
typedef void (*PFN_vkGetPhysicalDeviceProperties)(VkPhysicalDevice, VkPhysicalDeviceProperties*);
typedef void (*PFN_vkGetPhysicalDeviceMemoryProperties)(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties*);
typedef void (*PFN_vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice, uint32_t*, VkQueueFamilyProperties*);
typedef VkResult (*PFN_vkCreateDevice)(VkPhysicalDevice, const VkDeviceCreateInfo*, const void*, VkDevice*);
typedef void (*PFN_vkDestroyDevice)(VkDevice);
typedef void (*PFN_vkGetDeviceQueue)(VkDevice, uint32_t, uint32_t, VkQueue*);
typedef VkResult (*PFN_vkCreateCommandPool)(VkDevice, const VkCommandPoolCreateInfo*, const void*, VkCommandPool*);
typedef void (*PFN_vkDestroyCommandPool)(VkDevice, VkCommandPool, const void*);
typedef VkResult (*PFN_vkAllocateCommandBuffers)(VkDevice, const VkCommandBufferAllocateInfo*, VkCommandBuffer*);
typedef void (*PFN_vkFreeCommandBuffers)(VkDevice, VkCommandPool, uint32_t, const VkCommandBuffer*);
typedef VkResult (*PFN_vkCreateBuffer)(VkDevice, const VkBufferCreateInfo*, const void*, VkBuffer*);
typedef void (*PFN_vkDestroyBuffer)(VkDevice, VkBuffer, const void*);
typedef void (*PFN_vkGetBufferMemoryRequirements)(VkDevice, VkBuffer, VkMemoryRequirements*);
typedef VkResult (*PFN_vkAllocateMemory)(VkDevice, const VkMemoryAllocateInfo*, const void*, VkDeviceMemory*);
typedef void (*PFN_vkFreeMemory)(VkDevice, VkDeviceMemory, const void*);
typedef VkResult (*PFN_vkBindBufferMemory)(VkDevice, VkBuffer, VkDeviceMemory, VkDeviceSize);
typedef VkResult (*PFN_vkMapMemory)(VkDevice, VkDeviceMemory, VkDeviceSize, VkDeviceSize, VkFlags, void**);
typedef void (*PFN_vkUnmapMemory)(VkDevice, VkDeviceMemory);
typedef VkResult (*PFN_vkCreateShaderModule)(VkDevice, const VkShaderModuleCreateInfo*, const void*, VkShaderModule*);
typedef void (*PFN_vkDestroyShaderModule)(VkDevice, VkShaderModule, const void*);
typedef VkResult (*PFN_vkCreateDescriptorSetLayout)(VkDevice, const VkDescriptorSetLayoutCreateInfo*, const void*, VkDescriptorSetLayout*);
typedef void (*PFN_vkDestroyDescriptorSetLayout)(VkDevice, VkDescriptorSetLayout, const void*);
typedef VkResult (*PFN_vkCreatePipelineLayout)(VkDevice, const VkPipelineLayoutCreateInfo*, const void*, VkPipelineLayout*);
typedef void (*PFN_vkDestroyPipelineLayout)(VkDevice, VkPipelineLayout, const void*);
typedef VkResult (*PFN_vkCreateComputePipelines)(VkDevice, void*, uint32_t, const VkComputePipelineCreateInfo*, const void*, VkPipeline*);
typedef void (*PFN_vkDestroyPipeline)(VkDevice, VkPipeline, const void*);
typedef VkResult (*PFN_vkCreateDescriptorPool)(VkDevice, const VkDescriptorPoolCreateInfo*, const void*, VkDescriptorPool*);
typedef void (*PFN_vkDestroyDescriptorPool)(VkDevice, VkDescriptorPool, const void*);
typedef VkResult (*PFN_vkAllocateDescriptorSets)(VkDevice, const VkDescriptorSetAllocateInfo*, VkDescriptorSet*);
typedef void (*PFN_vkUpdateDescriptorSets)(VkDevice, uint32_t, const VkWriteDescriptorSet*, uint32_t, const void*);
typedef VkResult (*PFN_vkBeginCommandBuffer)(VkCommandBuffer, const VkCommandBufferBeginInfo*);
typedef VkResult (*PFN_vkEndCommandBuffer)(VkCommandBuffer);
typedef void (*PFN_vkCmdBindPipeline)(VkCommandBuffer, uint32_t, VkPipeline);
typedef void (*PFN_vkCmdBindDescriptorSets)(VkCommandBuffer, uint32_t, VkPipelineLayout, uint32_t, uint32_t, const VkDescriptorSet*, uint32_t, const uint32_t*);
typedef void (*PFN_vkCmdDispatch)(VkCommandBuffer, uint32_t, uint32_t, uint32_t);
typedef VkResult (*PFN_vkQueueSubmit)(VkQueue, uint32_t, const VkSubmitInfo*, VkFence);
typedef VkResult (*PFN_vkQueueWaitIdle)(VkQueue);
typedef VkResult (*PFN_vkDeviceWaitIdle)(VkDevice);
typedef VkResult (*PFN_vkCreateFence)(VkDevice, const VkFenceCreateInfo*, const void*, VkFence*);
typedef void (*PFN_vkDestroyFence)(VkDevice, VkFence, const void*);
typedef VkResult (*PFN_vkWaitForFences)(VkDevice, uint32_t, const VkFence*, VkFlags, uint64_t);
typedef VkResult (*PFN_vkResetFences)(VkDevice, uint32_t, const VkFence*);

// Global function pointers
PFN_vkCreateInstance vkCreateInstance = nullptr;
PFN_vkDestroyInstance vkDestroyInstance = nullptr;
PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices = nullptr;
PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties = nullptr;
PFN_vkGetPhysicalDeviceMemoryProperties vkGetPhysicalDeviceMemoryProperties = nullptr;
PFN_vkGetPhysicalDeviceQueueFamilyProperties vkGetPhysicalDeviceQueueFamilyProperties = nullptr;
PFN_vkCreateDevice vkCreateDevice = nullptr;
PFN_vkDestroyDevice vkDestroyDevice = nullptr;
PFN_vkGetDeviceQueue vkGetDeviceQueue = nullptr;
PFN_vkCreateCommandPool vkCreateCommandPool = nullptr;
PFN_vkDestroyCommandPool vkDestroyCommandPool = nullptr;
PFN_vkAllocateCommandBuffers vkAllocateCommandBuffers = nullptr;
PFN_vkFreeCommandBuffers vkFreeCommandBuffers = nullptr;
PFN_vkCreateBuffer vkCreateBuffer = nullptr;
PFN_vkDestroyBuffer vkDestroyBuffer = nullptr;
PFN_vkGetBufferMemoryRequirements vkGetBufferMemoryRequirements = nullptr;
PFN_vkAllocateMemory vkAllocateMemory = nullptr;
PFN_vkFreeMemory vkFreeMemory = nullptr;
PFN_vkBindBufferMemory vkBindBufferMemory = nullptr;
PFN_vkMapMemory vkMapMemory = nullptr;
PFN_vkUnmapMemory vkUnmapMemory = nullptr;
PFN_vkCreateShaderModule vkCreateShaderModule = nullptr;
PFN_vkDestroyShaderModule vkDestroyShaderModule = nullptr;
PFN_vkCreateDescriptorSetLayout vkCreateDescriptorSetLayout = nullptr;
PFN_vkDestroyDescriptorSetLayout vkDestroyDescriptorSetLayout = nullptr;
PFN_vkCreatePipelineLayout vkCreatePipelineLayout = nullptr;
PFN_vkDestroyPipelineLayout vkDestroyPipelineLayout = nullptr;
PFN_vkCreateComputePipelines vkCreateComputePipelines = nullptr;
PFN_vkDestroyPipeline vkDestroyPipeline = nullptr;
PFN_vkCreateDescriptorPool vkCreateDescriptorPool = nullptr;
PFN_vkDestroyDescriptorPool vkDestroyDescriptorPool = nullptr;
PFN_vkAllocateDescriptorSets vkAllocateDescriptorSets = nullptr;
PFN_vkUpdateDescriptorSets vkUpdateDescriptorSets = nullptr;
PFN_vkBeginCommandBuffer vkBeginCommandBuffer = nullptr;
PFN_vkEndCommandBuffer vkEndCommandBuffer = nullptr;
PFN_vkCmdBindPipeline vkCmdBindPipeline = nullptr;
PFN_vkCmdBindDescriptorSets vkCmdBindDescriptorSets = nullptr;
PFN_vkCmdDispatch vkCmdDispatch = nullptr;
PFN_vkQueueSubmit vkQueueSubmit = nullptr;
PFN_vkQueueWaitIdle vkQueueWaitIdle = nullptr;
PFN_vkDeviceWaitIdle vkDeviceWaitIdle = nullptr;
PFN_vkCreateFence vkCreateFence = nullptr;
PFN_vkDestroyFence vkDestroyFence = nullptr;
PFN_vkWaitForFences vkWaitForFences = nullptr;
PFN_vkResetFences vkResetFences = nullptr;

HMODULE g_vulkanLib = nullptr;

bool LoadVulkan() {
    g_vulkanLib = LoadLibraryA("vulkan-1.dll");
    if (!g_vulkanLib) {
        std::cerr << "Failed to load vulkan-1.dll" << std::endl;
        return false;
    }

    vkCreateInstance = (PFN_vkCreateInstance)GetProcAddress(g_vulkanLib, "vkCreateInstance");
    vkDestroyInstance = (PFN_vkDestroyInstance)GetProcAddress(g_vulkanLib, "vkDestroyInstance");
    vkEnumeratePhysicalDevices = (PFN_vkEnumeratePhysicalDevices)GetProcAddress(g_vulkanLib, "vkEnumeratePhysicalDevices");
    vkGetPhysicalDeviceProperties = (PFN_vkGetPhysicalDeviceProperties)GetProcAddress(g_vulkanLib, "vkGetPhysicalDeviceProperties");
    vkGetPhysicalDeviceMemoryProperties = (PFN_vkGetPhysicalDeviceMemoryProperties)GetProcAddress(g_vulkanLib, "vkGetPhysicalDeviceMemoryProperties");
    vkGetPhysicalDeviceQueueFamilyProperties = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)GetProcAddress(g_vulkanLib, "vkGetPhysicalDeviceQueueFamilyProperties");
    vkCreateDevice = (PFN_vkCreateDevice)GetProcAddress(g_vulkanLib, "vkCreateDevice");
    vkDestroyDevice = (PFN_vkDestroyDevice)GetProcAddress(g_vulkanLib, "vkDestroyDevice");
    vkGetDeviceQueue = (PFN_vkGetDeviceQueue)GetProcAddress(g_vulkanLib, "vkGetDeviceQueue");
    vkCreateCommandPool = (PFN_vkCreateCommandPool)GetProcAddress(g_vulkanLib, "vkCreateCommandPool");
    vkDestroyCommandPool = (PFN_vkDestroyCommandPool)GetProcAddress(g_vulkanLib, "vkDestroyCommandPool");
    vkAllocateCommandBuffers = (PFN_vkAllocateCommandBuffers)GetProcAddress(g_vulkanLib, "vkAllocateCommandBuffers");
    vkFreeCommandBuffers = (PFN_vkFreeCommandBuffers)GetProcAddress(g_vulkanLib, "vkFreeCommandBuffers");
    vkCreateBuffer = (PFN_vkCreateBuffer)GetProcAddress(g_vulkanLib, "vkCreateBuffer");
    vkDestroyBuffer = (PFN_vkDestroyBuffer)GetProcAddress(g_vulkanLib, "vkDestroyBuffer");
    vkGetBufferMemoryRequirements = (PFN_vkGetBufferMemoryRequirements)GetProcAddress(g_vulkanLib, "vkGetBufferMemoryRequirements");
    vkAllocateMemory = (PFN_vkAllocateMemory)GetProcAddress(g_vulkanLib, "vkAllocateMemory");
    vkFreeMemory = (PFN_vkFreeMemory)GetProcAddress(g_vulkanLib, "vkFreeMemory");
    vkBindBufferMemory = (PFN_vkBindBufferMemory)GetProcAddress(g_vulkanLib, "vkBindBufferMemory");
    vkMapMemory = (PFN_vkMapMemory)GetProcAddress(g_vulkanLib, "vkMapMemory");
    vkUnmapMemory = (PFN_vkUnmapMemory)GetProcAddress(g_vulkanLib, "vkUnmapMemory");
    vkCreateShaderModule = (PFN_vkCreateShaderModule)GetProcAddress(g_vulkanLib, "vkCreateShaderModule");
    vkDestroyShaderModule = (PFN_vkDestroyShaderModule)GetProcAddress(g_vulkanLib, "vkDestroyShaderModule");
    vkCreateDescriptorSetLayout = (PFN_vkCreateDescriptorSetLayout)GetProcAddress(g_vulkanLib, "vkCreateDescriptorSetLayout");
    vkDestroyDescriptorSetLayout = (PFN_vkDestroyDescriptorSetLayout)GetProcAddress(g_vulkanLib, "vkDestroyDescriptorSetLayout");
    vkCreatePipelineLayout = (PFN_vkCreatePipelineLayout)GetProcAddress(g_vulkanLib, "vkCreatePipelineLayout");
    vkDestroyPipelineLayout = (PFN_vkDestroyPipelineLayout)GetProcAddress(g_vulkanLib, "vkDestroyPipelineLayout");
    vkCreateComputePipelines = (PFN_vkCreateComputePipelines)GetProcAddress(g_vulkanLib, "vkCreateComputePipelines");
    vkDestroyPipeline = (PFN_vkDestroyPipeline)GetProcAddress(g_vulkanLib, "vkDestroyPipeline");
    vkCreateDescriptorPool = (PFN_vkCreateDescriptorPool)GetProcAddress(g_vulkanLib, "vkCreateDescriptorPool");
    vkDestroyDescriptorPool = (PFN_vkDestroyDescriptorPool)GetProcAddress(g_vulkanLib, "vkDestroyDescriptorPool");
    vkAllocateDescriptorSets = (PFN_vkAllocateDescriptorSets)GetProcAddress(g_vulkanLib, "vkAllocateDescriptorSets");
    vkUpdateDescriptorSets = (PFN_vkUpdateDescriptorSets)GetProcAddress(g_vulkanLib, "vkUpdateDescriptorSets");
    vkBeginCommandBuffer = (PFN_vkBeginCommandBuffer)GetProcAddress(g_vulkanLib, "vkBeginCommandBuffer");
    vkEndCommandBuffer = (PFN_vkEndCommandBuffer)GetProcAddress(g_vulkanLib, "vkEndCommandBuffer");
    vkCmdBindPipeline = (PFN_vkCmdBindPipeline)GetProcAddress(g_vulkanLib, "vkCmdBindPipeline");
    vkCmdBindDescriptorSets = (PFN_vkCmdBindDescriptorSets)GetProcAddress(g_vulkanLib, "vkCmdBindDescriptorSets");
    vkCmdDispatch = (PFN_vkCmdDispatch)GetProcAddress(g_vulkanLib, "vkCmdDispatch");
    vkQueueSubmit = (PFN_vkQueueSubmit)GetProcAddress(g_vulkanLib, "vkQueueSubmit");
    vkQueueWaitIdle = (PFN_vkQueueWaitIdle)GetProcAddress(g_vulkanLib, "vkQueueWaitIdle");
    vkDeviceWaitIdle = (PFN_vkDeviceWaitIdle)GetProcAddress(g_vulkanLib, "vkDeviceWaitIdle");
    vkCreateFence = (PFN_vkCreateFence)GetProcAddress(g_vulkanLib, "vkCreateFence");
    vkDestroyFence = (PFN_vkDestroyFence)GetProcAddress(g_vulkanLib, "vkDestroyFence");
    vkWaitForFences = (PFN_vkWaitForFences)GetProcAddress(g_vulkanLib, "vkWaitForFences");
    vkResetFences = (PFN_vkResetFences)GetProcAddress(g_vulkanLib, "vkResetFences");

    return vkCreateInstance && vkDestroyInstance && vkEnumeratePhysicalDevices;
}

void UnloadVulkan() {
    if (g_vulkanLib) {
        FreeLibrary(g_vulkanLib);
        g_vulkanLib = nullptr;
    }
}

class Timer {
public:
    void Start() { start_ = std::chrono::high_resolution_clock::now(); }
    void Stop() { end_ = std::chrono::high_resolution_clock::now(); }
    double ElapsedMs() const {
        return std::chrono::duration<double, std::milli>(end_ - start_).count();
    }
    double ElapsedUs() const {
        return std::chrono::duration<double, std::micro>(end_ - start_).count();
    }
private:
    std::chrono::high_resolution_clock::time_point start_, end_;
};

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "VULKAN GPU BENCHMARK (Dynamic Loading)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Load Vulkan
    if (!LoadVulkan()) {
        std::cout << "FAILED: Could not load Vulkan runtime" << std::endl;
        return 1;
    }

    std::cout << "Vulkan runtime loaded successfully" << std::endl;
    std::cout << std::endl;

    // Create instance
    VkApplicationInfo appInfo = {};
    appInfo.sType = 0; // VK_STRUCTURE_TYPE_APPLICATION_INFO
    appInfo.pApplicationName = "RawrXD Benchmark";
    appInfo.applicationVersion = 1;
    appInfo.pEngineName = "RawrXD";
    appInfo.engineVersion = 1;
    appInfo.apiVersion = (1 << 22) | (3 << 12); // Vulkan 1.3

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = 1; // VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO
    createInfo.pApplicationInfo = &appInfo;

    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = vkCreateInstance(&createInfo, nullptr, &instance);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create Vulkan instance: " << result << std::endl;
        UnloadVulkan();
        return 1;
    }

    std::cout << "Vulkan instance created" << std::endl;

    // Enumerate physical devices
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        std::cout << "No Vulkan-compatible devices found" << std::endl;
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    std::cout << "Found " << deviceCount << " device(s)" << std::endl;
    std::cout << std::endl;

    // Select first discrete GPU or any GPU
    VkPhysicalDevice selectedDevice = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties selectedProps = {};
    int computeQueueFamily = -1;

    for (uint32_t i = 0; i < deviceCount; i++) {
        VkPhysicalDeviceProperties props = {};
        vkGetPhysicalDeviceProperties(devices[i], &props);

        uint32_t queueFamilyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queueFamilyCount, nullptr);
        
        // Just use queue family 0 - it should have compute on modern GPUs
        int computeIdx = 0;
        
        if (queueFamilyCount > 0) {
            std::cout << "Device " << i << ": " << props.deviceName << std::endl;
            std::cout << "  Vendor: ";
            if (props.vendorID == VK_VENDOR_ID_AMD) std::cout << "AMD";
            else if (props.vendorID == VK_VENDOR_ID_NVIDIA) std::cout << "NVIDIA";
            else if (props.vendorID == VK_VENDOR_ID_INTEL) std::cout << "Intel";
            else std::cout << "0x" << std::hex << props.vendorID << std::dec;
            std::cout << std::endl;
            std::cout << "  Type: " << (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU ? "Discrete" :
                                        props.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU ? "Integrated" : "Other")
                      << " (raw type: " << props.deviceType << ")" << std::endl;
            std::cout << "  Compute queue family: " << computeIdx << std::endl;
            std::cout << std::endl;

            // Prefer RX 7800 XT (high-performance discrete GPU)
            std::string devName(props.deviceName);
            bool is7800XT = devName.find("RX 7800") != std::string::npos ||
                           devName.find("7800 XT") != std::string::npos;
            bool isIntegrated = devName.find("Graphics") != std::string::npos ||
                               devName.find("Radeon(TM)") != std::string::npos;
            
            if (selectedDevice == VK_NULL_HANDLE) {
                selectedDevice = devices[i];
                selectedProps = props;
                computeQueueFamily = computeIdx;
            } else if (is7800XT && !isIntegrated) {
                // Always prefer RX 7800 XT over integrated graphics
                selectedDevice = devices[i];
                selectedProps = props;
                computeQueueFamily = computeIdx;
            }
        }
    }

    if (selectedDevice == VK_NULL_HANDLE) {
        std::cout << "No device with compute support found" << std::endl;
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    std::cout << "Selected device: " << selectedProps.deviceName << std::endl;
    std::cout << std::endl;

    // Create logical device
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo = {};
    queueCreateInfo.sType = 2; // VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO
    queueCreateInfo.queueFamilyIndex = computeQueueFamily;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkDeviceCreateInfo deviceCreateInfo = {};
    deviceCreateInfo.sType = 3; // VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;

    VkDevice device = VK_NULL_HANDLE;
    result = vkCreateDevice(selectedDevice, &deviceCreateInfo, nullptr, &device);
    std::cout << "vkCreateDevice result: " << result << " (VK_SUCCESS=" << VK_SUCCESS << ")" << std::endl;
    std::cout << "Device handle: " << device << std::endl;
    
    if (result != VK_SUCCESS || device == VK_NULL_HANDLE) {
        std::cout << "Failed to create logical device" << std::endl;
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    std::cout << "Device created successfully" << std::endl;
    std::cout << "Queue family index: " << computeQueueFamily << std::endl;

    // Get device-specific function pointers
    typedef void* (*PFN_vkGetDeviceProcAddr)(VkDevice, const char*);
    PFN_vkGetDeviceProcAddr getDevProcAddr = (PFN_vkGetDeviceProcAddr)GetProcAddress(g_vulkanLib, "vkGetDeviceProcAddr");
    
    if (!getDevProcAddr) {
        std::cout << "Failed to get vkGetDeviceProcAddr" << std::endl;
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    // Get queue using device-specific function pointer
    typedef void (*PFN_vkGetDeviceQueue)(VkDevice, uint32_t, uint32_t, VkQueue*);
    PFN_vkGetDeviceQueue getDevQueue = (PFN_vkGetDeviceQueue)getDevProcAddr(device, "vkGetDeviceQueue");
    
    if (!getDevQueue) {
        std::cout << "Failed to get vkGetDeviceQueue function pointer" << std::endl;
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    VkQueue computeQueue = VK_NULL_HANDLE;
    getDevQueue(device, computeQueueFamily, 0, &computeQueue);
    
    // Also try the global function pointer as fallback
    if (computeQueue == VK_NULL_HANDLE && vkGetDeviceQueue) {
        vkGetDeviceQueue(device, computeQueueFamily, 0, &computeQueue);
    }

    std::cout << "Queue handle: " << computeQueue << std::endl;

    if (computeQueue == VK_NULL_HANDLE) {
        std::cout << "Failed to get compute queue" << std::endl;
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    std::cout << "Logical device created" << std::endl;
    std::cout << "Compute queue: " << computeQueue << std::endl;
    std::cout << std::endl;

    // Create command pool
    VkCommandPool commandPool = VK_NULL_HANDLE;
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = 39; // VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO
    poolInfo.queueFamilyIndex = computeQueueFamily;
    poolInfo.flags = 1; // VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT

    result = vkCreateCommandPool(device, &poolInfo, nullptr, &commandPool);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create command pool: " << result << std::endl;
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    // Allocate command buffer
    VkCommandBuffer commandBuffer = VK_NULL_HANDLE;
    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = 40; // VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO
    allocInfo.commandPool = commandPool;
    allocInfo.level = 0; // VK_COMMAND_BUFFER_LEVEL_PRIMARY
    allocInfo.commandBufferCount = 1;

    result = vkAllocateCommandBuffers(device, &allocInfo, &commandBuffer);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to allocate command buffer: " << result << std::endl;
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    // Create fence
    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = 42; // VK_STRUCTURE_TYPE_FENCE_CREATE_INFO
    fenceInfo.flags = VK_FENCE_CREATE_SIGNALED_BIT;

    result = vkCreateFence(device, &fenceInfo, nullptr, &fence);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create fence: " << result << std::endl;
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    // Get memory properties
    VkPhysicalDeviceMemoryProperties memProps = {};
    vkGetPhysicalDeviceMemoryProperties(selectedDevice, &memProps);

    // Allocate GPU buffer
    const size_t bufferSize = 4096 * sizeof(float); // 16KB

    VkBuffer buffer = VK_NULL_HANDLE;
    VkBufferCreateInfo bufferInfo = {};
    bufferInfo.sType = 12; // VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO
    bufferInfo.size = bufferSize;
    bufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufferInfo.sharingMode = 0; // VK_SHARING_MODE_EXCLUSIVE

    result = vkCreateBuffer(device, &bufferInfo, nullptr, &buffer);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create buffer: " << result << std::endl;
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    VkMemoryRequirements memReqs = {};
    vkGetBufferMemoryRequirements(device, buffer, &memReqs);

    // Find memory type
    uint32_t memoryTypeIndex = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; i++) {
        if ((memReqs.memoryTypeBits & (1 << i)) &&
            (memProps.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            memoryTypeIndex = i;
            break;
        }
    }

    if (memoryTypeIndex == UINT32_MAX) {
        std::cout << "Failed to find suitable memory type" << std::endl;
        vkDestroyBuffer(device, buffer, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkMemoryAllocateInfo memAllocInfo = {};
    memAllocInfo.sType = 5; // VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO
    memAllocInfo.allocationSize = memReqs.size;
    memAllocInfo.memoryTypeIndex = memoryTypeIndex;

    result = vkAllocateMemory(device, &memAllocInfo, nullptr, &memory);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to allocate memory: " << result << std::endl;
        vkDestroyBuffer(device, buffer, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    result = vkBindBufferMemory(device, buffer, memory, 0);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to bind buffer memory: " << result << std::endl;
        vkFreeMemory(device, memory, nullptr);
        vkDestroyBuffer(device, buffer, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device);
        vkDestroyInstance(instance);
        UnloadVulkan();
        return 1;
    }

    std::cout << "GPU buffer allocated: " << bufferSize << " bytes" << std::endl;
    std::cout << std::endl;

    // Benchmark GPU operations
    const int iterations = 1000;
    Timer timer;

    std::cout << "Benchmarking GPU operations..." << std::endl;
    timer.Start();

    for (int i = 0; i < iterations; i++) {
        // Reset fence
        vkResetFences(device, 1, &fence);

        // Begin command buffer
        VkCommandBufferBeginInfo beginInfo = {};
        beginInfo.sType = 43; // VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO
        beginInfo.flags = 1; // VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT

        vkBeginCommandBuffer(commandBuffer, &beginInfo);

        // End command buffer
        vkEndCommandBuffer(commandBuffer);

        // Submit
        VkSubmitInfo submitInfo = {};
        submitInfo.sType = 4; // VK_STRUCTURE_TYPE_SUBMIT_INFO
        submitInfo.commandBufferCount = 1;
        submitInfo.pCommandBuffers = &commandBuffer;

        vkQueueSubmit(computeQueue, 1, &submitInfo, fence);

        // Wait for completion
        vkWaitForFences(device, 1, &fence, VK_TRUE, UINT64_MAX);
    }

    timer.Stop();

    double timePerOpUs = timer.ElapsedUs() / iterations;
    double opsPerSec = 1000000.0 / timePerOpUs;

    std::cout << "  Total time: " << timer.ElapsedMs() << " ms" << std::endl;
    std::cout << "  Time per operation: " << timePerOpUs << " us" << std::endl;
    std::cout << "  Operations/sec: " << opsPerSec << std::endl;
    std::cout << std::endl;

    // Cleanup
    vkFreeMemory(device, memory, nullptr);
    vkDestroyBuffer(device, buffer, nullptr);
    vkDestroyFence(device, fence, nullptr);
    vkDestroyCommandPool(device, commandPool, nullptr);
    vkDestroyDevice(device);
    vkDestroyInstance(instance);
    UnloadVulkan();

    std::cout << "========================================" << std::endl;
    std::cout << "VULKAN GPU DETECTED AND FUNCTIONAL" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Device: " << selectedProps.deviceName << std::endl;
    std::cout << "GPU overhead: " << timePerOpUs << " us/op" << std::endl;
    std::cout << std::endl;
    std::cout << "Ready for GPU-accelerated inference!" << std::endl;

    return 0;
}
