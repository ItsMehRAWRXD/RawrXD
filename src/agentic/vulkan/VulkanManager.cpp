<<<<<<< HEAD
#include "VulkanManager.hpp"
#include <cstring>

// ============================================================================
// Dynamic Vulkan API Function Pointers (loaded from vulkan-1.dll at runtime)
// ============================================================================

// Vulkan type definitions needed for function signatures
typedef uint32_t VkFlags;
typedef VkFlags VkInstanceCreateFlags;
typedef VkFlags VkDeviceCreateFlags;
typedef VkFlags VkDeviceQueueCreateFlags;
typedef VkFlags VkCommandPoolCreateFlags;
typedef VkFlags VkDescriptorPoolCreateFlags;
typedef VkFlags VkBufferCreateFlags;
typedef VkFlags VkMemoryPropertyFlags;
typedef VkFlags VkBufferUsageFlags;
typedef VkFlags VkFenceCreateFlags;
typedef VkFlags VkCommandBufferUsageFlags;
typedef VkFlags VkPipelineStageFlags;
typedef VkFlags VkShaderStageFlags;
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;

enum VkResult {
    VK_SUCCESS = 0,
    VK_NOT_READY = 1,
    VK_TIMEOUT = 2,
    VK_ERROR_OUT_OF_HOST_MEMORY = -1,
    VK_ERROR_DEVICE_LOST = -4
};

enum VkStructureType {
    VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1,
    VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 2,
    VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 3,
    VK_STRUCTURE_TYPE_SUBMIT_INFO = 4,
    VK_STRUCTURE_TYPE_FENCE_CREATE_INFO = 8,
    VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO = 39,
    VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO = 40,
    VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO = 42,
    VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO = 12,
    VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO = 5,
    VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO = 33,
    VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO = 32,
    VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO = 30,
    VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO = 29,
    VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO = 16,
    VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO = 18,
    VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO = 34,
    VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET = 35,
    VK_STRUCTURE_TYPE_APPLICATION_INFO = 0
};

enum VkQueueFlagBits { VK_QUEUE_COMPUTE_BIT = 0x00000002 };
enum VkMemoryPropertyFlagBits {
    VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT = 0x02,
    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT = 0x04,
    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT = 0x01
};
enum VkBufferUsageFlagBits {
    VK_BUFFER_USAGE_STORAGE_BUFFER_BIT = 0x20,
    VK_BUFFER_USAGE_TRANSFER_SRC_BIT = 0x01,
    VK_BUFFER_USAGE_TRANSFER_DST_BIT = 0x02
};
enum VkCommandPoolCreateFlagBits { VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT = 0x02 };
enum VkDescriptorType { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER = 7 };
enum VkCommandBufferLevel { VK_COMMAND_BUFFER_LEVEL_PRIMARY = 0 };
enum VkSharingMode { VK_SHARING_MODE_EXCLUSIVE = 0 };
enum VkPipelineBindPoint { VK_PIPELINE_BIND_POINT_COMPUTE = 1 };
static constexpr VkFenceCreateFlags VK_FENCE_CREATE_SIGNALED_BIT = 0x01;

// Minimal structures for Vulkan calls
struct VkApplicationInfo {
    VkStructureType sType; const void* pNext; const char* pApplicationName;
    uint32_t applicationVersion; const char* pEngineName; uint32_t engineVersion;
    uint32_t apiVersion;
};
struct VkInstanceCreateInfo {
    VkStructureType sType; const void* pNext; VkInstanceCreateFlags flags;
    const VkApplicationInfo* pApplicationInfo;
    uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames;
};
struct VkPhysicalDeviceProperties {
    uint32_t apiVersion; uint32_t driverVersion; uint32_t vendorID; uint32_t deviceID;
    uint32_t deviceType; char deviceName[256]; uint8_t pipelineCacheUUID[16];
    // Note: Full struct includes VkPhysicalDeviceLimits, VkPhysicalDeviceSparseProperties
};
struct VkPhysicalDeviceMemoryProperties {
    uint32_t memoryTypeCount;
    struct { VkMemoryPropertyFlags propertyFlags; uint32_t heapIndex; } memoryTypes[32];
    uint32_t memoryHeapCount;
    struct { VkDeviceSize size; VkFlags flags; } memoryHeaps[16];
};
struct VkQueueFamilyProperties {
    VkFlags queueFlags; uint32_t queueCount; uint32_t timestampValidBits;
    struct { uint32_t width, height, depth; } minImageTransferGranularity;
};
struct VkDeviceQueueCreateInfo {
    VkStructureType sType; const void* pNext; VkDeviceQueueCreateFlags flags;
    uint32_t queueFamilyIndex; uint32_t queueCount; const float* pQueuePriorities;
};
struct VkDeviceCreateInfo {
    VkStructureType sType; const void* pNext; VkDeviceCreateFlags flags;
    uint32_t queueCreateInfoCount; const VkDeviceQueueCreateInfo* pQueueCreateInfos;
    uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames;
    const void* pEnabledFeatures;
};
struct VkCommandPoolCreateInfo {
    VkStructureType sType; const void* pNext; VkCommandPoolCreateFlags flags;
    uint32_t queueFamilyIndex;
};
struct VkBufferCreateInfo {
    VkStructureType sType; const void* pNext; VkBufferCreateFlags flags;
    VkDeviceSize size; VkBufferUsageFlags usage; VkSharingMode sharingMode;
    uint32_t queueFamilyIndexCount; const uint32_t* pQueueFamilyIndices;
};
struct VkMemoryRequirements { VkDeviceSize size; VkDeviceSize alignment; uint32_t memoryTypeBits; };
struct VkMemoryAllocateInfo {
    VkStructureType sType; const void* pNext; VkDeviceSize allocationSize; uint32_t memoryTypeIndex;
};
struct VkFenceCreateInfo { VkStructureType sType; const void* pNext; VkFenceCreateFlags flags; };
struct VkCommandBufferAllocateInfo {
    VkStructureType sType; const void* pNext; VkCommandPool_T* commandPool;
    VkCommandBufferLevel level; uint32_t commandBufferCount;
};
struct VkCommandBufferBeginInfo {
    VkStructureType sType; const void* pNext; VkCommandBufferUsageFlags flags;
    const void* pInheritanceInfo;
};
struct VkSubmitInfo {
    VkStructureType sType; const void* pNext;
    uint32_t waitSemaphoreCount; const void* pWaitSemaphores;
    const VkPipelineStageFlags* pWaitDstStageMask;
    uint32_t commandBufferCount; VkCommandBuffer_T* const* pCommandBuffers;
    uint32_t signalSemaphoreCount; const void* pSignalSemaphores;
};
struct VkDescriptorPoolSize { VkDescriptorType type; uint32_t descriptorCount; };
struct VkDescriptorPoolCreateInfo {
    VkStructureType sType; const void* pNext; VkDescriptorPoolCreateFlags flags;
    uint32_t maxSets; uint32_t poolSizeCount; const VkDescriptorPoolSize* pPoolSizes;
};

// Function pointer types
typedef VkResult (*PFN_vkCreateInstance)(const VkInstanceCreateInfo*, const void*, VkInstance_T**);
typedef void (*PFN_vkDestroyInstance)(VkInstance_T*, const void*);
typedef VkResult (*PFN_vkEnumeratePhysicalDevices)(VkInstance_T*, uint32_t*, VkPhysicalDevice_T**);
typedef void (*PFN_vkGetPhysicalDeviceProperties)(VkPhysicalDevice_T*, VkPhysicalDeviceProperties*);
typedef void (*PFN_vkGetPhysicalDeviceMemoryProperties)(VkPhysicalDevice_T*, VkPhysicalDeviceMemoryProperties*);
typedef void (*PFN_vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice_T*, uint32_t*, VkQueueFamilyProperties*);
typedef VkResult (*PFN_vkCreateDevice)(VkPhysicalDevice_T*, const VkDeviceCreateInfo*, const void*, VkDevice_T**);
typedef void (*PFN_vkDestroyDevice)(VkDevice_T*, const void*);
typedef void (*PFN_vkGetDeviceQueue)(VkDevice_T*, uint32_t, uint32_t, VkQueue_T**);
typedef VkResult (*PFN_vkCreateCommandPool)(VkDevice_T*, const VkCommandPoolCreateInfo*, const void*, VkCommandPool_T**);
typedef void (*PFN_vkDestroyCommandPool)(VkDevice_T*, VkCommandPool_T*, const void*);
typedef VkResult (*PFN_vkCreateBuffer)(VkDevice_T*, const VkBufferCreateInfo*, const void*, VkBuffer_T**);
typedef void (*PFN_vkDestroyBuffer)(VkDevice_T*, VkBuffer_T*, const void*);
typedef void (*PFN_vkGetBufferMemoryRequirements)(VkDevice_T*, VkBuffer_T*, VkMemoryRequirements*);
typedef VkResult (*PFN_vkAllocateMemory)(VkDevice_T*, const VkMemoryAllocateInfo*, const void*, VkDeviceMemory_T**);
typedef void (*PFN_vkFreeMemory)(VkDevice_T*, VkDeviceMemory_T*, const void*);
typedef VkResult (*PFN_vkBindBufferMemory)(VkDevice_T*, VkBuffer_T*, VkDeviceMemory_T*, VkDeviceSize);
typedef VkResult (*PFN_vkMapMemory)(VkDevice_T*, VkDeviceMemory_T*, VkDeviceSize, VkDeviceSize, VkFlags, void**);
typedef void (*PFN_vkUnmapMemory)(VkDevice_T*, VkDeviceMemory_T*);
typedef VkResult (*PFN_vkCreateFence)(VkDevice_T*, const VkFenceCreateInfo*, const void*, VkFence_T**);
typedef void (*PFN_vkDestroyFence)(VkDevice_T*, VkFence_T*, const void*);
typedef VkResult (*PFN_vkResetFences)(VkDevice_T*, uint32_t, VkFence_T* const*);
typedef VkResult (*PFN_vkWaitForFences)(VkDevice_T*, uint32_t, VkFence_T* const*, VkBool32, uint64_t);
typedef VkResult (*PFN_vkAllocateCommandBuffers)(VkDevice_T*, const VkCommandBufferAllocateInfo*, VkCommandBuffer_T**);
typedef VkResult (*PFN_vkBeginCommandBuffer)(VkCommandBuffer_T*, const VkCommandBufferBeginInfo*);
typedef VkResult (*PFN_vkEndCommandBuffer)(VkCommandBuffer_T*);
typedef VkResult (*PFN_vkQueueSubmit)(VkQueue_T*, uint32_t, const VkSubmitInfo*, VkFence_T*);
typedef VkResult (*PFN_vkQueueWaitIdle)(VkQueue_T*);
typedef void (*PFN_vkCmdDispatch)(VkCommandBuffer_T*, uint32_t, uint32_t, uint32_t);
typedef VkResult (*PFN_vkCreateDescriptorPool)(VkDevice_T*, const VkDescriptorPoolCreateInfo*, const void*, VkDescriptorPool_T**);
typedef void (*PFN_vkDestroyDescriptorPool)(VkDevice_T*, VkDescriptorPool_T*, const void*);

// Global function pointers (loaded once)
static HMODULE g_vulkanDll = nullptr;
static PFN_vkCreateInstance                         fn_vkCreateInstance = nullptr;
static PFN_vkDestroyInstance                        fn_vkDestroyInstance = nullptr;
static PFN_vkEnumeratePhysicalDevices               fn_vkEnumeratePhysicalDevices = nullptr;
static PFN_vkGetPhysicalDeviceProperties            fn_vkGetPhysicalDeviceProperties = nullptr;
static PFN_vkGetPhysicalDeviceMemoryProperties      fn_vkGetPhysicalDeviceMemoryProperties = nullptr;
static PFN_vkGetPhysicalDeviceQueueFamilyProperties fn_vkGetPhysicalDeviceQueueFamilyProperties = nullptr;
static PFN_vkCreateDevice                           fn_vkCreateDevice = nullptr;
static PFN_vkDestroyDevice                          fn_vkDestroyDevice = nullptr;
static PFN_vkGetDeviceQueue                         fn_vkGetDeviceQueue = nullptr;
static PFN_vkCreateCommandPool                      fn_vkCreateCommandPool = nullptr;
static PFN_vkDestroyCommandPool                     fn_vkDestroyCommandPool = nullptr;
static PFN_vkCreateBuffer                           fn_vkCreateBuffer = nullptr;
static PFN_vkDestroyBuffer                          fn_vkDestroyBuffer = nullptr;
static PFN_vkGetBufferMemoryRequirements            fn_vkGetBufferMemoryRequirements = nullptr;
static PFN_vkAllocateMemory                         fn_vkAllocateMemory = nullptr;
static PFN_vkFreeMemory                             fn_vkFreeMemory = nullptr;
static PFN_vkBindBufferMemory                       fn_vkBindBufferMemory = nullptr;
static PFN_vkMapMemory                              fn_vkMapMemory = nullptr;
static PFN_vkUnmapMemory                            fn_vkUnmapMemory = nullptr;
static PFN_vkCreateFence                            fn_vkCreateFence = nullptr;
static PFN_vkDestroyFence                           fn_vkDestroyFence = nullptr;
static PFN_vkResetFences                            fn_vkResetFences = nullptr;
static PFN_vkWaitForFences                          fn_vkWaitForFences = nullptr;
static PFN_vkAllocateCommandBuffers                 fn_vkAllocateCommandBuffers = nullptr;
static PFN_vkBeginCommandBuffer                     fn_vkBeginCommandBuffer = nullptr;
static PFN_vkEndCommandBuffer                       fn_vkEndCommandBuffer = nullptr;
static PFN_vkQueueSubmit                            fn_vkQueueSubmit = nullptr;
static PFN_vkQueueWaitIdle                          fn_vkQueueWaitIdle = nullptr;
static PFN_vkCmdDispatch                            fn_vkCmdDispatch = nullptr;
static PFN_vkCreateDescriptorPool                   fn_vkCreateDescriptorPool = nullptr;
static PFN_vkDestroyDescriptorPool                  fn_vkDestroyDescriptorPool = nullptr;

static bool loadVulkanFunctions() {
    if (g_vulkanDll) return true;
    
    g_vulkanDll = LoadLibraryA("vulkan-1.dll");
    if (!g_vulkanDll) return false;
    
    #define LOAD_VK(name) fn_##name = (PFN_##name)GetProcAddress(g_vulkanDll, #name); \
        if (!fn_##name) { FreeLibrary(g_vulkanDll); g_vulkanDll = nullptr; return false; }
    
    LOAD_VK(vkCreateInstance);
    LOAD_VK(vkDestroyInstance);
    LOAD_VK(vkEnumeratePhysicalDevices);
    LOAD_VK(vkGetPhysicalDeviceProperties);
    LOAD_VK(vkGetPhysicalDeviceMemoryProperties);
    LOAD_VK(vkGetPhysicalDeviceQueueFamilyProperties);
    LOAD_VK(vkCreateDevice);
    LOAD_VK(vkDestroyDevice);
    LOAD_VK(vkGetDeviceQueue);
    LOAD_VK(vkCreateCommandPool);
    LOAD_VK(vkDestroyCommandPool);
    LOAD_VK(vkCreateBuffer);
    LOAD_VK(vkDestroyBuffer);
    LOAD_VK(vkGetBufferMemoryRequirements);
    LOAD_VK(vkAllocateMemory);
    LOAD_VK(vkFreeMemory);
    LOAD_VK(vkBindBufferMemory);
    LOAD_VK(vkMapMemory);
    LOAD_VK(vkUnmapMemory);
    LOAD_VK(vkCreateFence);
    LOAD_VK(vkDestroyFence);
    LOAD_VK(vkResetFences);
    LOAD_VK(vkWaitForFences);
    LOAD_VK(vkAllocateCommandBuffers);
    LOAD_VK(vkBeginCommandBuffer);
    LOAD_VK(vkEndCommandBuffer);
    LOAD_VK(vkQueueSubmit);
    LOAD_VK(vkQueueWaitIdle);
    LOAD_VK(vkCmdDispatch);
    LOAD_VK(vkCreateDescriptorPool);
    LOAD_VK(vkDestroyDescriptorPool);
    
    #undef LOAD_VK
    return true;
}

namespace RawrXD::Agentic::Vulkan {

bool VulkanManager::initialize(VulkanContext& context, bool enableValidation) {
    if (!loadVulkanFunctions()) {
        return false;
    }
    
    // Create Vulkan instance
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD-Agentic";
    appInfo.applicationVersion = 1;
    appInfo.pEngineName = "RawrXD";
    appInfo.engineVersion = 1;
    appInfo.apiVersion = (1 << 22) | (3 << 12); // VK_API_VERSION_1_3
    
    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;
    
    const char* validationLayer = "VK_LAYER_KHRONOS_validation";
    if (enableValidation) {
        createInfo.enabledLayerCount = 1;
        createInfo.ppEnabledLayerNames = &validationLayer;
    }
    
    VkResult result = fn_vkCreateInstance(&createInfo, nullptr, &context.instance);
    if (result != VK_SUCCESS) {
        return false;
    }
    
    // Enumerate physical devices, pick first one
    uint32_t deviceCount = 0;
    fn_vkEnumeratePhysicalDevices(context.instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        fn_vkDestroyInstance(context.instance, nullptr);
        context.instance = nullptr;
        return false;
    }
    
    std::vector<VkPhysicalDevice> devices(deviceCount);
    fn_vkEnumeratePhysicalDevices(context.instance, &deviceCount, devices.data());
    context.physicalDevice = devices[0]; // Use first GPU
    
    // Find memory type indices
    VkPhysicalDeviceMemoryProperties memProps{};
    fn_vkGetPhysicalDeviceMemoryProperties(context.physicalDevice, &memProps);
    
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        auto flags = memProps.memoryTypes[i].propertyFlags;
        if ((flags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) && context.deviceLocalMemoryType == 0) {
            context.deviceLocalMemoryType = i;
        }
        if ((flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) && context.hostVisibleMemoryType == 0) {
            context.hostVisibleMemoryType = i;
        }
        if ((flags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT))
            == (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
            context.coherentMemoryType = i;
        }
    }
    
    // Create logical device and command infrastructure
    if (!createDevice(context)) {
        fn_vkDestroyInstance(context.instance, nullptr);
        context.instance = nullptr;
        return false;
    }
    
    if (!createCommandPool(context)) {
        shutdown(context);
        return false;
    }
    
    if (!createDescriptorPool(context)) {
        shutdown(context);
        return false;
    }
    
    // Allocate command buffer
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = context.commandPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    
    result = fn_vkAllocateCommandBuffers(context.device, &allocInfo, &context.commandBuffer);
    if (result != VK_SUCCESS) {
        shutdown(context);
        return false;
    }
    
    // Create fence for synchronization
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fenceInfo.flags = VK_FENCE_CREATE_SIGNALED_BIT;
    
    result = fn_vkCreateFence(context.device, &fenceInfo, nullptr, &context.fence);
    if (result != VK_SUCCESS) {
        shutdown(context);
        return false;
    }
    
    return true;
}

void VulkanManager::shutdown(VulkanContext& context) {
    if (!context.device) return;
    
    fn_vkQueueWaitIdle(context.computeQueue);
    
    if (context.fence) { fn_vkDestroyFence(context.device, context.fence, nullptr); context.fence = nullptr; }
    if (context.commandPool) { fn_vkDestroyCommandPool(context.device, context.commandPool, nullptr); context.commandPool = nullptr; }
    if (context.descriptorPool) { fn_vkDestroyDescriptorPool(context.device, context.descriptorPool, nullptr); context.descriptorPool = nullptr; }
    
    // Free buffers and memory
    if (context.bitmaskMappedPtr && context.bitmaskMemory) {
        fn_vkUnmapMemory(context.device, context.bitmaskMemory);
        context.bitmaskMappedPtr = nullptr;
    }
    if (context.fsmBuffer) { fn_vkDestroyBuffer(context.device, context.fsmBuffer, nullptr); context.fsmBuffer = nullptr; }
    if (context.fsmMemory) { fn_vkFreeMemory(context.device, context.fsmMemory, nullptr); context.fsmMemory = nullptr; }
    if (context.bitmaskBuffer) { fn_vkDestroyBuffer(context.device, context.bitmaskBuffer, nullptr); context.bitmaskBuffer = nullptr; }
    if (context.bitmaskMemory) { fn_vkFreeMemory(context.device, context.bitmaskMemory, nullptr); context.bitmaskMemory = nullptr; }
    if (context.logitsBuffer) { fn_vkDestroyBuffer(context.device, context.logitsBuffer, nullptr); context.logitsBuffer = nullptr; }
    if (context.outputBuffer) { fn_vkDestroyBuffer(context.device, context.outputBuffer, nullptr); context.outputBuffer = nullptr; }
    
    fn_vkDestroyDevice(context.device, nullptr);
    context.device = nullptr;
    
    if (context.instance) {
        fn_vkDestroyInstance(context.instance, nullptr);
        context.instance = nullptr;
    }
}

bool VulkanManager::createFSMResources(VulkanContext& context, const void* fsmTable, size_t tableSize) {
    if (!context.device || !fsmTable || tableSize == 0) return false;
    
    // Create FSM buffer (device-local for fast GPU access)
    VkBufferCreateInfo bufferInfo{};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = tableSize;
    bufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    VkResult result = fn_vkCreateBuffer(context.device, &bufferInfo, nullptr, &context.fsmBuffer);
    if (result != VK_SUCCESS) return false;
    
    VkMemoryRequirements memReqs{};
    fn_vkGetBufferMemoryRequirements(context.device, context.fsmBuffer, &memReqs);
    
    // Allocate in host-visible+coherent memory so we can copy data directly
    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memReqs.size;
    allocInfo.memoryTypeIndex = findMemoryType(context, memReqs.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    
    result = fn_vkAllocateMemory(context.device, &allocInfo, nullptr, &context.fsmMemory);
    if (result != VK_SUCCESS) return false;
    
    fn_vkBindBufferMemory(context.device, context.fsmBuffer, context.fsmMemory, 0);
    
    // Copy FSM table data
    void* mapped = nullptr;
    fn_vkMapMemory(context.device, context.fsmMemory, 0, tableSize, 0, &mapped);
    memcpy(mapped, fsmTable, tableSize);
    fn_vkUnmapMemory(context.device, context.fsmMemory);
    
    // Create bitmask buffer (host-visible for zero-copy updates)
    VkBufferCreateInfo bitmaskInfo{};
    bitmaskInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bitmaskInfo.size = tableSize; // Same size as FSM table for bitmask
    bitmaskInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    bitmaskInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    result = fn_vkCreateBuffer(context.device, &bitmaskInfo, nullptr, &context.bitmaskBuffer);
    if (result != VK_SUCCESS) return false;
    
    fn_vkGetBufferMemoryRequirements(context.device, context.bitmaskBuffer, &memReqs);
    allocInfo.allocationSize = memReqs.size;
    allocInfo.memoryTypeIndex = findMemoryType(context, memReqs.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    
    result = fn_vkAllocateMemory(context.device, &allocInfo, nullptr, &context.bitmaskMemory);
    if (result != VK_SUCCESS) return false;
    
    fn_vkBindBufferMemory(context.device, context.bitmaskBuffer, context.bitmaskMemory, 0);
    
    // Keep bitmask mapped for zero-copy updates
    fn_vkMapMemory(context.device, context.bitmaskMemory, 0, tableSize, 0, &context.bitmaskMappedPtr);
    memset(context.bitmaskMappedPtr, 0xFF, tableSize); // All tokens enabled initially
    
    return true;
}

bool VulkanManager::updateBitmask(VulkanContext& context, const void* bitmask, size_t size) {
    if (!context.bitmaskMappedPtr) {
        return false;
    }
    
    // Zero-copy update via mapped memory
    memcpy(context.bitmaskMappedPtr, bitmask, size);
    
    return true;
}

bool VulkanManager::dispatchCompute(VulkanContext& context, uint32_t vocabSize, uint32_t currentState) {
    if (!context.device || !context.commandBuffer || !context.computeQueue) return false;
    
    // Reset fence
    fn_vkResetFences(context.device, 1, &context.fence);
    
    // Record command buffer
    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = 0x01; // VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT
    
    VkResult result = fn_vkBeginCommandBuffer(context.commandBuffer, &beginInfo);
    if (result != VK_SUCCESS) return false;
    
    // Dispatch compute shader
    uint32_t groupCountX = (vocabSize + context.workgroupSizeX - 1) / context.workgroupSizeX;
    fn_vkCmdDispatch(context.commandBuffer, groupCountX, context.workgroupSizeY, context.workgroupSizeZ);
    
    result = fn_vkEndCommandBuffer(context.commandBuffer);
    if (result != VK_SUCCESS) return false;
    
    // Submit to compute queue
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &context.commandBuffer;
    
    result = fn_vkQueueSubmit(context.computeQueue, 1, &submitInfo, context.fence);
    return result == VK_SUCCESS;
}

bool VulkanManager::waitForCompletion(VulkanContext& context) {
    if (!context.device || !context.fence) return false;
    
    // Wait up to 5 seconds for GPU completion
    VkResult result = fn_vkWaitForFences(context.device, 1, &context.fence, 1, 5000000000ULL);
    return result == VK_SUCCESS;
}

std::string VulkanManager::getDeviceName(const VulkanContext& context) {
    if (!context.physicalDevice) return "No Vulkan device";
    
    VkPhysicalDeviceProperties props{};
    fn_vkGetPhysicalDeviceProperties(context.physicalDevice, &props);
    return std::string(props.deviceName);
}

bool VulkanManager::isVulkanAvailable() {
    // Try to load vulkan-1.dll
    HMODULE vulkanDll = LoadLibraryA("vulkan-1.dll");
    if (vulkanDll) {
        FreeLibrary(vulkanDll);
        return true;
    }
    return false;
}

bool VulkanManager::createDevice(VulkanContext& context) {
    if (!context.physicalDevice) return false;
    
    // Find compute queue family
    uint32_t queueFamilyCount = 0;
    fn_vkGetPhysicalDeviceQueueFamilyProperties(context.physicalDevice, &queueFamilyCount, nullptr);
    
    std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
    fn_vkGetPhysicalDeviceQueueFamilyProperties(context.physicalDevice, &queueFamilyCount, queueFamilies.data());
    
    uint32_t computeFamily = UINT32_MAX;
    for (uint32_t i = 0; i < queueFamilyCount; ++i) {
        if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            computeFamily = i;
            break;
        }
    }
    
    if (computeFamily == UINT32_MAX) return false;
    
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queueCI{};
    queueCI.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCI.queueFamilyIndex = computeFamily;
    queueCI.queueCount = 1;
    queueCI.pQueuePriorities = &priority;
    
    VkDeviceCreateInfo deviceCI{};
    deviceCI.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCI.queueCreateInfoCount = 1;
    deviceCI.pQueueCreateInfos = &queueCI;
    
    VkResult result = fn_vkCreateDevice(context.physicalDevice, &deviceCI, nullptr, &context.device);
    if (result != VK_SUCCESS) return false;
    
    fn_vkGetDeviceQueue(context.device, computeFamily, 0, &context.computeQueue);
    return true;
}

bool VulkanManager::createCommandPool(VulkanContext& context) {
    if (!context.device) return false;
    
    // Find compute queue family index (same logic as createDevice)
    uint32_t queueFamilyCount = 0;
    fn_vkGetPhysicalDeviceQueueFamilyProperties(context.physicalDevice, &queueFamilyCount, nullptr);
    std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
    fn_vkGetPhysicalDeviceQueueFamilyProperties(context.physicalDevice, &queueFamilyCount, queueFamilies.data());
    
    uint32_t computeFamily = 0;
    for (uint32_t i = 0; i < queueFamilyCount; ++i) {
        if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            computeFamily = i;
            break;
        }
    }
    
    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    poolInfo.queueFamilyIndex = computeFamily;
    
    VkResult result = fn_vkCreateCommandPool(context.device, &poolInfo, nullptr, &context.commandPool);
    return result == VK_SUCCESS;
}

bool VulkanManager::createDescriptorPool(VulkanContext& context) {
    if (!context.device) return false;
    
    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 8; // FSM, bitmask, logits, output + extras
    
    VkDescriptorPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.maxSets = 4;
    poolInfo.poolSizeCount = 1;
    poolInfo.pPoolSizes = &poolSize;
    
    VkResult result = fn_vkCreateDescriptorPool(context.device, &poolInfo, nullptr, &context.descriptorPool);
    return result == VK_SUCCESS;
}

bool VulkanManager::createPipeline(VulkanContext& context) {
    if (!context.device) return false;
    
    // Load SPIR-V compute shader from disk
    std::vector<char> shaderCode = readFile("shaders/compute.spv");
    if (shaderCode.empty()) {
        // Fallback: try embedded shader path
        shaderCode = readFile("assets/shaders/default_compute.spv");
        if (shaderCode.empty()) {
            printf("[VulkanManager] ERROR: Failed to load compute shader\n");
            return false;
        }
    }
    
    // Create shader module
    VkShaderModuleCreateInfo shaderModuleInfo{};
    shaderModuleInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderModuleInfo.codeSize = shaderCode.size();
    shaderModuleInfo.pCode = reinterpret_cast<const uint32_t*>(shaderCode.data());
    
    VkShaderModule computeShaderModule;
    if (vkCreateShaderModule(context.device, &shaderModuleInfo, nullptr, &computeShaderModule) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to create shader module\n");
        return false;
    }
    
    // Create descriptor set layout for compute bindings
    // Binding 0: Input buffer (read-only)
    // Binding 1: Output buffer (write-only)
    // Binding 2: Uniform buffer (parameters)
    VkDescriptorSetLayoutBinding bindings[3] = {};
    
    bindings[0].binding = 0;
    bindings[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[0].descriptorCount = 1;
    bindings[0].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    bindings[0].pImmutableSamplers = nullptr;
    
    bindings[1].binding = 1;
    bindings[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[1].descriptorCount = 1;
    bindings[1].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    bindings[1].pImmutableSamplers = nullptr;
    
    bindings[2].binding = 2;
    bindings[2].descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
    bindings[2].descriptorCount = 1;
    bindings[2].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    bindings[2].pImmutableSamplers = nullptr;
    
    VkDescriptorSetLayoutCreateInfo descriptorLayoutInfo{};
    descriptorLayoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    descriptorLayoutInfo.bindingCount = 3;
    descriptorLayoutInfo.pBindings = bindings;
    
    if (vkCreateDescriptorSetLayout(context.device, &descriptorLayoutInfo, nullptr, &context.descriptorSetLayout) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to create descriptor set layout\n");
        vkDestroyShaderModule(context.device, computeShaderModule, nullptr);
        return false;
    }
    
    // Create pipeline layout
    VkPipelineLayoutCreateInfo pipelineLayoutInfo{};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &context.descriptorSetLayout;
    pipelineLayoutInfo.pushConstantRangeCount = 0;
    pipelineLayoutInfo.pPushConstantRanges = nullptr;
    
    if (vkCreatePipelineLayout(context.device, &pipelineLayoutInfo, nullptr, &context.pipelineLayout) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to create pipeline layout\n");
        vkDestroyDescriptorSetLayout(context.device, context.descriptorSetLayout, nullptr);
        vkDestroyShaderModule(context.device, computeShaderModule, nullptr);
        return false;
    }
    
    // Create compute pipeline
    VkPipelineShaderStageCreateInfo shaderStageInfo{};
    shaderStageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    shaderStageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    shaderStageInfo.module = computeShaderModule;
    shaderStageInfo.pName = "main";  // Entry point
    
    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage = shaderStageInfo;
    pipelineInfo.layout = context.pipelineLayout;
    pipelineInfo.basePipelineHandle = VK_NULL_HANDLE;
    pipelineInfo.basePipelineIndex = -1;
    
    if (vkCreateComputePipelines(context.device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &context.computePipeline) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to create compute pipeline\n");
        vkDestroyPipelineLayout(context.device, context.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(context.device, context.descriptorSetLayout, nullptr);
        vkDestroyShaderModule(context.device, computeShaderModule, nullptr);
        return false;
    }
    
    // Shader module can be destroyed after pipeline creation
    vkDestroyShaderModule(context.device, computeShaderModule, nullptr);
    
    // Create descriptor pool for allocating descriptor sets
    VkDescriptorPoolSize poolSizes[3] = {};
    poolSizes[0].type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSizes[0].descriptorCount = 10;
    poolSizes[1].type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSizes[1].descriptorCount = 10;
    poolSizes[2].type = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
    poolSizes[2].descriptorCount = 10;
    
    VkDescriptorPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.maxSets = 10;
    poolInfo.poolSizeCount = 3;
    poolInfo.pPoolSizes = poolSizes;
    
    if (vkCreateDescriptorPool(context.device, &poolInfo, nullptr, &context.descriptorPool) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to create descriptor pool\n");
        vkDestroyPipeline(context.device, context.computePipeline, nullptr);
        vkDestroyPipelineLayout(context.device, context.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(context.device, context.descriptorSetLayout, nullptr);
        return false;
    }
    
    // Create command pool for compute operations
    VkCommandPoolCreateInfo cmdPoolInfo{};
    cmdPoolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    cmdPoolInfo.queueFamilyIndex = context.computeQueueFamily;
    cmdPoolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    
    if (vkCreateCommandPool(context.device, &cmdPoolInfo, nullptr, &context.commandPool) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to create command pool\n");
        vkDestroyDescriptorPool(context.device, context.descriptorPool, nullptr);
        vkDestroyPipeline(context.device, context.computePipeline, nullptr);
        vkDestroyPipelineLayout(context.device, context.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(context.device, context.descriptorSetLayout, nullptr);
        return false;
    }
    
    // Allocate command buffer
    VkCommandBufferAllocateInfo cmdAllocInfo{};
    cmdAllocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cmdAllocInfo.commandPool = context.commandPool;
    cmdAllocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cmdAllocInfo.commandBufferCount = 1;
    
    if (vkAllocateCommandBuffers(context.device, &cmdAllocInfo, &context.commandBuffer) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to allocate command buffer\n");
        vkDestroyCommandPool(context.device, context.commandPool, nullptr);
        vkDestroyDescriptorPool(context.device, context.descriptorPool, nullptr);
        vkDestroyPipeline(context.device, context.computePipeline, nullptr);
        vkDestroyPipelineLayout(context.device, context.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(context.device, context.descriptorSetLayout, nullptr);
        return false;
    }
    
    // Create synchronization primitives
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fenceInfo.flags = VK_FENCE_CREATE_SIGNALED_BIT;  // Start signaled
    
    if (vkCreateFence(context.device, &fenceInfo, nullptr, &context.computeFence) != VK_SUCCESS) {
        printf("[VulkanManager] ERROR: Failed to create fence\n");
        vkDestroyCommandPool(context.device, context.commandPool, nullptr);
        vkDestroyDescriptorPool(context.device, context.descriptorPool, nullptr);
        vkDestroyPipeline(context.device, context.computePipeline, nullptr);
        vkDestroyPipelineLayout(context.device, context.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(context.device, context.descriptorSetLayout, nullptr);
        return false;
    }
    
    printf("[VulkanManager] Compute pipeline created successfully\n");
    printf("  - Shader module: loaded %zu bytes SPIR-V\n", shaderCode.size());
    printf("  - Descriptor set layout: 3 bindings\n");
    printf("  - Pipeline layout: created\n");
    printf("  - Compute pipeline: ready\n");
    printf("  - Command pool/buffer: allocated\n");
    printf("  - Synchronization: fence created\n");
    
    return true;
}

// Helper function to read SPIR-V binary file
std::vector<char> VulkanManager::readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::ate | std::ios::binary);
    
    if (!file.is_open()) {
        return {};
    }
    
    size_t fileSize = (size_t)file.tellg();
    std::vector<char> buffer(fileSize);
    
    file.seekg(0);
    file.read(buffer.data(), fileSize);
    file.close();
    
    return buffer;
}

uint32_t VulkanManager::findMemoryType(const VulkanContext& context, uint32_t typeFilter, uint32_t properties) {
    VkPhysicalDeviceMemoryProperties memProps{};
    fn_vkGetPhysicalDeviceMemoryProperties(context.physicalDevice, &memProps);
    
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        if ((typeFilter & (1u << i)) && (memProps.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }
    
    // Fallback to any matching type
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        if (typeFilter & (1u << i)) {
            return i;
        }
    }
    
    return UINT32_MAX;
}

std::vector<std::string> VulkanManager::enumerateDevices(VulkanContext& context) {
    if (!context.instance) return {};
    
    uint32_t deviceCount = 0;
    fn_vkEnumeratePhysicalDevices(context.instance, &deviceCount, nullptr);
    if (deviceCount == 0) return {};
    
    std::vector<VkPhysicalDevice_T*> devices(deviceCount);
    fn_vkEnumeratePhysicalDevices(context.instance, &deviceCount, devices.data());
    
    std::vector<std::string> names;
    for (auto* device : devices) {
        VkPhysicalDeviceProperties props{};
        fn_vkGetPhysicalDeviceProperties(device, &props);
        names.push_back(std::string(props.deviceName));
    }
    
    return names;
}

bool VulkanManager::selectDevice(VulkanContext& context, uint32_t deviceIndex) {
    uint32_t deviceCount = 0;
    fn_vkEnumeratePhysicalDevices(context.instance, &deviceCount, nullptr);
    if (deviceIndex >= deviceCount) return false;
    
    std::vector<VkPhysicalDevice_T*> devices(deviceCount);
    fn_vkEnumeratePhysicalDevices(context.instance, &deviceCount, devices.data());
    
    context.physicalDevice = devices[deviceIndex];
    return true;
}

bool VulkanManager::createPipeline(VulkanContext& context, const char* shaderPath) {
    // Pipeline creation with shader loading
    if (!context.device) return false;
    
    // Load SPIR-V shader from file if provided
    std::vector<uint32_t> shaderCode;
    if (shaderPath) {
        std::ifstream file(shaderPath, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            shaderCode.resize(size / sizeof(uint32_t));
            file.read(reinterpret_cast<char*>(shaderCode.data()), size);
        }
    }
    
    // If no shader loaded, return false
    if (shaderCode.empty()) {
        return false;
    }
    
    // Create shader module
    VkShaderModuleCreateInfo shaderInfo{};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = shaderCode.size() * sizeof(uint32_t);
    shaderInfo.pCode = shaderCode.data();
    
    VkShaderModule_T* shaderModule = nullptr;
    VkResult result = fn_vkCreateShaderModule(context.device, &shaderInfo, nullptr, &shaderModule);
    if (result != VK_SUCCESS) return false;
    
    // Create descriptor set layout
    VkDescriptorSetLayoutBinding bindings[] = {
        { 0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr },
        { 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr },
        { 2, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr }
    };
    
    VkDescriptorSetLayoutCreateInfo layoutInfo{};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 3;
    layoutInfo.pBindings = bindings;
    
    VkDescriptorSetLayout_T* descriptorSetLayout = nullptr;
    result = fn_vkCreateDescriptorSetLayout(context.device, &layoutInfo, nullptr, &descriptorSetLayout);
    if (result != VK_SUCCESS) {
        fn_vkDestroyShaderModule(context.device, shaderModule, nullptr);
        return false;
    }
    
    // Create pipeline layout
    VkPipelineLayoutCreateInfo pipelineLayoutInfo{};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &descriptorSetLayout;
    
    VkPipelineLayout_T* pipelineLayout = nullptr;
    result = fn_vkCreatePipelineLayout(context.device, &pipelineLayoutInfo, nullptr, &pipelineLayout);
    if (result != VK_SUCCESS) {
        fn_vkDestroyDescriptorSetLayout(context.device, descriptorSetLayout, nullptr);
        fn_vkDestroyShaderModule(context.device, shaderModule, nullptr);
        return false;
    }
    
    // Create compute pipeline
    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipelineInfo.stage.module = shaderModule;
    pipelineInfo.stage.pName = "main";
    pipelineInfo.layout = pipelineLayout;
    
    VkPipeline_T* pipeline = nullptr;
    result = fn_vkCreateComputePipelines(context.device, nullptr, 1, &pipelineInfo, nullptr, &pipeline);
    
    // Cleanup shader module (no longer needed after pipeline creation)
    fn_vkDestroyShaderModule(context.device, shaderModule, nullptr);
    
    if (result != VK_SUCCESS) {
        fn_vkDestroyPipelineLayout(context.device, pipelineLayout, nullptr);
        fn_vkDestroyDescriptorSetLayout(context.device, descriptorSetLayout, nullptr);
        return false;
    }
    
    // Store pipeline resources in context or manager
    // Note: In production, these should be stored properly
    return true;
}

bool VulkanManager::updateDescriptorSet(VulkanContext& context, VkBuffer_T* buffer0, VkBuffer_T* buffer1, VkBuffer_T* buffer2) {
    // Update descriptor sets with buffer bindings
    if (!context.device) return false;
    return true; // Placeholder - full implementation would update descriptor sets
}

VkDeviceSize VulkanManager::getDeviceMemorySize(const VulkanContext& context) {
    if (!context.physicalDevice) return 0;
    
    VkPhysicalDeviceMemoryProperties memProps{};
    fn_vkGetPhysicalDeviceMemoryProperties(context.physicalDevice, &memProps);
    
    VkDeviceSize totalSize = 0;
    for (uint32_t i = 0; i < memProps.memoryHeapCount; ++i) {
        if (memProps.memoryHeaps[i].flags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
            totalSize += memProps.memoryHeaps[i].size;
        }
    }
    
    return totalSize;
}

VkDeviceSize VulkanManager::getDeviceMemoryUsed(const VulkanContext& context) {
    // Would require VK_EXT_memory_budget extension
    // Return 0 as placeholder
    return 0;
}

bool VulkanManager::copyBuffer(VulkanContext& context, VkBuffer_T* srcBuffer, VkBuffer_T* dstBuffer, VkDeviceSize size) {
    if (!context.device || !context.commandBuffer || !srcBuffer || !dstBuffer) return false;
    
    VkResult result = fn_vkResetFences(context.device, 1, &context.fence);
    if (result != VK_SUCCESS) return false;
    
    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    
    result = fn_vkBeginCommandBuffer(context.commandBuffer, &beginInfo);
    if (result != VK_SUCCESS) return false;
    
    // Record copy command
    struct VkBufferCopy { VkDeviceSize srcOffset; VkDeviceSize dstOffset; VkDeviceSize size; };
    VkBufferCopy copyRegion{ 0, 0, size };
    fn_vkCmdCopyBuffer(context.commandBuffer, srcBuffer, dstBuffer, 1, &copyRegion);
    
    result = fn_vkEndCommandBuffer(context.commandBuffer);
    if (result != VK_SUCCESS) return false;
    
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &context.commandBuffer;
    
    result = fn_vkQueueSubmit(context.computeQueue, 1, &submitInfo, context.fence);
    if (result != VK_SUCCESS) return false;
    
    result = fn_vkWaitForFences(context.device, 1, &context.fence, 1, 5000000000ULL);
    return result == VK_SUCCESS;
}

void VulkanManager::cmdPipelineBarrier(VulkanContext& context, VkPipelineStageFlags srcStage, 
                                        VkPipelineStageFlags dstStage, VkBuffer_T* buffer, 
                                        VkAccessFlags srcAccess, VkAccessFlags dstAccess) {
    if (!context.commandBuffer || !buffer) return;
    
    VkBufferMemoryBarrier barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrier.srcAccessMask = srcAccess;
    barrier.dstAccessMask = dstAccess;
    barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.buffer = buffer;
    barrier.offset = 0;
    barrier.size = VK_WHOLE_SIZE;
    
    fn_vkCmdPipelineBarrier(context.commandBuffer, srcStage, dstStage, 0, 0, nullptr, 1, &barrier, 0, nullptr);
}

// Additional helper implementations
bool VulkanManager::waitForCompletion(VulkanContext& context, uint64_t timeoutNs) {
    if (!context.device || !context.fence) return false;
    
    VkResult result = fn_vkWaitForFences(context.device, 1, &context.fence, 1, timeoutNs);
    return result == VK_SUCCESS;
}

} // namespace RawrXD::Agentic::Vulkan

=======
// vulkan_compute_real.cpp - PRODUCTION VULKAN INITIALIZATION
// Replaces stub with full instance/device/queue setup
// Implements complete Vulkan compute pipeline with error handling and logging

#include <vulkan/vulkan.h>
#include <windows.h>
#include <vector>
#include <stdio.h>
#include <cstring>

// ============================================================
// STRUCTURED LOGGING
// ============================================================
enum LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

static void LogMessage(LogLevel level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    const char* level_str[] = { "[DEBUG]", "[INFO]", "[WARN]", "[ERROR]" };
    printf("%s ", level_str[level]);
    vprintf(fmt, args);
    printf("\n");

    va_end(args);
}

// ============================================================
// VULKAN FUNCTION POINTERS (FOR EXTENSIONS)
// ============================================================
PFN_vkCreateDebugReportCallbackEXT vkCreateDebugReportCallbackEXT = nullptr;
PFN_vkDestroyDebugReportCallbackEXT vkDestroyDebugReportCallbackEXT = nullptr;

// ============================================================
// GLOBAL STATE
// ============================================================
static VkInstance g_instance = VK_NULL_HANDLE;
static VkPhysicalDevice g_physical_device = VK_NULL_HANDLE;
static VkDevice g_device = VK_NULL_HANDLE;
static VkQueue g_compute_queue = VK_NULL_HANDLE;
static uint32_t g_compute_queue_family = 0;
static VkCommandPool g_command_pool = VK_NULL_HANDLE;
static VkDebugReportCallbackEXT g_debug_callback = VK_NULL_HANDLE;
static HMODULE g_vulkan_module = nullptr;
static bool g_vulkan_initialized = false;

// ============================================================
// DEBUG CALLBACK IMPLEMENTATION
// ============================================================
static VKAPI_ATTR VkBool32 VKAPI_CALL DebugCallback(
    VkDebugReportFlagsEXT flags,
    VkDebugReportObjectTypeEXT objType,
    uint64_t obj,
    size_t location,
    int32_t code,
    const char* layerPrefix,
    const char* msg,
    void* userData) {
    
    if (flags & VK_DEBUG_REPORT_ERROR_BIT_EXT) {
        LogMessage(ERROR, "VULKAN ERROR [%s]: %s", layerPrefix, msg);
    } else if (flags & VK_DEBUG_REPORT_WARNING_BIT_EXT) {
        LogMessage(WARN, "VULKAN WARNING [%s]: %s", layerPrefix, msg);
    } else {
        LogMessage(DEBUG, "VULKAN [%s]: %s", layerPrefix, msg);
    }
    return VK_FALSE;
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

// Convert VkResult to string
static const char* VkResultString(VkResult result) {
    switch (result) {
        case VK_SUCCESS: return "VK_SUCCESS";
        case VK_NOT_READY: return "VK_NOT_READY";
        case VK_TIMEOUT: return "VK_TIMEOUT";
        case VK_EVENT_SET: return "VK_EVENT_SET";
        case VK_EVENT_RESET: return "VK_EVENT_RESET";
        case VK_INCOMPLETE: return "VK_INCOMPLETE";
        case VK_ERROR_OUT_OF_HOST_MEMORY: return "VK_ERROR_OUT_OF_HOST_MEMORY";
        case VK_ERROR_OUT_OF_DEVICE_MEMORY: return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
        case VK_ERROR_INITIALIZATION_FAILED: return "VK_ERROR_INITIALIZATION_FAILED";
        case VK_ERROR_DEVICE_LOST: return "VK_ERROR_DEVICE_LOST";
        case VK_ERROR_MEMORY_MAP_FAILED: return "VK_ERROR_MEMORY_MAP_FAILED";
        case VK_ERROR_LAYER_NOT_PRESENT: return "VK_ERROR_LAYER_NOT_PRESENT";
        case VK_ERROR_EXTENSION_NOT_PRESENT: return "VK_ERROR_EXTENSION_NOT_PRESENT";
        case VK_ERROR_FEATURE_NOT_PRESENT: return "VK_ERROR_FEATURE_NOT_PRESENT";
        case VK_ERROR_INCOMPATIBLE_DRIVER: return "VK_ERROR_INCOMPATIBLE_DRIVER";
        case VK_ERROR_TOO_MANY_OBJECTS: return "VK_ERROR_TOO_MANY_OBJECTS";
        case VK_ERROR_FORMAT_NOT_SUPPORTED: return "VK_ERROR_FORMAT_NOT_SUPPORTED";
        case VK_ERROR_FRAGMENTED_POOL: return "VK_ERROR_FRAGMENTED_POOL";
        default: return "UNKNOWN_ERROR";
    }
}

// Load Vulkan DLL
static bool LoadVulkanLibrary() {
    LogMessage(INFO, "Loading Vulkan runtime library");
    
    g_vulkan_module = LoadLibraryA("vulkan-1.dll");
    if (!g_vulkan_module) {
        LogMessage(ERROR, "Failed to load vulkan-1.dll");
        return false;
    }
    
    LogMessage(DEBUG, "vulkan-1.dll loaded successfully");
    return true;
}

// ============================================================
// REAL VULKAN INITIALIZATION
// ============================================================
VkResult Titan_Vulkan_Init_Real() {
    auto start_time = GetTickCount();
    
    LogMessage(INFO, "=== Starting Vulkan Initialization ===");
    
    if (g_vulkan_initialized) {
        LogMessage(WARN, "Vulkan already initialized, skipping");
        return VK_SUCCESS;
    }
    
    // 1. Load Vulkan library
    if (!LoadVulkanLibrary()) {
        LogMessage(ERROR, "Failed to load Vulkan library");
        return VK_ERROR_INITIALIZATION_FAILED;
    }
    
    // 2. Application info
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD AI Inference";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD Engine";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_3;
    
    LogMessage(DEBUG, "Application Info: name=RawrXD, API version=1.3");
    
    // 3. Instance extensions
    const char* extensions[] = {
        VK_EXT_DEBUG_REPORT_EXTENSION_NAME,
        VK_KHR_EXTERNAL_MEMORY_CAPABILITIES_EXTENSION_NAME,
        VK_KHR_GET_PHYSICAL_DEVICE_PROPERTIES_2_EXTENSION_NAME
    };
    uint32_t extension_count = 3;
    
    // 4. Validation layers (debug mode)
    const char* layers[] = {
        "VK_LAYER_KHRONOS_validation"
    };
    uint32_t layer_count = 1;
    
    LogMessage(DEBUG, "Requesting %d extensions and %d validation layers", extension_count, layer_count);
    
    // 5. Instance create info
    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;
    createInfo.enabledExtensionCount = extension_count;
    createInfo.ppEnabledExtensionNames = extensions;
    createInfo.enabledLayerCount = layer_count;
    createInfo.ppEnabledLayerNames = layers;
    
    // 6. Create Vulkan instance
    LogMessage(INFO, "Creating Vulkan instance");
    VkResult result = vkCreateInstance(&createInfo, nullptr, &g_instance);
    if (result != VK_SUCCESS) {
        LogMessage(ERROR, "vkCreateInstance failed: %s (0x%08X)", VkResultString(result), result);
        goto VULKAN_INIT_FAILED;
    }
    LogMessage(DEBUG, "Vulkan instance created successfully");
    
    // 7. Setup debug callback
    vkCreateDebugReportCallbackEXT = (PFN_vkCreateDebugReportCallbackEXT)
        vkGetInstanceProcAddr(g_instance, "vkCreateDebugReportCallbackEXT");
    vkDestroyDebugReportCallbackEXT = (PFN_vkDestroyDebugReportCallbackEXT)
        vkGetInstanceProcAddr(g_instance, "vkDestroyDebugReportCallbackEXT");
    
    if (vkCreateDebugReportCallbackEXT) {
        VkDebugReportCallbackCreateInfoEXT debugCreateInfo = {};
        debugCreateInfo.sType = VK_STRUCTURE_TYPE_DEBUG_REPORT_CALLBACK_CREATE_INFO_EXT;
        debugCreateInfo.flags = VK_DEBUG_REPORT_ERROR_BIT_EXT | 
                                VK_DEBUG_REPORT_WARNING_BIT_EXT |
                                VK_DEBUG_REPORT_PERFORMANCE_WARNING_BIT_EXT;
        debugCreateInfo.pfnCallback = DebugCallback;
        
        result = vkCreateDebugReportCallbackEXT(g_instance, &debugCreateInfo, nullptr, &g_debug_callback);
        if (result == VK_SUCCESS) {
            LogMessage(DEBUG, "Debug callback installed");
        }
    } else {
        LogMessage(WARN, "Debug extension not available");
    }
    
    // 8. Enumerate physical devices
    LogMessage(INFO, "Enumerating physical devices");
    uint32_t deviceCount = 0;
    result = vkEnumeratePhysicalDevices(g_instance, &deviceCount, nullptr);
    if (result != VK_SUCCESS || deviceCount == 0) {
        LogMessage(ERROR, "No Vulkan devices found or enumeration failed: %s", VkResultString(result));
        goto VULKAN_INIT_FAILED;
    }
    LogMessage(DEBUG, "Found %d physical devices", deviceCount);
    
    std::vector<VkPhysicalDevice> devices(deviceCount);
    result = vkEnumeratePhysicalDevices(g_instance, &deviceCount, devices.data());
    if (result != VK_SUCCESS) {
        LogMessage(ERROR, "Failed to enumerate physical devices: %s", VkResultString(result));
        goto VULKAN_INIT_FAILED;
    }
    
    // 9. Select best device (discrete GPU preferred)
    LogMessage(INFO, "Selecting physical device");
    VkPhysicalDeviceProperties deviceProps;
    bool found_compute_device = false;
    
    for (auto& device : devices) {
        vkGetPhysicalDeviceProperties(device, &deviceProps);
        
        LogMessage(DEBUG, "Device: %s (Type: %d)", deviceProps.deviceName, deviceProps.deviceType);
        
        // Check for compute queue
        uint32_t queueFamilyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(device, &queueFamilyCount, nullptr);
        
        std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
        vkGetPhysicalDeviceQueueFamilyProperties(device, &queueFamilyCount, queueFamilies.data());
        
        for (uint32_t i = 0; i < queueFamilyCount; i++) {
            if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
                LogMessage(DEBUG, "  Queue family %d: compute capable (count=%d)", i, queueFamilies[i].queueCount);
                
                // Prefer discrete GPU
                if (deviceProps.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU || 
                    !found_compute_device) {
                    g_physical_device = device;
                    g_compute_queue_family = i;
                    found_compute_device = true;
                    
                    if (deviceProps.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
                        LogMessage(DEBUG, "Selected discrete GPU: %s", deviceProps.deviceName);
                        goto DEVICE_SELECTED;
                    }
                }
            }
        }
    }
    
    DEVICE_SELECTED:
    if (g_physical_device == VK_NULL_HANDLE) {
        LogMessage(ERROR, "No device with compute support found");
        goto VULKAN_INIT_FAILED;
    }
    
    vkGetPhysicalDeviceProperties(g_physical_device, &deviceProps);
    LogMessage(INFO, "Selected GPU: %s (queue family: %d)", deviceProps.deviceName, g_compute_queue_family);
    
    // 10. Create logical device
    LogMessage(INFO, "Creating logical device");
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo = {};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = g_compute_queue_family;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;
    
    // Enable shader features
    VkPhysicalDeviceFeatures deviceFeatures = {};
    deviceFeatures.shaderFloat64 = VK_TRUE;
    deviceFeatures.shaderInt64 = VK_TRUE;
    
    // Device extensions
    const char* deviceExtensions[] = {
        VK_KHR_EXTERNAL_MEMORY_EXTENSION_NAME,
        VK_KHR_EXTERNAL_MEMORY_WIN32_EXTENSION_NAME,
        VK_KHR_EXTERNAL_SEMAPHORE_EXTENSION_NAME,
        VK_KHR_EXTERNAL_SEMAPHORE_WIN32_EXTENSION_NAME
    };
    uint32_t device_ext_count = 4;
    
    VkDeviceCreateInfo deviceCreateInfo = {};
    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;
    deviceCreateInfo.pEnabledFeatures = &deviceFeatures;
    deviceCreateInfo.enabledExtensionCount = device_ext_count;
    deviceCreateInfo.ppEnabledExtensionNames = deviceExtensions;
    
    result = vkCreateDevice(g_physical_device, &deviceCreateInfo, nullptr, &g_device);
    if (result != VK_SUCCESS) {
        LogMessage(ERROR, "vkCreateDevice failed: %s", VkResultString(result));
        goto VULKAN_INIT_FAILED;
    }
    LogMessage(DEBUG, "Logical device created successfully");
    
    // 11. Get compute queue
    vkGetDeviceQueue(g_device, g_compute_queue_family, 0, &g_compute_queue);
    if (g_compute_queue == VK_NULL_HANDLE) {
        LogMessage(ERROR, "Failed to get compute queue");
        goto VULKAN_INIT_FAILED;
    }
    LogMessage(DEBUG, "Compute queue obtained");
    
    // 12. Create command pool
    LogMessage(INFO, "Creating command pool");
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = g_compute_queue_family;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    
    result = vkCreateCommandPool(g_device, &poolInfo, nullptr, &g_command_pool);
    if (result != VK_SUCCESS) {
        LogMessage(ERROR, "vkCreateCommandPool failed: %s", VkResultString(result));
        goto VULKAN_INIT_FAILED;
    }
    LogMessage(DEBUG, "Command pool created successfully");
    
    g_vulkan_initialized = true;
    LogMessage(INFO, "=== Vulkan Initialization Complete (%.0f ms) ===", 
        (float)(GetTickCount() - start_time));
    
    return VK_SUCCESS;
    
VULKAN_INIT_FAILED:
    Titan_Vulkan_Cleanup();
    return result;
}

// ============================================================
// CLEANUP FUNCTION (MEMORY LEAK FIX)
// ============================================================
void Titan_Vulkan_Cleanup() {
    LogMessage(INFO, "=== Starting Vulkan Cleanup ===");
    
    if (g_command_pool != VK_NULL_HANDLE) {
        LogMessage(DEBUG, "Destroying command pool");
        vkDestroyCommandPool(g_device, g_command_pool, nullptr);
        g_command_pool = VK_NULL_HANDLE;
    }
    
    if (g_debug_callback != VK_NULL_HANDLE && vkDestroyDebugReportCallbackEXT) {
        LogMessage(DEBUG, "Destroying debug callback");
        vkDestroyDebugReportCallbackEXT(g_instance, g_debug_callback, nullptr);
        g_debug_callback = VK_NULL_HANDLE;
    }
    
    if (g_device != VK_NULL_HANDLE) {
        LogMessage(DEBUG, "Waiting for device idle");
        vkDeviceWaitIdle(g_device);
        
        LogMessage(DEBUG, "Destroying device");
        vkDestroyDevice(g_device, nullptr);
        g_device = VK_NULL_HANDLE;
    }
    
    if (g_instance != VK_NULL_HANDLE) {
        LogMessage(DEBUG, "Destroying instance");
        vkDestroyInstance(g_instance, nullptr);
        g_instance = VK_NULL_HANDLE;
    }
    
    if (g_vulkan_module) {
        LogMessage(DEBUG, "Unloading vulkan-1.dll");
        FreeLibrary(g_vulkan_module);
        g_vulkan_module = nullptr;
    }
    
    g_vulkan_initialized = false;
    LogMessage(INFO, "=== Vulkan Cleanup Complete ===");
}

// ============================================================
// GETTER FUNCTIONS
// ============================================================
VkDevice Titan_Vulkan_GetDevice() { 
    return g_device; 
}

VkPhysicalDevice Titan_Vulkan_GetPhysicalDevice() {
    return g_physical_device;
}

VkQueue Titan_Vulkan_GetQueue() { 
    return g_compute_queue; 
}

uint32_t Titan_Vulkan_GetQueueFamily() { 
    return g_compute_queue_family; 
}

VkCommandPool Titan_Vulkan_GetCommandPool() { 
    return g_command_pool; 
}

bool Titan_Vulkan_IsInitialized() {
    return g_vulkan_initialized;
}

// ============================================================
// SAFE WRAPPER
// ============================================================
VkResult Titan_Vulkan_Init_Safe() {
    try {
        return Titan_Vulkan_Init_Real();
    }
    catch (const std::exception& e) {
        LogMessage(ERROR, "Exception in Vulkan initialization: %s", e.what());
        Titan_Vulkan_Cleanup();
        return VK_ERROR_INITIALIZATION_FAILED;
    }
    catch (...) {
        LogMessage(ERROR, "Unknown exception in Vulkan initialization");
        Titan_Vulkan_Cleanup();
        return VK_ERROR_INITIALIZATION_FAILED;
    }
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
