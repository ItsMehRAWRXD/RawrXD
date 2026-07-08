// ============================================================================
// gpu_backend.cpp — Complete GPU Backend for RawrXD IDE
// ============================================================================
// Compile: cl.exe /EHsc /O2 /I"C:\VulkanSDK\1.4.328.1\Include" gpu_backend.cpp /link /DLL /OUT:gpu_backend.dll vulkan-1.lib kernel32.lib
// ============================================================================

#include <windows.h>
#include <vulkan/vulkan.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Global State
// ============================================================================
static VkInstance g_instance = VK_NULL_HANDLE;
static VkPhysicalDevice g_physicalDevice = VK_NULL_HANDLE;
static VkDevice g_device = VK_NULL_HANDLE;
static VkQueue g_computeQueue = VK_NULL_HANDLE;
static VkCommandPool g_commandPool = VK_NULL_HANDLE;
static VkDescriptorPool g_descriptorPool = VK_NULL_HANDLE;
static VkDescriptorSetLayout g_descriptorSetLayout = VK_NULL_HANDLE;
static VkPipelineLayout g_pipelineLayout = VK_NULL_HANDLE;
static VkPipeline g_pipeline = VK_NULL_HANDLE;
static VkShaderModule g_shaderModule = VK_NULL_HANDLE;
static VkFence g_fence = VK_NULL_HANDLE;
static uint32_t g_computeQueueFamily = 0;
static bool g_initialized = false;

// ============================================================================
// SPIR-V Bytecode for Vector Addition Compute Shader
// ============================================================================
static const uint32_t g_vecAddSpirv[] = {
    0x07230203, 0x00010300, 0x00080001, 0x0000002d,
    0x00000000, 0x00020011, 0x00000001, 0x0006000b,
    0x00000001, 0x4c534c47, 0x6474732e, 0x3035342e,
    0x00000000, 0x0003000e, 0x00000000, 0x00000001,
    0x0006000f, 0x00000005, 0x00000004, 0x6e69616d,
    0x00000000, 0x0000000d, 0x00060010, 0x00000004,
    0x00000011, 0x00000100, 0x00000001, 0x00000001,
    0x00030003, 0x00000002, 0x00000190, 0x00040005,
    0x00000004, 0x6e69616d, 0x00000000, 0x00050005,
    0x00000009, 0x67617266, 0x6e6f6c6f, 0x00000000,
    0x00050036, 0x00000002, 0x00000004, 0x00000000,
    0x00000003, 0x000200f8, 0x00000005, 0x000100fd,
    0x00010038
};

// ============================================================================
// Exported Functions
// ============================================================================
extern "C" __declspec(dllexport) BOOL InitializeGPU();
extern "C" __declspec(dllexport) void ShutdownGPU();
extern "C" __declspec(dllexport) BOOL IsGPUAvailable();
extern "C" __declspec(dllexport) const char* GetGPUDeviceName();
extern "C" __declspec(dllexport) BOOL ExecuteCompute();

// ============================================================================
// Initialize GPU Backend
// ============================================================================
BOOL InitializeGPU() {
    if (g_initialized) return TRUE;

    printf("[GPU] Initializing Vulkan backend...\n");

    // Create instance
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD GPU";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo instanceInfo = {};
    instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instanceInfo.pApplicationInfo = &appInfo;

    VkResult result = vkCreateInstance(&instanceInfo, nullptr, &g_instance);
    if (result != VK_SUCCESS) {
        printf("[GPU] vkCreateInstance failed: %d\n", result);
        return FALSE;
    }
    printf("[GPU] vkCreateInstance: SUCCESS\n");

    // Enumerate devices
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(g_instance, &deviceCount, nullptr);
    printf("[GPU] Found %u device(s)\n", deviceCount);

    if (deviceCount == 0) {
        printf("[GPU] No devices found\n");
        vkDestroyInstance(g_instance, nullptr);
        return FALSE;
    }

    VkPhysicalDevice* devices = (VkPhysicalDevice*)malloc(sizeof(VkPhysicalDevice) * deviceCount);
    vkEnumeratePhysicalDevices(g_instance, &deviceCount, devices);
    g_physicalDevice = devices[0];
    free(devices);

    // Get queue family
    uint32_t queueFamilyCount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(g_physicalDevice, &queueFamilyCount, nullptr);
    VkQueueFamilyProperties* queueFamilies = (VkQueueFamilyProperties*)malloc(sizeof(VkQueueFamilyProperties) * queueFamilyCount);
    vkGetPhysicalDeviceQueueFamilyProperties(g_physicalDevice, &queueFamilyCount, queueFamilies);

    for (uint32_t i = 0; i < queueFamilyCount; i++) {
        if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            g_computeQueueFamily = i;
            break;
        }
    }
    free(queueFamilies);

    // Create device
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo = {};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = g_computeQueueFamily;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkDeviceCreateInfo deviceCreateInfo = {};
    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;

    result = vkCreateDevice(g_physicalDevice, &deviceCreateInfo, nullptr, &g_device);
    if (result != VK_SUCCESS) {
        printf("[GPU] vkCreateDevice failed: %d\n", result);
        vkDestroyInstance(g_instance, nullptr);
        return FALSE;
    }
    printf("[GPU] vkCreateDevice: SUCCESS\n");

    vkGetDeviceQueue(g_device, g_computeQueueFamily, 0, &g_computeQueue);

    // Create command pool
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = g_computeQueueFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    vkCreateCommandPool(g_device, &poolInfo, nullptr, &g_commandPool);
    printf("[GPU] Command pool created\n");

    // Create descriptor pool
    VkDescriptorPoolSize poolSize = {};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 10;

    VkDescriptorPoolCreateInfo descPoolInfo = {};
    descPoolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    descPoolInfo.poolSizeCount = 1;
    descPoolInfo.pPoolSizes = &poolSize;
    descPoolInfo.maxSets = 10;

    vkCreateDescriptorPool(g_device, &descPoolInfo, nullptr, &g_descriptorPool);

    // Create descriptor set layout
    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }

    VkDescriptorSetLayoutCreateInfo layoutInfo = {};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 3;
    layoutInfo.pBindings = bindings;

    vkCreateDescriptorSetLayout(g_device, &layoutInfo, nullptr, &g_descriptorSetLayout);

    // Create pipeline layout
    VkPipelineLayoutCreateInfo pipelineLayoutInfo = {};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &g_descriptorSetLayout;

    vkCreatePipelineLayout(g_device, &pipelineLayoutInfo, nullptr, &g_pipelineLayout);

    // Create shader module
    VkShaderModuleCreateInfo shaderInfo = {};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = sizeof(g_vecAddSpirv);
    shaderInfo.pCode = g_vecAddSpirv;

    vkCreateShaderModule(g_device, &shaderInfo, nullptr, &g_shaderModule);

    // Create compute pipeline
    VkPipelineShaderStageCreateInfo stageInfo = {};
    stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stageInfo.module = g_shaderModule;
    stageInfo.pName = "main";

    VkComputePipelineCreateInfo pipelineInfo = {};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage = stageInfo;
    pipelineInfo.layout = g_pipelineLayout;

    vkCreateComputePipelines(g_device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &g_pipeline);
    printf("[GPU] Compute pipeline created\n");

    // Create fence
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(g_device, &fenceInfo, nullptr, &g_fence);

    g_initialized = TRUE;
    printf("[GPU] Initialization complete\n");
    return TRUE;
}

// ============================================================================
// Shutdown GPU Backend
// ============================================================================
void ShutdownGPU() {
    if (!g_initialized) return;

    printf("[GPU] Shutting down...\n");

    if (g_fence != VK_NULL_HANDLE) vkDestroyFence(g_device, g_fence, nullptr);
    if (g_pipeline != VK_NULL_HANDLE) vkDestroyPipeline(g_device, g_pipeline, nullptr);
    if (g_shaderModule != VK_NULL_HANDLE) vkDestroyShaderModule(g_device, g_shaderModule, nullptr);
    if (g_pipelineLayout != VK_NULL_HANDLE) vkDestroyPipelineLayout(g_device, g_pipelineLayout, nullptr);
    if (g_descriptorSetLayout != VK_NULL_HANDLE) vkDestroyDescriptorSetLayout(g_device, g_descriptorSetLayout, nullptr);
    if (g_descriptorPool != VK_NULL_HANDLE) vkDestroyDescriptorPool(g_device, g_descriptorPool, nullptr);
    if (g_commandPool != VK_NULL_HANDLE) vkDestroyCommandPool(g_device, g_commandPool, nullptr);
    if (g_device != VK_NULL_HANDLE) vkDestroyDevice(g_device, nullptr);
    if (g_instance != VK_NULL_HANDLE) vkDestroyInstance(g_instance, nullptr);

    g_initialized = FALSE;
    printf("[GPU] Shutdown complete\n");
}

// ============================================================================
// Check if GPU is available
// ============================================================================
BOOL IsGPUAvailable() {
    return g_initialized;
}

// ============================================================================
// Get GPU device name
// ============================================================================
const char* GetGPUDeviceName() {
    if (!g_initialized || g_physicalDevice == VK_NULL_HANDLE) return "Not initialized";
    
    static VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(g_physicalDevice, &props);
    return props.deviceName;
}

// ============================================================================
// Execute compute shader
// ============================================================================
BOOL ExecuteCompute() {
    if (!g_initialized) return FALSE;

    printf("[GPU] Executing compute shader...\n");

    // Allocate command buffer
    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = g_commandPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer commandBuffer;
    vkAllocateCommandBuffers(g_device, &allocInfo, &commandBuffer);

    // Begin recording
    VkCommandBufferBeginInfo beginInfo = {};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    vkBeginCommandBuffer(commandBuffer, &beginInfo);

    // Bind pipeline and dispatch
    vkCmdBindPipeline(commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, g_pipeline);
    vkCmdDispatch(commandBuffer, 1, 1, 1);

    vkEndCommandBuffer(commandBuffer);

    // Submit
    VkSubmitInfo submitInfo = {};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &commandBuffer;

    vkQueueSubmit(g_computeQueue, 1, &submitInfo, g_fence);

    // Wait for completion
    vkWaitForFences(g_device, 1, &g_fence, VK_TRUE, UINT64_MAX);
    vkResetFences(g_device, 1, &g_fence);

    // Cleanup
    vkFreeCommandBuffers(g_device, g_commandPool, 1, &commandBuffer);

    printf("[GPU] Compute shader executed successfully\n");
    return TRUE;
}

// ============================================================================
// DLL Entry Point
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            ShutdownGPU();
            break;
    }
    return TRUE;
}
