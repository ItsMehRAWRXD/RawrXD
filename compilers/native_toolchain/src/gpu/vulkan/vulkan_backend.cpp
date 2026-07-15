// vulkan_backend.cpp - Vulkan Compute Backend Implementation
// Phase 8.3 G12: Vulkan Compute Implementation

#define VK_USE_PLATFORM_WIN32_KHR
#define NOMINMAX

#include "vulkan_backend.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ============================================================================
// DEBUG CALLBACK
// ============================================================================

static VKAPI_ATTR VkBool32 VKAPI_CALL debug_callback(
    VkDebugUtilsMessageSeverityFlagBitsEXT severity,
    VkDebugUtilsMessageTypeFlagsEXT type,
    const VkDebugUtilsMessengerCallbackDataEXT* callback_data,
    void* user_data
) {
    (void)type;
    (void)user_data;
    
    if (severity >= VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT) {
        printf("[Vulkan] %s\n", callback_data->pMessage);
    }
    return VK_FALSE;
}

// ============================================================================
// DEVICE ENUMERATION
// ============================================================================

int Vulkan_EnumerateDevices(GPUDeviceInfo* devices, int max_devices) {
    VkInstanceCreateInfo create_info = {0};
    create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    
    const char* extensions[] = {
        VK_EXT_DEBUG_UTILS_EXTENSION_NAME
    };
    create_info.enabledExtensionCount = 1;
    create_info.ppEnabledExtensionNames = extensions;
    
    VkInstance instance;
    VkResult result = vkCreateInstance(&create_info, NULL, &instance);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to create instance: %d\n", result);
        return 0;
    }
    
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(instance, &device_count, NULL);
    
    if (device_count == 0) {
        printf("[Vulkan] No devices found\n");
        vkDestroyInstance(instance, NULL);
        return 0;
    }
    
    VkPhysicalDevice* physical_devices = (VkPhysicalDevice*)malloc(
        device_count * sizeof(VkPhysicalDevice));
    vkEnumeratePhysicalDevices(instance, &device_count, physical_devices);
    
    int count = 0;
    for (uint32_t i = 0; i < device_count && count < max_devices; i++) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(physical_devices[i], &props);
        
        // Check for compute capability
        VkPhysicalDeviceFeatures features;
        vkGetPhysicalDeviceFeatures(physical_devices[i], &features);
        
        VkPhysicalDeviceMemoryProperties mem_props;
        vkGetPhysicalDeviceMemoryProperties(physical_devices[i], &mem_props);
        
        // Find local device memory
        uint64_t vram_size = 0;
        for (uint32_t j = 0; j < mem_props.memoryTypeCount; j++) {
            if (mem_props.memoryTypes[j].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                vram_size = mem_props.memoryHeaps[mem_props.memoryTypes[j].heapIndex].size;
                break;
            }
        }
        
        // Only include discrete GPUs or devices with significant VRAM
        if (vram_size > 1024 * 1024 * 1024) {  // > 1GB
            strncpy(devices[count].name, props.deviceName, sizeof(devices[count].name) - 1);
            devices[count].vendor_id = props.vendorID;
            devices[count].device_id = props.deviceID;
            devices[count].vram_size = vram_size;
            devices[count].vram_free = vram_size;  // Approximation
            devices[count].compute_units = 0;  // Would query from driver
            devices[count].max_workgroup_size = props.limits.maxComputeWorkGroupSize[0];
            devices[count].supports_fp16 = 0;  // Check extension instead
            devices[count].supports_int8 = 0;  // Check extension
            count++;
        }
    }
    
    free(physical_devices);
    vkDestroyInstance(instance, NULL);
    
    printf("[Vulkan] Found %d suitable compute devices\n", count);
    return count;
}

// ============================================================================
// BACKEND CREATION
// ============================================================================

GPUBackend* Vulkan_BackendCreate(void) {
    GPUBackend* backend = (GPUBackend*)calloc(1, sizeof(GPUBackend));
    if (!backend) return NULL;
    
    VulkanContext* ctx = (VulkanContext*)calloc(1, sizeof(VulkanContext));
    if (!ctx) {
        free(backend);
        return NULL;
    }
    
    backend->type = GPU_BACKEND_VULKAN;
    backend->device = ctx;
    
    // Create Vulkan instance
    VkApplicationInfo app_info = {0};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "RawrXD GPU Backend";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "RawrXD";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_2;
    
    const char* extensions[] = {
        VK_EXT_DEBUG_UTILS_EXTENSION_NAME
    };
    
    VkInstanceCreateInfo instance_info = {0};
    instance_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instance_info.pApplicationInfo = &app_info;
    instance_info.enabledExtensionCount = 1;
    instance_info.ppEnabledExtensionNames = extensions;
    
    VkResult result = vkCreateInstance(&instance_info, NULL, &ctx->instance);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to create instance: %d\n", result);
        free(ctx);
        free(backend);
        return NULL;
    }
    
    // Select physical device
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(ctx->instance, &device_count, NULL);
    if (device_count == 0) {
        printf("[Vulkan] No devices found\n");
        vkDestroyInstance(ctx->instance, NULL);
        free(ctx);
        free(backend);
        return NULL;
    }
    
    VkPhysicalDevice* devices = (VkPhysicalDevice*)malloc(
        device_count * sizeof(VkPhysicalDevice));
    vkEnumeratePhysicalDevices(ctx->instance, &device_count, devices);
    
    // Select first discrete GPU or GPU with most VRAM
    ctx->physical_device = devices[0];
    uint64_t best_vram = 0;
    
    for (uint32_t i = 0; i < device_count; i++) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(devices[i], &props);
        
        VkPhysicalDeviceMemoryProperties mem_props;
        vkGetPhysicalDeviceMemoryProperties(devices[i], &mem_props);
        
        uint64_t vram = 0;
        for (uint32_t j = 0; j < mem_props.memoryTypeCount; j++) {
            if (mem_props.memoryTypes[j].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                vram = mem_props.memoryHeaps[mem_props.memoryTypes[j].heapIndex].size;
                break;
            }
        }
        
        // Prefer discrete GPU
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU || vram > best_vram) {
            ctx->physical_device = devices[i];
            best_vram = vram;
        }
    }
    
    free(devices);
    
    // Get device properties
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(ctx->physical_device, &props);
    vkGetPhysicalDeviceMemoryProperties(ctx->physical_device, &ctx->memory_props);
    
    strncpy(backend->device_info.name, props.deviceName, sizeof(backend->device_info.name) - 1);
    backend->device_info.vendor_id = props.vendorID;
    backend->device_info.device_id = props.deviceID;
    backend->device_info.max_workgroup_size = props.limits.maxComputeWorkGroupSize[0];
    
    // Find local memory size
    for (uint32_t i = 0; i < ctx->memory_props.memoryTypeCount; i++) {
        if (ctx->memory_props.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
            backend->device_info.vram_size = ctx->memory_props.memoryHeaps[
                ctx->memory_props.memoryTypes[i].heapIndex].size;
            break;
        }
    }
    
    // Find compute queue
    uint32_t queue_family_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(ctx->physical_device, &queue_family_count, NULL);
    
    VkQueueFamilyProperties* queue_families = (VkQueueFamilyProperties*)malloc(
        queue_family_count * sizeof(VkQueueFamilyProperties));
    vkGetPhysicalDeviceQueueFamilyProperties(ctx->physical_device, &queue_family_count, queue_families);
    
    ctx->compute_queue_family = UINT32_MAX;
    for (uint32_t i = 0; i < queue_family_count; i++) {
        if (queue_families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            ctx->compute_queue_family = i;
            break;
        }
    }
    
    free(queue_families);
    
    if (ctx->compute_queue_family == UINT32_MAX) {
        printf("[Vulkan] No compute queue found\n");
        vkDestroyInstance(ctx->instance, NULL);
        free(ctx);
        free(backend);
        return NULL;
    }
    
    // Create logical device
    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {0};
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueFamilyIndex = ctx->compute_queue_family;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &queue_priority;
    
    VkPhysicalDeviceFeatures features = {0};
    
    VkDeviceCreateInfo device_info = {0};
    device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;
    device_info.pEnabledFeatures = &features;
    
    result = vkCreateDevice(ctx->physical_device, &device_info, NULL, &ctx->device);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to create device: %d\n", result);
        vkDestroyInstance(ctx->instance, NULL);
        free(ctx);
        free(backend);
        return NULL;
    }
    
    // Get compute queue
    vkGetDeviceQueue(ctx->device, ctx->compute_queue_family, 0, &ctx->compute_queue);
    
    // Create command pool
    VkCommandPoolCreateInfo pool_info = {0};
    pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.queueFamilyIndex = ctx->compute_queue_family;
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    
    result = vkCreateCommandPool(ctx->device, &pool_info, NULL, &ctx->command_pool);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to create command pool: %d\n", result);
        vkDestroyDevice(ctx->device, NULL);
        vkDestroyInstance(ctx->instance, NULL);
        free(ctx);
        free(backend);
        return NULL;
    }
    
    // Allocate command buffer
    VkCommandBufferAllocateInfo alloc_info = {0};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = ctx->command_pool;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;
    
    result = vkAllocateCommandBuffers(ctx->device, &alloc_info, &ctx->command_buffer);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to allocate command buffer: %d\n", result);
        vkDestroyCommandPool(ctx->device, ctx->command_pool, NULL);
        vkDestroyDevice(ctx->device, NULL);
        vkDestroyInstance(ctx->instance, NULL);
        free(ctx);
        free(backend);
        return NULL;
    }
    
    // Create fence
    VkFenceCreateInfo fence_info = {0};
    fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    
    result = vkCreateFence(ctx->device, &fence_info, NULL, &ctx->fence);
    if (result != VK_SUCCESS) {
        printf("[Vulkan] Failed to create fence: %d\n", result);
        vkFreeCommandBuffers(ctx->device, ctx->command_pool, 1, &ctx->command_buffer);
        vkDestroyCommandPool(ctx->device, ctx->command_pool, NULL);
        vkDestroyDevice(ctx->device, NULL);
        vkDestroyInstance(ctx->instance, NULL);
        free(ctx);
        free(backend);
        return NULL;
    }
    
    // Set function pointers
    backend->allocate = Vulkan_Allocate;
    backend->free = Vulkan_Free;
    backend->upload = Vulkan_Upload;
    backend->download = Vulkan_Download;
    backend->synchronize = Vulkan_Synchronize;
    backend->destroy = Vulkan_BackendDestroy;
    
    printf("[Vulkan] Backend created successfully\n");
    printf("  Device: %s\n", backend->device_info.name);
    printf("  VRAM: %llu MB\n", backend->device_info.vram_size / (1024 * 1024));
    
    return backend;
}

void Vulkan_BackendDestroy(GPUBackend* backend) {
    if (!backend) return;
    
    VulkanContext* ctx = (VulkanContext*)backend->device;
    if (!ctx) {
        free(backend);
        return;
    }
    
    // Cleanup shader modules
    if (ctx->rmsnorm_shader) vkDestroyShaderModule(ctx->device, ctx->rmsnorm_shader, NULL);
    if (ctx->rope_shader) vkDestroyShaderModule(ctx->device, ctx->rope_shader, NULL);
    if (ctx->attention_shader) vkDestroyShaderModule(ctx->device, ctx->attention_shader, NULL);
    if (ctx->matmul_shader) vkDestroyShaderModule(ctx->device, ctx->matmul_shader, NULL);
    if (ctx->softmax_shader) vkDestroyShaderModule(ctx->device, ctx->softmax_shader, NULL);
    if (ctx->swiglu_shader) vkDestroyShaderModule(ctx->device, ctx->swiglu_shader, NULL);
    if (ctx->add_shader) vkDestroyShaderModule(ctx->device, ctx->add_shader, NULL);
    
    // Cleanup
    if (ctx->fence) vkDestroyFence(ctx->device, ctx->fence, NULL);
    if (ctx->command_buffer) vkFreeCommandBuffers(ctx->device, ctx->command_pool, 1, &ctx->command_buffer);
    if (ctx->command_pool) vkDestroyCommandPool(ctx->device, ctx->command_pool, NULL);
    if (ctx->device) vkDestroyDevice(ctx->device, NULL);
    if (ctx->instance) vkDestroyInstance(ctx->instance, NULL);
    
    free(ctx);
    free(backend);
    
    printf("[Vulkan] Backend destroyed\n");
}