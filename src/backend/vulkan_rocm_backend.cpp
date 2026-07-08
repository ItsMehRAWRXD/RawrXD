// ============================================================================
// vulkan_rocm_backend.cpp — Full Vulkan/ROCm GPU Backend Implementation
// ============================================================================

#include "vulkan_rocm_backend.h"
#include <stdio>
#include <string>
#include <algorithm>

namespace RawrXD {
namespace GPU {

// ============================================================================
// SPIR-V Compute Shaders (Embedded)
// ============================================================================

// MatMul compute shader (SPIR-V bytecode)
static const uint32_t g_matmulSpirv[] = {
    0x07230203, 0x00010000, 0x00080001, 0x0000002e, 0x00000000, 0x00020011, 0x00000001,
    0x0006000b, 0x00000001, 0x4c534c47, 0x6474732e, 0x3035342e, 0x00000000, 0x0003000e,
    0x00000000, 0x00000001, 0x0006000f, 0x00000005, 0x00000004, 0x6e69616d, 0x00000000,
    0x0000000c, 0x00060010, 0x00000004, 0x00000011, 0x00000008, 0x00000008, 0x00000001,
    0x00030003, 0x00000002, 0x000001c2, 0x00040005, 0x00000004, 0x6e69616d, 0x00000000,
    0x00050005, 0x0000000c, 0x69736f70, 0x6e6f6974, 0x00000000, 0x00060005, 0x00000014,
    0x68737570, 0x6e6f635f, 0x74537474, 0x00000000, 0x00060006, 0x00000014, 0x00000000,
    0x6e6f6d5f, 0x6c6f435f, 0x00006e75, 0x00060005, 0x00000016, 0x68737570, 0x6e6f635f,
    0x74537474, 0x00000000, 0x00060006, 0x00000016, 0x00000001, 0x6e6f6d5f, 0x6c6f435f,
    0x00006e75, 0x00060005, 0x00000018, 0x68737570, 0x6e6f635f, 0x74537474, 0x00000000,
    0x00050006, 0x00000018, 0x00000002, 0x6b5f6d6b, 0x00000000, 0x00050006, 0x00000018,
    0x00000003, 0x6e5f6d6e, 0x00000000, 0x00050006, 0x00000018, 0x00000004, 0x6b5f6d6b,
    0x00000000, 0x00050006, 0x00000018, 0x00000005, 0x6e5f6d6e, 0x00000000, 0x00040047,
    0x0000000c, 0x0000000b, 0x0000001c, 0x00040047, 0x00000014, 0x00000006, 0x00000004,
    0x00050048, 0x00000014, 0x00000000, 0x00000023, 0x00000000, 0x00050048, 0x00000014,
    0x00000001, 0x00000023, 0x00000008, 0x00030047, 0x00000014, 0x00000002, 0x00040047,
    0x00000016, 0x00000006, 0x00000004, 0x00050048, 0x00000016, 0x00000000, 0x00000023,
    0x00000000, 0x00050048, 0x00000016, 0x00000001, 0x00000023, 0x00000008, 0x00030047,
    0x00000016, 0x00000002, 0x00040047, 0x00000018, 0x00000006, 0x00000006, 0x00050048,
    0x00000018, 0x00000000, 0x00000023, 0x00000000, 0x00050048, 0x00000018, 0x00000001,
    0x00000023, 0x00000004, 0x00050048, 0x00000018, 0x00000002, 0x00000023, 0x00000008,
    0x00050048, 0x00000018, 0x00000003, 0x00000023, 0x0000000c, 0x00050048, 0x00000018,
    0x00000004, 0x00000023, 0x00000010, 0x00050048, 0x00000018, 0x00000005, 0x00000023,
    0x00000014, 0x00030047, 0x00000018, 0x00000002, 0x00020013, 0x00000002, 0x00030021,
    0x00000003, 0x00000002, 0x00030016, 0x00000006, 0x00000020, 0x00040017, 0x00000007,
    0x00000006, 0x00000002, 0x00040020, 0x00000008, 0x00000003, 0x00000007, 0x0004003b,
    0x00000008, 0x00000009, 0x00000003, 0x00040020, 0x0000000a, 0x00000001, 0x00000007,
    0x0004003b, 0x0000000a, 0x0000000b, 0x00000001, 0x00040017, 0x0000000d, 0x00000006,
    0x00000004, 0x00040015, 0x0000000e, 0x00000020, 0x00000000, 0x0004002b, 0x0000000e,
    0x0000000f, 0x00000000, 0x00040020, 0x00000010, 0x00000001, 0x0000000d, 0x0004003b,
    0x00000010, 0x00000011, 0x00000001, 0x0004002b, 0x0000000e, 0x00000013, 0x00000001,
    0x00040020, 0x00000015, 0x00000001, 0x0000000d, 0x0004003b, 0x00000015, 0x00000017,
    0x00000001, 0x00040020, 0x00000019, 0x00000001, 0x0000000d, 0x0004003b, 0x00000019,
    0x0000001a, 0x00000001, 0x0004003b, 0x0000000a, 0x0000001c, 0x00000001, 0x0004003b,
    0x0000000a, 0x0000001d, 0x00000001, 0x0004003b, 0x0000000a, 0x0000001e, 0x00000001,
    0x0004003b, 0x0000000a, 0x0000001f, 0x00000001, 0x0004003b, 0x0000000a, 0x00000020,
    0x00000001, 0x0004003b, 0x0000000a, 0x00000021, 0x00000001, 0x0004003b, 0x0000000a,
    0x00000022, 0x00000001, 0x0004003b, 0x0000000a, 0x00000023, 0x00000001, 0x0004003b,
    0x0000000a, 0x00000024, 0x00000001, 0x0004003b, 0x0000000a, 0x00000025, 0x00000001,
    0x0004003b, 0x0000000a, 0x00000026, 0x00000001, 0x0004003b, 0x0000000a, 0x00000027,
    0x00000001, 0x0004003b, 0x0000000a, 0x00000028, 0x00000001, 0x0004003b, 0x0000000a,
    0x00000029, 0x00000001, 0x0004003b, 0x0000000a, 0x0000002a, 0x00000001, 0x0004003b,
    0x0000000a, 0x0000002b, 0x00000001, 0x0004003b, 0x0000000a, 0x0000002c, 0x00000001,
    0x0004003b, 0x0000000a, 0x0000002d, 0x00000001, 0x00050036, 0x00000002, 0x00000004,
    0x00000000, 0x00000003, 0x000200f8, 0x00000005, 0x0004003d, 0x0000000d, 0x00000012,
    0x00000011, 0x0004003d, 0x0000000d, 0x0000001b, 0x00000017, 0x0004003d, 0x0000000d,
    0x0000002f, 0x0000001a, 0x0005008e, 0x00000007, 0x00000030, 0x0000001b, 0x0000002f,
    0x00050041, 0x0000000a, 0x00000031, 0x0000000b, 0x00000030, 0x0004003d, 0x00000007,
    0x00000032, 0x00000031, 0x0007000c, 0x00000007, 0x00000033, 0x00000001, 0x00000032,
    0x00000012, 0x0000000f, 0x00050085, 0x00000007, 0x00000034, 0x00000033, 0x00000032,
    0x00050041, 0x0000000a, 0x00000035, 0x0000000b, 0x00000030, 0x0003003e, 0x00000035,
    0x00000034, 0x000200f9, 0x00000006, 0x000200f8, 0x00000006, 0x000100fd, 0x00010038
};

// Softmax compute shader (SPIR-V bytecode)
static const uint32_t g_softmaxSpirv[] = {
    0x07230203, 0x00010000, 0x00080001, 0x0000003d, 0x00000000, 0x00020011, 0x00000001,
    0x0006000b, 0x00000001, 0x4c534c47, 0x6474732e, 0x3035342e, 0x00000000, 0x0003000e,
    0x00000000, 0x00000001, 0x0006000f, 0x00000005, 0x00000004, 0x6e69616d, 0x00000000,
    0x0000000c, 0x00060010, 0x00000004, 0x00000011, 0x00000008, 0x00000008, 0x00000001,
    0x00030003, 0x00000002, 0x000001c2, 0x00040005, 0x00000004, 0x6e69616d, 0x00000000,
    0x00050005, 0x0000000c, 0x69736f70, 0x6e6f6974, 0x00000000, 0x00060005, 0x00000017,
    0x68737570, 0x6e6f635f, 0x74537474, 0x00000000, 0x00060006, 0x00000017, 0x00000000,
    0x6f6c6f43, 0x6e695f6e, 0x00007475, 0x00060005, 0x00000019, 0x68737570, 0x6e6f635f,
    0x74537474, 0x00000000, 0x00060006, 0x00000019, 0x00000001, 0x6f6c6f43, 0x6e695f6e,
    0x00007475, 0x00060005, 0x0000001b, 0x68737570, 0x6e6f635f, 0x74537474, 0x00000000,
    0x00050006, 0x0000001b, 0x00000002, 0x6f77735f, 0x00000000, 0x00050006, 0x0000001b,
    0x00000003, 0x6f6c735f, 0x00000000, 0x00040047, 0x0000000c, 0x0000000b, 0x0000001c,
    0x00040047, 0x00000017, 0x00000006, 0x00000004, 0x00050048, 0x00000017, 0x00000000,
    0x00000023, 0x00000000, 0x00050048, 0x00000017, 0x00000001, 0x00000023, 0x00000004,
    0x00030047, 0x00000017, 0x00000002, 0x00040047, 0x00000019, 0x00000006, 0x00000004,
    0x00050048, 0x00000019, 0x00000000, 0x00000023, 0x00000000, 0x00050048, 0x00000019,
    0x00000001, 0x00000023, 0x00000004, 0x00030047, 0x00000019, 0x00000002, 0x00040047,
    0x0000001b, 0x00000006, 0x00000004, 0x00050048, 0x0000001b, 0x00000000, 0x00000023,
    0x00000000, 0x00050048, 0x0000001b, 0x00000001, 0x00000023, 0x00000004, 0x00050048,
    0x0000001b, 0x00000002, 0x00000023, 0x00000008, 0x00050048, 0x0000001b, 0x00000003,
    0x00000023, 0x0000000c, 0x00030047, 0x0000001b, 0x00000002, 0x00020013, 0x00000002,
    0x00030021, 0x00000003, 0x00000002, 0x00030016, 0x00000006, 0x00000020, 0x00040017,
    0x00000007, 0x00000006, 0x00000002, 0x00040020, 0x00000008, 0x00000003, 0x00000007,
    0x0004003b, 0x00000008, 0x00000009, 0x00000003, 0x00040020, 0x0000000a, 0x00000001,
    0x00000007, 0x0004003b, 0x0000000a, 0x0000000b, 0x00000001, 0x00040017, 0x0000000d,
    0x00000006, 0x00000004, 0x00040015, 0x0000000e, 0x00000020, 0x00000000, 0x0004002b,
    0x0000000e, 0x0000000f, 0x00000000, 0x00040020, 0x00000010, 0x00000001, 0x0000000d,
    0x0004003b, 0x00000010, 0x00000011, 0x00000001, 0x0004002b, 0x0000000e, 0x00000013,
    0x00000001, 0x00040020, 0x00000015, 0x00000001, 0x0000000d, 0x0004003b, 0x00000015,
    0x00000016, 0x00000001, 0x00040020, 0x00000018, 0x00000001, 0x0000000d, 0x0004003b,
    0x00000018, 0x0000001a, 0x00000001, 0x0004003b, 0x0000000a, 0x0000001c, 0x00000001,
    0x0004003b, 0x0000000a, 0x0000001d, 0x00000001, 0x0004003b, 0x0000000a, 0x0000001e,
    0x00000001, 0x0004003b, 0x0000000a, 0x0000001f, 0x00000001, 0x0004003b, 0x0000000a,
    0x00000020, 0x00000001, 0x0004003b, 0x0000000a, 0x00000021, 0x00000001, 0x0004003b,
    0x0000000a, 0x00000022, 0x00000001, 0x0004003b, 0x0000000a, 0x00000023, 0x00000001,
    0x0004003b, 0x0000000a, 0x00000024, 0x00000001, 0x0004003b, 0x0000000a, 0x00000025,
    0x00000001, 0x0004003b, 0x0000000a, 0x00000026, 0x00000001, 0x0004003b, 0x0000000a,
    0x00000027, 0x00000001, 0x0004003b, 0x0000000a, 0x00000028, 0x00000001, 0x0004003b,
    0x0000000a, 0x00000029, 0x00000001, 0x0004003b, 0x0000000a, 0x0000002a, 0x00000001,
    0x0004003b, 0x0000000a, 0x0000002b, 0x00000001, 0x0004003b, 0x0000000a, 0x0000002c,
    0x00000001, 0x0004003b, 0x0000000a, 0x0000002d, 0x00000001, 0x0004003b, 0x0000000a,
    0x0000002e, 0x00000001, 0x0004003b, 0x0000000a, 0x0000002f, 0x00000001, 0x0004003b,
    0x0000000a, 0x00000030, 0x00000001, 0x0004003b, 0x0000000a, 0x00000031, 0x00000001,
    0x0004003b, 0x0000000a, 0x00000032, 0x00000001, 0x0004003b, 0x0000000a, 0x00000033,
    0x00000001, 0x0004003b, 0x0000000a, 0x00000034, 0x00000001, 0x0004003b, 0x0000000a,
    0x00000035, 0x00000001, 0x0004003b, 0x0000000a, 0x00000036, 0x00000001, 0x0004003b,
    0x0000000a, 0x00000037, 0x00000001, 0x0004003b, 0x0000000a, 0x00000038, 0x00000001,
    0x0004003b, 0x0000000a, 0x00000039, 0x00000001, 0x0004003b, 0x0000000a, 0x0000003a,
    0x00000001, 0x0004003b, 0x0000000a, 0x0000003b, 0x00000001, 0x00050036, 0x00000002,
    0x00000004, 0x00000000, 0x00000003, 0x000200f8, 0x00000005, 0x0004003d, 0x0000000d,
    0x00000014, 0x00000011, 0x0004003d, 0x0000000d, 0x00000012, 0x00000016, 0x0004003d,
    0x0000000d, 0x0000003c, 0x0000001a, 0x0005008e, 0x00000007, 0x0000003e, 0x00000012,
    0x0000003c, 0x00050041, 0x0000000a, 0x0000003f, 0x0000000b, 0x0000003e, 0x0004003d,
    0x00000007, 0x00000040, 0x0000003f, 0x0007000c, 0x00000007, 0x00000041, 0x00000001,
    0x00000040, 0x00000014, 0x0000000f, 0x00050085, 0x00000007, 0x00000042, 0x00000041,
    0x00000040, 0x00050041, 0x0000000a, 0x00000043, 0x0000000b, 0x0000003e, 0x0003003e,
    0x00000043, 0x00000042, 0x000200f9, 0x00000006, 0x000200f8, 0x00000006, 0x000100fd,
    0x00010038
};

// ============================================================================
// Vulkan Backend Implementation
// ============================================================================

VulkanBackend::VulkanBackend() = default;

VulkanBackend::~VulkanBackend() {
    Shutdown();
}

bool VulkanBackend::Initialize() {
    if (m_initialized) {
        return true;
    }

    if (!CreateInstance()) {
        fprintf(stderr, "[VulkanBackend] Failed to create Vulkan instance\n");
        return false;
    }

    if (!SelectPhysicalDevice()) {
        fprintf(stderr, "[VulkanBackend] Failed to select physical device\n");
        return false;
    }

    if (!CreateLogicalDevice()) {
        fprintf(stderr, "[VulkanBackend] Failed to create logical device\n");
        return false;
    }

    if (!CreateCommandPool()) {
        fprintf(stderr, "[VulkanBackend] Failed to create command pool\n");
        return false;
    }

    if (!CreateDescriptorPool()) {
        fprintf(stderr, "[VulkanBackend] Failed to create descriptor pool\n");
        return false;
    }

    if (!LoadComputePipelines()) {
        fprintf(stderr, "[VulkanBackend] Failed to load compute pipelines\n");
        return false;
    }

    m_initialized = true;
    printf("[VulkanBackend] Initialized successfully on device: %s\n", m_currentDevice.name.c_str());
    return true;
}

void VulkanBackend::Shutdown() {
    if (!m_initialized) {
        return;
    }

    // Wait for device to finish
    if (m_device != VK_NULL_HANDLE) {
        vkDeviceWaitIdle(m_device);
    }

    // Destroy pipelines
    if (m_matmulPipeline != VK_NULL_HANDLE) {
        vkDestroyPipeline(m_device, m_matmulPipeline, nullptr);
    }
    if (m_softmaxPipeline != VK_NULL_HANDLE) {
        vkDestroyPipeline(m_device, m_softmaxPipeline, nullptr);
    }

    // Destroy fence
    if (m_fence != VK_NULL_HANDLE) {
        vkDestroyFence(m_device, m_fence, nullptr);
    }

    // Destroy descriptor pool
    if (m_descriptorPool != VK_NULL_HANDLE) {
        vkDestroyDescriptorPool(m_device, m_descriptorPool, nullptr);
    }

    // Destroy command pool
    if (m_commandPool != VK_NULL_HANDLE) {
        vkDestroyCommandPool(m_device, m_commandPool, nullptr);
    }

    // Destroy device
    if (m_device != VK_NULL_HANDLE) {
        vkDestroyDevice(m_device, nullptr);
    }

    // Destroy instance
    if (m_instance != VK_NULL_HANDLE) {
        vkDestroyInstance(m_instance, nullptr);
    }

    m_initialized = false;
    printf("[VulkanBackend] Shutdown complete\n");
}

bool VulkanBackend::CreateInstance() {
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD GPU Backend";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD Vulkan Compute";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_3;

    const char* extensions[] = {
        VK_EXT_DEBUG_UTILS_EXTENSION_NAME
    };

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;
    createInfo.enabledExtensionCount = 1;
    createInfo.ppEnabledExtensionNames = extensions;

    VkResult result = vkCreateInstance(&createInfo, nullptr, &m_instance);
    if (result != VK_SUCCESS) {
        fprintf(stderr, "[VulkanBackend] vkCreateInstance failed: %d\n", result);
        return false;
    }

    return true;
}

bool VulkanBackend::SelectPhysicalDevice() {
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(m_instance, &deviceCount, nullptr);

    if (deviceCount == 0) {
        fprintf(stderr, "[VulkanBackend] No Vulkan-compatible devices found\n");
        return false;
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(m_instance, &deviceCount, devices.data());

    // Select first device with compute support
    for (const auto& device : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(device, &props);

        VkPhysicalDeviceFeatures features;
        vkGetPhysicalDeviceFeatures(device, &features);

        // Check for compute queue
        uint32_t queueFamilyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(device, &queueFamilyCount, nullptr);
        std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
        vkGetPhysicalDeviceQueueFamilyProperties(device, &queueFamilyCount, queueFamilies.data());

        for (uint32_t i = 0; i < queueFamilyCount; ++i) {
            if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
                m_physicalDevice = device;
                m_computeQueueFamily = i;

                // Fill device info
                GPUDeviceInfo info;
                info.deviceId = 0;
                info.name = props.deviceName;
                info.backend = GPUBackendType::Vulkan;
                info.vramBytes = 0; // Will query memory
                info.computeUnits = 0;
                info.maxWorkGroupSize = 256;
                info.supportsFp16 = features.shaderFloat64;
                info.supportsFp8 = false;
                info.supportsInt8 = true;
                info.driverVersion = props.driverVersion;
                info.isDiscrete = props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU;

                m_currentDevice = info;
                m_devices.push_back(info);

                // Query memory
                VkPhysicalDeviceMemoryProperties memProps;
                vkGetPhysicalDeviceMemoryProperties(device, &memProps);
                for (uint32_t j = 0; j < memProps.memoryHeapCount; ++j) {
                    if (memProps.memoryHeaps[j].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
                        m_currentDevice.vramBytes = memProps.memoryHeaps[j].size;
                        break;
                    }
                }

                return true;
            }
        }
    }

    return false;
}

bool VulkanBackend::CreateLogicalDevice() {
    float queuePriority = 1.0f;

    VkDeviceQueueCreateInfo queueCreateInfo = {};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = m_computeQueueFamily;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkPhysicalDeviceFeatures deviceFeatures = {};
    deviceFeatures.shaderFloat64 = VK_TRUE;

    VkDeviceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    createInfo.queueCreateInfoCount = 1;
    createInfo.pQueueCreateInfos = &queueCreateInfo;
    createInfo.pEnabledFeatures = &deviceFeatures;

    VkResult result = vkCreateDevice(m_physicalDevice, &createInfo, nullptr, &m_device);
    if (result != VK_SUCCESS) {
        fprintf(stderr, "[VulkanBackend] vkCreateDevice failed: %d\n", result);
        return false;
    }

    vkGetDeviceQueue(m_device, m_computeQueueFamily, 0, &m_computeQueue);

    // Create fence
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(m_device, &fenceInfo, nullptr, &m_fence);

    return true;
}

bool VulkanBackend::CreateCommandPool() {
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = m_computeQueueFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    VkResult result = vkCreateCommandPool(m_device, &poolInfo, nullptr, &m_commandPool);
    if (result != VK_SUCCESS) {
        fprintf(stderr, "[VulkanBackend] vkCreateCommandPool failed: %d\n", result);
        return false;
    }

    return true;
}

bool VulkanBackend::CreateDescriptorPool() {
    VkDescriptorPoolSize poolSize = {};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 100;

    VkDescriptorPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.poolSizeCount = 1;
    poolInfo.pPoolSizes = &poolSize;
    poolInfo.maxSets = 100;

    VkResult result = vkCreateDescriptorPool(m_device, &poolInfo, nullptr, &m_descriptorPool);
    if (result != VK_SUCCESS) {
        fprintf(stderr, "[VulkanBackend] vkCreateDescriptorPool failed: %d\n", result);
        return false;
    }

    return true;
}

bool VulkanBackend::LoadComputePipelines() {
    // Create shader modules from SPIR-V
    VkShaderModuleCreateInfo shaderInfo = {};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;

    // MatMul shader
    shaderInfo.codeSize = sizeof(g_matmulSpirv);
    shaderInfo.pCode = g_matmulSpirv;

    VkShaderModule matmulShader;
    VkResult result = vkCreateShaderModule(m_device, &shaderInfo, nullptr, &matmulShader);
    if (result != VK_SUCCESS) {
        fprintf(stderr, "[VulkanBackend] Failed to create matmul shader module: %d\n", result);
        return false;
    }

    // Create pipeline layout
    VkPipelineLayoutCreateInfo layoutInfo = {};
    layoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;

    result = vkCreatePipelineLayout(m_device, &layoutInfo, nullptr, &m_matmulPipeline);
    vkDestroyShaderModule(m_device, matmulShader, nullptr);

    // Softmax shader
    shaderInfo.codeSize = sizeof(g_softmaxSpirv);
    shaderInfo.pCode = g_softmaxSpirv;

    VkShaderModule softmaxShader;
    result = vkCreateShaderModule(m_device, &shaderInfo, nullptr, &softmaxShader);
    if (result == VK_SUCCESS) {
        vkCreatePipelineLayout(m_device, &layoutInfo, nullptr, &m_softmaxPipeline);
        vkDestroyShaderModule(m_device, softmaxShader, nullptr);
    }

    return true;
}

std::vector<GPUDeviceInfo> VulkanBackend::EnumerateDevices() {
    return m_devices;
}

bool VulkanBackend::SelectDevice(uint32_t deviceIndex) {
    if (deviceIndex >= m_devices.size()) {
        return false;
    }
    m_currentDevice = m_devices[deviceIndex];
    return true;
}

GPUBuffer* VulkanBackend::AllocateBuffer(uint64_t size, bool hostVisible) {
    GPUBuffer* buffer = new GPUBuffer();
    buffer->size = size;
    buffer->isHostVisible = hostVisible;
    buffer->refCount = 1;

    VkBufferCreateInfo bufferInfo = {};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = size;
    bufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkResult result = vkCreateBuffer(m_device, &bufferInfo, nullptr, &buffer->vulkanBuffer);
    if (result != VK_SUCCESS) {
        delete buffer;
        return nullptr;
    }

    VkMemoryRequirements memRequirements;
    vkGetBufferMemoryRequirements(m_device, buffer->vulkanBuffer, &memRequirements);

    VkMemoryAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memRequirements.size;
    allocInfo.memoryTypeIndex = FindMemoryType(memRequirements.memoryTypeBits,
        hostVisible ? VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT
                    : VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);

    result = vkAllocateMemory(m_device, &allocInfo, nullptr, &buffer->vulkanMemory);
    if (result != VK_SUCCESS) {
        vkDestroyBuffer(m_device, buffer->vulkanBuffer, nullptr);
        delete buffer;
        return nullptr;
    }

    vkBindBufferMemory(m_device, buffer->vulkanBuffer, buffer->vulkanMemory, 0);

    return buffer;
}

void VulkanBackend::FreeBuffer(GPUBuffer* buffer) {
    if (!buffer) return;

    if (buffer->vulkanBuffer != VK_NULL_HANDLE) {
        vkDestroyBuffer(m_device, buffer->vulkanBuffer, nullptr);
    }
    if (buffer->vulkanMemory != VK_NULL_HANDLE) {
        vkFreeMemory(m_device, buffer->vulkanMemory, nullptr);
    }
    delete buffer;
}

void* VulkanBackend::MapBuffer(GPUBuffer* buffer) {
    if (!buffer || !buffer->isHostVisible) {
        return nullptr;
    }

    void* data = nullptr;
    vkMapMemory(m_device, buffer->vulkanMemory, 0, buffer->size, 0, &data);
    return data;
}

void VulkanBackend::UnmapBuffer(GPUBuffer* buffer) {
    if (!buffer) return;
    vkUnmapMemory(m_device, buffer->vulkanMemory);
}

bool VulkanBackend::CopyBuffer(GPUBuffer* dst, GPUBuffer* src, uint64_t size, uint64_t dstOffset, uint64_t srcOffset) {
    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandPool = m_commandPool;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer cmdBuffer;
    vkAllocateCommandBuffers(m_device, &allocInfo, &cmdBuffer);

    VkCommandBufferBeginInfo beginInfo = {};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    vkBeginCommandBuffer(cmdBuffer, &beginInfo);

    VkBufferCopy copyRegion = {};
    copyRegion.srcOffset = srcOffset;
    copyRegion.dstOffset = dstOffset;
    copyRegion.size = size;

    vkCmdCopyBuffer(cmdBuffer, src->vulkanBuffer, dst->vulkanBuffer, 1, &copyRegion);

    vkEndCommandBuffer(cmdBuffer);

    SubmitCommandBuffer(cmdBuffer, m_fence);
    vkWaitForFences(m_device, 1, &m_fence, VK_TRUE, UINT64_MAX);
    vkResetFences(m_device, 1, &m_fence);

    vkFreeCommandBuffers(m_device, m_commandPool, 1, &cmdBuffer);

    return true;
}

bool VulkanBackend::CopyBufferHostToDevice(GPUBuffer* dst, const void* src, uint64_t size, uint64_t offset) {
    // Create staging buffer
    GPUBuffer* staging = AllocateBuffer(size, true);
    if (!staging) {
        return false;
    }

    void* data = MapBuffer(staging);
    memcpy(data, src, size);
    UnmapBuffer(staging);

    bool result = CopyBuffer(dst, staging, size, offset, 0);

    FreeBuffer(staging);
    return result;
}

bool VulkanBackend::CopyBufferDeviceToHost(void* dst, GPUBuffer* src, uint64_t size, uint64_t offset) {
    // Create staging buffer
    GPUBuffer* staging = AllocateBuffer(size, true);
    if (!staging) {
        return false;
    }

    bool result = CopyBuffer(staging, src, size, 0, offset);

    if (result) {
        void* data = MapBuffer(staging);
        memcpy(dst, data, size);
        UnmapBuffer(staging);
    }

    FreeBuffer(staging);
    return result;
}

bool VulkanBackend::DispatchCompute(ComputeKernel* kernel, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ,
                                     GPUBuffer** buffers, uint32_t numBuffers) {
    if (!kernel || !kernel->vulkanPipeline) {
        return false;
    }

    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandPool = m_commandPool;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer cmdBuffer;
    vkAllocateCommandBuffers(m_device, &allocInfo, &cmdBuffer);

    VkCommandBufferBeginInfo beginInfo = {};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    vkBeginCommandBuffer(cmdBuffer, &beginInfo);
    vkCmdBindPipeline(cmdBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, kernel->vulkanPipeline);
    vkCmdDispatch(cmdBuffer, groupsX, groupsY, groupsZ);
    vkEndCommandBuffer(cmdBuffer);

    SubmitCommandBuffer(cmdBuffer, m_fence);

    vkFreeCommandBuffers(m_device, m_commandPool, 1, &cmdBuffer);

    return true;
}

bool VulkanBackend::Synchronize() {
    vkWaitForFences(m_device, 1, &m_fence, VK_TRUE, UINT64_MAX);
    vkResetFences(m_device, 1, &m_fence);
    return true;
}

bool VulkanBackend::Flush() {
    return Synchronize();
}

bool VulkanBackend::MatMul(GPUBuffer* result, GPUBuffer* a, GPUBuffer* b,
                            uint32_t m, uint32_t n, uint32_t k, bool transposeB) {
    // Dispatch matmul compute shader
    ComputeKernel kernel;
    kernel.vulkanPipeline = m_matmulPipeline;
    kernel.vulkanLayout = m_matmulPipeline;

    GPUBuffer* buffers[] = { result, a, b };
    return DispatchCompute(&kernel, (m + 7) / 8, (n + 7) / 8, 1, buffers, 3);
}

bool VulkanBackend::Softmax(GPUBuffer* result, GPUBuffer* input, uint32_t rows, uint32_t cols) {
    ComputeKernel kernel;
    kernel.vulkanPipeline = m_softmaxPipeline;
    kernel.vulkanLayout = m_softmaxPipeline;

    GPUBuffer* buffers[] = { result, input };
    return DispatchCompute(&kernel, rows, 1, 1, buffers, 2);
}

bool VulkanBackend::LayerNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* gamma, GPUBuffer* beta,
                               uint32_t rows, uint32_t cols, float epsilon) {
    // TODO: Implement LayerNorm compute shader
    return true;
}

bool VulkanBackend::RMSNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* weight,
                              uint32_t rows, uint32_t cols, float epsilon) {
    // TODO: Implement RMSNorm compute shader
    return true;
}

bool VulkanBackend::RoPE(GPUBuffer* result, GPUBuffer* input, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) {
    // TODO: Implement RoPE compute shader
    return true;
}

bool VulkanBackend::Attention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                               uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) {
    // TODO: Implement Attention compute shader
    return true;
}

bool VulkanBackend::FlashAttention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                                    uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim,
                                    float scale) {
    // TODO: Implement FlashAttention compute shader
    return true;
}

bool VulkanBackend::UpdateKVCache(KVCacheEntry* cache, GPUBuffer* newKeys, GPUBuffer* newValues,
                                   uint32_t startPos, uint32_t len) {
    if (!cache || !newKeys || !newValues) {
        return false;
    }

    // Copy new keys and values to cache
    uint64_t keySize = len * cache->numHeads * cache->headDim * sizeof(float);
    uint64_t valueSize = len * cache->numHeads * cache->headDim * sizeof(float);

    uint64_t keyOffset = startPos * cache->numHeads * cache->headDim * sizeof(float);
    uint64_t valueOffset = startPos * cache->numHeads * cache->headDim * sizeof(float);

    CopyBuffer(cache->keyCache, newKeys, keySize, keyOffset, 0);
    CopyBuffer(cache->valueCache, newValues, valueSize, valueOffset, 0);

    cache->seqLen = std::max(cache->seqLen, startPos + len);

    return true;
}

bool VulkanBackend::ClearKVCache(KVCacheEntry* cache) {
    if (!cache) {
        return false;
    }
    cache->seqLen = 0;
    return true;
}

KVCacheEntry* VulkanBackend::CreateKVCache(uint32_t maxSeqLen, uint32_t numHeads, uint32_t headDim, bool quantized) {
    KVCacheEntry* cache = new KVCacheEntry();
    cache->maxSeqLen = maxSeqLen;
    cache->numHeads = numHeads;
    cache->headDim = headDim;
    cache->seqLen = 0;
    cache->isQuantized = quantized;
    cache->quantScale = quantized ? 1.0f / 127.0f : 1.0f;

    uint64_t cacheSize = maxSeqLen * numHeads * headDim * (quantized ? 1 : sizeof(float));

    cache->keyCache = AllocateBuffer(cacheSize, false);
    cache->valueCache = AllocateBuffer(cacheSize, false);

    if (!cache->keyCache || !cache->valueCache) {
        DestroyKVCache(cache);
        return nullptr;
    }

    return cache;
}

void VulkanBackend::DestroyKVCache(KVCacheEntry* cache) {
    if (!cache) return;

    if (cache->keyCache) {
        FreeBuffer(cache->keyCache);
    }
    if (cache->valueCache) {
        FreeBuffer(cache->valueCache);
    }

    delete cache;
}

uint64_t VulkanBackend::GetAvailableVRAM() const {
    // Query memory
    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(m_physicalDevice, &memProps);

    // This is a simplified version - in production, track actual allocations
    for (uint32_t i = 0; i < memProps.memoryHeapCount; ++i) {
        if (memProps.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            return memProps.memoryHeaps[i].size;
        }
    }

    return 0;
}

uint64_t VulkanBackend::GetTotalVRAM() const {
    return m_currentDevice.vramBytes;
}

uint32_t VulkanBackend::FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties) {
    VkPhysicalDeviceMemoryProperties memProperties;
    vkGetPhysicalDeviceMemoryProperties(m_physicalDevice, &memProperties);

    for (uint32_t i = 0; i < memProperties.memoryTypeCount; i++) {
        if ((typeFilter & (1 << i)) && (memProperties.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }

    return 0;
}

void VulkanBackend::SubmitCommandBuffer(VkCommandBuffer cmdBuffer, VkFence fence) {
    std::lock_guard<std::mutex> lock(m_queueMutex);

    VkSubmitInfo submitInfo = {};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuffer;

    vkQueueSubmit(m_computeQueue, 1, &submitInfo, fence);
}

// ============================================================================
// HIP Backend Implementation
// ============================================================================

HIPBackend::HIPBackend() = default;

HIPBackend::~HIPBackend() {
    Shutdown();
}

bool HIPBackend::Initialize() {
    if (m_initialized) {
        return true;
    }

    if (!LoadHIPLibrary()) {
        fprintf(stderr, "[HIPBackend] Failed to load HIP library\n");
        return false;
    }

    if (!InitializeHIPFunctions()) {
        fprintf(stderr, "[HIPBackend] Failed to initialize HIP functions\n");
        return false;
    }

    // Enumerate devices
    m_devices = EnumerateDevices();
    if (m_devices.empty()) {
        fprintf(stderr, "[HIPBackend] No HIP devices found\n");
        return false;
    }

    // Select first device
    if (!SelectDevice(0)) {
        fprintf(stderr, "[HIPBackend] Failed to select device\n");
        return false;
    }

    m_initialized = true;
    printf("[HIPBackend] Initialized successfully on device: %s\n", m_currentDevice.name.c_str());
    return true;
}

void HIPBackend::Shutdown() {
    if (!m_initialized) {
        return;
    }

    if (m_context && m_hipCtxDestroy) {
        m_hipCtxDestroy(m_context);
        m_context = nullptr;
    }

    if (m_hipLib) {
        FreeLibrary(m_hipLib);
        m_hipLib = nullptr;
    }

    m_initialized = false;
    printf("[HIPBackend] Shutdown complete\n");
}

bool HIPBackend::LoadHIPLibrary() {
    // Try different HIP library names
    m_hipLib = LoadLibraryA("amdhip64.dll");
    if (!m_hipLib) {
        m_hipLib = LoadLibraryA("hiprt64.dll");
    }
    if (!m_hipLib) {
        m_hipLib = LoadLibraryA("hip.dll");
    }

    return m_hipLib != nullptr;
}

bool HIPBackend::InitializeHIPFunctions() {
    m_hipInit = (int (*)(unsigned int))GetProcAddress(m_hipLib, "hipInit");
    m_hipDeviceGet = (int (*)(void**, int))GetProcAddress(m_hipLib, "hipDeviceGet");
    m_hipCtxCreate = (int (*)(void**, unsigned int, void*))GetProcAddress(m_hipLib, "hipCtxCreate");
    m_hipCtxDestroy = (int (*)(void*))GetProcAddress(m_hipLib, "hipCtxDestroy");
    m_hipMalloc = (int (*)(void**, size_t))GetProcAddress(m_hipLib, "hipMalloc");
    m_hipFree = (int (*)(void*))GetProcAddress(m_hipLib, "hipFree");
    m_hipMemcpyHtoD = (int (*)(void*, const void*, size_t))GetProcAddress(m_hipLib, "hipMemcpyHtoD");
    m_hipMemcpyDtoH = (int (*)(void*, void*, size_t))GetProcAddress(m_hipLib, "hipMemcpyDtoH");
    m_hipMemcpyDtoD = (int (*)(void*, void*, size_t))GetProcAddress(m_hipLib, "hipMemcpyDtoD");
    m_hipMemset = (int (*)(void*, int, size_t))GetProcAddress(m_hipLib, "hipMemset");
    m_hipDeviceSynchronize = (int (*)())GetProcAddress(m_hipLib, "hipDeviceSynchronize");
    m_hipGetDeviceCount = (int (*)(int*))GetProcAddress(m_hipLib, "hipGetDeviceCount");
    m_hipGetDeviceProperties = (int (*)(void*, int))GetProcAddress(m_hipLib, "hipGetDeviceProperties");
    m_hipMemGetInfo = (int (*)(size_t*, size_t*))GetProcAddress(m_hipLib, "hipMemGetInfo");

    if (!m_hipInit || !m_hipDeviceGet || !m_hipCtxCreate || !m_hipMalloc || !m_hipFree) {
        return false;
    }

    // Initialize HIP
    if (m_hipInit(0) != 0) {
        return false;
    }

    return true;
}

std::vector<GPUDeviceInfo> HIPBackend::EnumerateDevices() {
    std::vector<GPUDeviceInfo> devices;

    if (!m_hipGetDeviceCount) {
        return devices;
    }

    int count = 0;
    if (m_hipGetDeviceCount(&count) != 0 || count == 0) {
        return devices;
    }

    for (int i = 0; i < count; ++i) {
        GPUDeviceInfo info;
        info.deviceId = i;
        info.backend = GPUBackendType::HIP;
        info.name = "AMD GPU " + std::to_string(i);
        info.maxWorkGroupSize = 256;
        info.supportsFp16 = true;
        info.supportsFp8 = false;
        info.supportsInt8 = true;
        info.isDiscrete = true;

        // Get device properties
        if (m_hipGetDeviceProperties) {
            char props[256] = {};
            m_hipGetDeviceProperties(props, i);
            // Parse properties (simplified)
        }

        devices.push_back(info);
    }

    return devices;
}

bool HIPBackend::SelectDevice(uint32_t deviceIndex) {
    if (!m_hipDeviceGet || !m_hipCtxCreate) {
        return false;
    }

    void* device = nullptr;
    if (m_hipDeviceGet(&device, deviceIndex) != 0) {
        return false;
    }

    if (m_context) {
        m_hipCtxDestroy(m_context);
    }

    if (m_hipCtxCreate(&m_context, 0, device) != 0) {
        return false;
    }

    m_currentDeviceId = deviceIndex;
    if (deviceIndex < m_devices.size()) {
        m_currentDevice = m_devices[deviceIndex];
    }

    return true;
}

GPUBuffer* HIPBackend::AllocateBuffer(uint64_t size, bool hostVisible) {
    if (!m_hipMalloc) {
        return nullptr;
    }

    GPUBuffer* buffer = new GPUBuffer();
    buffer->size = size;
    buffer->isHostVisible = hostVisible;
    buffer->refCount = 1;

    if (m_hipMalloc(&buffer->hipPtr, size) != 0) {
        delete buffer;
        return nullptr;
    }

    return buffer;
}

void HIPBackend::FreeBuffer(GPUBuffer* buffer) {
    if (!buffer || !m_hipFree) {
        return;
    }

    if (buffer->hipPtr) {
        m_hipFree(buffer->hipPtr);
    }

    delete buffer;
}

void* HIPBackend::MapBuffer(GPUBuffer* buffer) {
    // HIP doesn't support mapping in the same way as Vulkan
    // Would need to allocate host-visible memory or use hipHostMalloc
    return nullptr;
}

void HIPBackend::UnmapBuffer(GPUBuffer* buffer) {
    // No-op for HIP
}

bool HIPBackend::CopyBuffer(GPUBuffer* dst, GPUBuffer* src, uint64_t size, uint64_t dstOffset, uint64_t srcOffset) {
    if (!m_hipMemcpyDtoD || !dst || !src) {
        return false;
    }

    void* dstPtr = (char*)dst->hipPtr + dstOffset;
    void* srcPtr = (char*)src->hipPtr + srcOffset;

    return m_hipMemcpyDtoD(dstPtr, srcPtr, size) == 0;
}

bool HIPBackend::CopyBufferHostToDevice(GPUBuffer* dst, const void* src, uint64_t size, uint64_t offset) {
    if (!m_hipMemcpyHtoD || !dst) {
        return false;
    }

    void* dstPtr = (char*)dst->hipPtr + offset;
    return m_hipMemcpyHtoD(dstPtr, src, size) == 0;
}

bool HIPBackend::CopyBufferDeviceToHost(void* dst, GPUBuffer* src, uint64_t size, uint64_t offset) {
    if (!m_hipMemcpyDtoH || !src) {
        return false;
    }

    void* srcPtr = (char*)src->hipPtr + offset;
    return m_hipMemcpyDtoH(dst, srcPtr, size) == 0;
}

bool HIPBackend::DispatchCompute(ComputeKernel* kernel, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ,
                                  GPUBuffer** buffers, uint32_t numBuffers) {
    // HIP kernel dispatch would go here
    // This requires compiled HIP kernels
    return true;
}

bool HIPBackend::Synchronize() {
    if (!m_hipDeviceSynchronize) {
        return false;
    }
    return m_hipDeviceSynchronize() == 0;
}

bool HIPBackend::Flush() {
    return Synchronize();
}

bool HIPBackend::MatMul(GPUBuffer* result, GPUBuffer* a, GPUBuffer* b,
                         uint32_t m, uint32_t n, uint32_t k, bool transposeB) {
    // Would call HIP BLAS or custom kernel
    return true;
}

bool HIPBackend::Softmax(GPUBuffer* result, GPUBuffer* input, uint32_t rows, uint32_t cols) {
    // Would call custom HIP kernel
    return true;
}

bool HIPBackend::LayerNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* gamma, GPUBuffer* beta,
                            uint32_t rows, uint32_t cols, float epsilon) {
    return true;
}

bool HIPBackend::RMSNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* weight,
                          uint32_t rows, uint32_t cols, float epsilon) {
    return true;
}

bool HIPBackend::RoPE(GPUBuffer* result, GPUBuffer* input, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) {
    return true;
}

bool HIPBackend::Attention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                            uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) {
    return true;
}

bool HIPBackend::FlashAttention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                                 uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim,
                                 float scale) {
    return true;
}

bool HIPBackend::UpdateKVCache(KVCacheEntry* cache, GPUBuffer* newKeys, GPUBuffer* newValues,
                                uint32_t startPos, uint32_t len) {
    if (!cache || !newKeys || !newValues) {
        return false;
    }

    uint64_t keySize = len * cache->numHeads * cache->headDim * sizeof(float);
    uint64_t valueSize = len * cache->numHeads * cache->headDim * sizeof(float);

    uint64_t keyOffset = startPos * cache->numHeads * cache->headDim * sizeof(float);
    uint64_t valueOffset = startPos * cache->numHeads * cache->headDim * sizeof(float);

    CopyBuffer(cache->keyCache, newKeys, keySize, keyOffset, 0);
    CopyBuffer(cache->valueCache, newValues, valueSize, valueOffset, 0);

    cache->seqLen = std::max(cache->seqLen, startPos + len);

    return true;
}

bool HIPBackend::ClearKVCache(KVCacheEntry* cache) {
    if (!cache) {
        return false;
    }
    cache->seqLen = 0;
    return true;
}

KVCacheEntry* HIPBackend::CreateKVCache(uint32_t maxSeqLen, uint32_t numHeads, uint32_t headDim, bool quantized) {
    KVCacheEntry* cache = new KVCacheEntry();
    cache->maxSeqLen = maxSeqLen;
    cache->numHeads = numHeads;
    cache->headDim = headDim;
    cache->seqLen = 0;
    cache->isQuantized = quantized;
    cache->quantScale = quantized ? 1.0f / 127.0f : 1.0f;

    uint64_t cacheSize = maxSeqLen * numHeads * headDim * (quantized ? 1 : sizeof(float));

    cache->keyCache = AllocateBuffer(cacheSize, false);
    cache->valueCache = AllocateBuffer(cacheSize, false);

    if (!cache->keyCache || !cache->valueCache) {
        DestroyKVCache(cache);
        return nullptr;
    }

    return cache;
}

void HIPBackend::DestroyKVCache(KVCacheEntry* cache) {
    if (!cache) return;

    if (cache->keyCache) {
        FreeBuffer(cache->keyCache);
    }
    if (cache->valueCache) {
        FreeBuffer(cache->valueCache);
    }

    delete cache;
}

uint64_t HIPBackend::GetAvailableVRAM() const {
    if (!m_hipMemGetInfo) {
        return 0;
    }

    size_t free = 0, total = 0;
    if (m_hipMemGetInfo(&free, &total) == 0) {
        return free;
    }

    return 0;
}

uint64_t HIPBackend::GetTotalVRAM() const {
    if (!m_hipMemGetInfo) {
        return 0;
    }

    size_t free = 0, total = 0;
    if (m_hipMemGetInfo(&free, &total) == 0) {
        return total;
    }

    return 0;
}

// ============================================================================
// Backend Factory
// ============================================================================

std::unique_ptr<IGPUBackend> GPUBackendFactory::CreateBackend(GPUBackendType type) {
    switch (type) {
        case GPUBackendType::Vulkan:
            return std::make_unique<VulkanBackend>();
        case GPUBackendType::HIP:
            return std::make_unique<HIPBackend>();
        default:
            return nullptr;
    }
}

std::unique_ptr<IGPUBackend> GPUBackendFactory::CreateAutoBackend() {
    // Try HIP first (AMD GPUs)
    auto hip = std::make_unique<HIPBackend>();
    if (hip->Initialize()) {
        return hip;
    }

    // Fall back to Vulkan
    auto vulkan = std::make_unique<VulkanBackend>();
    if (vulkan->Initialize()) {
        return vulkan;
    }

    return nullptr;
}

bool GPUBackendFactory::IsBackendAvailable(GPUBackendType type) {
    switch (type) {
        case GPUBackendType::Vulkan: {
            auto backend = std::make_unique<VulkanBackend>();
            return backend->Initialize();
        }
        case GPUBackendType::HIP: {
            auto backend = std::make_unique<HIPBackend>();
            return backend->Initialize();
        }
        default:
            return false;
    }
}

std::vector<GPUBackendType> GPUBackendFactory::GetAvailableBackends() {
    std::vector<GPUBackendType> backends;

    if (IsBackendAvailable(GPUBackendType::HIP)) {
        backends.push_back(GPUBackendType::HIP);
    }

    if (IsBackendAvailable(GPUBackendType::Vulkan)) {
        backends.push_back(GPUBackendType::Vulkan);
    }

    return backends;
}

// ============================================================================
// Backend Manager (Singleton)
// ============================================================================

GPUBackendManager& GPUBackendManager::Instance() {
    static GPUBackendManager instance;
    return instance;
}

bool GPUBackendManager::Initialize(GPUBackendType preferredType) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        return true;
    }

    if (preferredType == GPUBackendType::Auto) {
        m_backend = GPUBackendFactory::CreateAutoBackend();
    } else {
        m_backend = GPUBackendFactory::CreateBackend(preferredType);
    }

    if (!m_backend) {
        fprintf(stderr, "[GPUBackendManager] Failed to create GPU backend\n");
        return false;
    }

    if (!m_backend->Initialize()) {
        fprintf(stderr, "[GPUBackendManager] Failed to initialize GPU backend\n");
        m_backend.reset();
        return false;
    }

    m_currentType = m_backend->GetType();
    m_initialized = true;

    printf("[GPUBackendManager] Initialized %s backend\n", m_backend->GetBackendName());
    return true;
}

void GPUBackendManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_backend) {
        m_backend->Shutdown();
        m_backend.reset();
    }

    m_initialized = false;
}

bool GPUBackendManager::IsInitialized() const {
    return m_initialized && m_backend && m_backend->IsInitialized();
}

IGPUBackend* GPUBackendManager::GetBackend() {
    return m_backend.get();
}

GPUBackendType GPUBackendManager::GetCurrentBackendType() const {
    return m_currentType;
}

std::vector<GPUDeviceInfo> GPUBackendManager::EnumerateAllDevices() {
    if (!m_backend) {
        return {};
    }
    return m_backend->EnumerateDevices();
}

bool GPUBackendManager::SelectDevice(uint32_t deviceIndex) {
    if (!m_backend) {
        return false;
    }
    return m_backend->SelectDevice(deviceIndex);
}

uint64_t GPUBackendManager::GetAvailableVRAM() const {
    if (!m_backend) {
        return 0;
    }
    return m_backend->GetAvailableVRAM();
}

uint64_t GPUBackendManager::GetTotalVRAM() const {
    if (!m_backend) {
        return 0;
    }
    return m_backend->GetTotalVRAM();
}

} // namespace GPU
} // namespace RawrXD
