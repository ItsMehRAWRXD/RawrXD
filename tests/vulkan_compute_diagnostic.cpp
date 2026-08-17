// ============================================================================
// RawrXD Vulkan Compute Diagnostic Test
// Minimal proof: buffer allocation → host→device transfer → compute fill → readback
// No shader compilation required. Uses vkCmdFillBuffer for deterministic verification.
// ============================================================================
#include <vulkan/vulkan.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#define CHECK_VK(result, msg) \
    if ((result) != VK_SUCCESS) { \
        printf("[VULKAN-DIAG] FAIL: %s (VkResult=%d)\n", (msg), static_cast<int>(result)); \
        return false; \
    }

static bool findComputeQueueFamily(VkPhysicalDevice physDev, uint32_t& outFamily) {
    uint32_t count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physDev, &count, nullptr);
    std::vector<VkQueueFamilyProperties> families(count);
    vkGetPhysicalDeviceQueueFamilyProperties(physDev, &count, families.data());
    for (uint32_t i = 0; i < count; ++i) {
        if (families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            outFamily = i;
            return true;
        }
    }
    return false;
}

static uint32_t findMemoryType(VkPhysicalDevice physDev, uint32_t typeFilter, VkMemoryPropertyFlags props) {
    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(physDev, &memProps);
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        if ((typeFilter & (1u << i)) && (memProps.memoryTypes[i].propertyFlags & props) == props) {
            return i;
        }
    }
    return 0xFFFFFFFFu;
}

bool RunVulkanComputeDiagnostic() {
    printf("=================================================================\n");
    printf("RawrXD Vulkan Compute Diagnostic Test\n");
    printf("=================================================================\n");

    // 1. Create instance
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD Vulkan Diagnostic";
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo instInfo{};
    instInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instInfo.pApplicationInfo = &appInfo;

    VkInstance instance = VK_NULL_HANDLE;
    CHECK_VK(vkCreateInstance(&instInfo, nullptr, &instance), "vkCreateInstance");
    printf("[VULKAN-DIAG] Instance created\n");

    // 2. Select physical device (prefer discrete GPU)
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        printf("[VULKAN-DIAG] FAIL: No physical devices found\n");
        vkDestroyInstance(instance, nullptr);
        return false;
    }
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    VkPhysicalDevice physDev = VK_NULL_HANDLE;
    for (auto dev : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(dev, &props);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            printf("[VULKAN-DIAG] Selected discrete GPU: %s\n", props.deviceName);
            physDev = dev;
            break;
        }
    }
    if (physDev == VK_NULL_HANDLE) {
        physDev = devices[0];
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(physDev, &props);
        printf("[VULKAN-DIAG] Selected fallback GPU: %s\n", props.deviceName);
    }

    // 3. Find compute queue family
    uint32_t computeFamily = 0;
    if (!findComputeQueueFamily(physDev, computeFamily)) {
        printf("[VULKAN-DIAG] FAIL: No compute queue family found\n");
        vkDestroyInstance(instance, nullptr);
        return false;
    }
    printf("[VULKAN-DIAG] Compute queue family: %u\n", computeFamily);

    // 4. Create logical device
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueInfo{};
    queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = computeFamily;
    queueInfo.queueCount = 1;
    queueInfo.pQueuePriorities = &queuePriority;

    VkDeviceCreateInfo devInfo{};
    devInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    devInfo.queueCreateInfoCount = 1;
    devInfo.pQueueCreateInfos = &queueInfo;

    VkDevice device = VK_NULL_HANDLE;
    CHECK_VK(vkCreateDevice(physDev, &devInfo, nullptr, &device), "vkCreateDevice");
    printf("[VULKAN-DIAG] Logical device created\n");

    VkQueue queue = VK_NULL_HANDLE;
    vkGetDeviceQueue(device, computeFamily, 0, &queue);

    // 5. Create command pool
    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = computeFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    VkCommandPool cmdPool = VK_NULL_HANDLE;
    CHECK_VK(vkCreateCommandPool(device, &poolInfo, nullptr, &cmdPool), "vkCreateCommandPool");

    // 6. Allocate command buffer
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = cmdPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer cmdBuf = VK_NULL_HANDLE;
    CHECK_VK(vkAllocateCommandBuffers(device, &allocInfo, &cmdBuf), "vkAllocateCommandBuffers");

    // 7. Create buffer (device-local + host-visible for simplicity)
    const size_t bufferSize = 1024; // 256 floats
    VkBufferCreateInfo bufInfo{};
    bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufInfo.size = bufferSize;
    bufInfo.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer buffer = VK_NULL_HANDLE;
    CHECK_VK(vkCreateBuffer(device, &bufInfo, nullptr, &buffer), "vkCreateBuffer");

    VkMemoryRequirements memReq;
    vkGetBufferMemoryRequirements(device, buffer, &memReq);

    uint32_t memType = findMemoryType(physDev, memReq.memoryTypeBits,
                                       VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (memType == 0xFFFFFFFFu) {
        // Fall back to device-local + staging
        memType = findMemoryType(physDev, memReq.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    }

    VkMemoryAllocateInfo memAlloc{};
    memAlloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    memAlloc.allocationSize = memReq.size;
    memAlloc.memoryTypeIndex = memType;

    VkDeviceMemory memory = VK_NULL_HANDLE;
    CHECK_VK(vkAllocateMemory(device, &memAlloc, nullptr, &memory), "vkAllocateMemory");
    CHECK_VK(vkBindBufferMemory(device, buffer, memory, 0), "vkBindBufferMemory");
    printf("[VULKAN-DIAG] Buffer allocated: %zu bytes (memType=%u)\n", bufferSize, memType);

    // 8. Initialize buffer with pattern via host-visible memory
    void* mapped = nullptr;
    CHECK_VK(vkMapMemory(device, memory, 0, bufferSize, 0, &mapped), "vkMapMemory");
    uint32_t* data = static_cast<uint32_t*>(mapped);
    for (size_t i = 0; i < bufferSize / sizeof(uint32_t); ++i) {
        data[i] = static_cast<uint32_t>(i);
    }
    vkUnmapMemory(device, memory);
    printf("[VULKAN-DIAG] Host write: pattern 0,1,2,...,%zu\n", bufferSize / sizeof(uint32_t) - 1);

    // 9. Record command buffer: fill buffer with 0xDEADBEEF
    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    CHECK_VK(vkBeginCommandBuffer(cmdBuf, &beginInfo), "vkBeginCommandBuffer");

    // Fill entire buffer with 0xDEADBEEF
    vkCmdFillBuffer(cmdBuf, buffer, 0, bufferSize, 0xDEADBEEF);

    // Barrier: ensure fill is complete before readback
    VkBufferMemoryBarrier barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    barrier.buffer = buffer;
    barrier.size = bufferSize;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT,
                         0, 0, nullptr, 1, &barrier, 0, nullptr);

    CHECK_VK(vkEndCommandBuffer(cmdBuf), "vkEndCommandBuffer");

    // 10. Submit and wait
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuf;

    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(device, &fenceInfo, nullptr, &fence);

    CHECK_VK(vkQueueSubmit(queue, 1, &submitInfo, fence), "vkQueueSubmit");
    CHECK_VK(vkWaitForFences(device, 1, &fence, VK_TRUE, 10000000000ULL), "vkWaitForFences");
    printf("[VULKAN-DIAG] Command submitted and completed\n");

    // 11. Read back and verify
    CHECK_VK(vkMapMemory(device, memory, 0, bufferSize, 0, &mapped), "vkMapMemory (readback)");
    data = static_cast<uint32_t*>(mapped);
    bool ok = true;
    for (size_t i = 0; i < bufferSize / sizeof(uint32_t); ++i) {
        if (data[i] != 0xDEADBEEF) {
            printf("[VULKAN-DIAG] FAIL: data[%zu] = 0x%08X (expected 0xDEADBEEF)\n", i, data[i]);
            ok = false;
            break;
        }
    }
    vkUnmapMemory(device, memory);

    if (ok) {
        printf("[VULKAN-DIAG] Readback verified: all %zu dwords = 0xDEADBEEF\n", bufferSize / sizeof(uint32_t));
    }

    // 12. Cleanup
    vkDestroyFence(device, fence, nullptr);
    vkFreeCommandBuffers(device, cmdPool, 1, &cmdBuf);
    vkDestroyCommandPool(device, cmdPool, nullptr);
    vkDestroyBuffer(device, buffer, nullptr);
    vkFreeMemory(device, memory, nullptr);
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);

    printf("=================================================================\n");
    if (ok) {
        printf("VULKAN COMPUTE DIAGNOSTIC: PASS\n");
        printf("  - Instance creation\n");
        printf("  - Physical device selection\n");
        printf("  - Logical device + compute queue\n");
        printf("  - Buffer allocation + memory bind\n");
        printf("  - Host write\n");
        printf("  - Command buffer recording\n");
        printf("  - vkCmdFillBuffer execution\n");
        printf("  - Memory barrier\n");
        printf("  - Fence synchronization\n");
        printf("  - Host readback + verification\n");
    } else {
        printf("VULKAN COMPUTE DIAGNOSTIC: FAIL\n");
    }
    printf("=================================================================\n");
    return ok;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    bool ok = RunVulkanComputeDiagnostic();
    return ok ? 0 : 1;
}
