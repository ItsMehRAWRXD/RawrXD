// ============================================================================
// RawrXD Vulkan Tensor Upload + Readback Verification Test
// Purpose: Prove GPU buffer allocation → host→device staging → GPU storage
//          → device→host readback → CPU verification works end-to-end.
// Uses synthetic data matching token_embd.weight dimensions for determinism.
// ============================================================================
#include <vulkan/vulkan.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>

#define CHECK_VK(result, msg) \
    if ((result) != VK_SUCCESS) { \
        printf("[TENSOR-UPLOAD] FAIL: %s (VkResult=%d)\n", (msg), static_cast<int>(result)); \
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

struct VulkanContext {
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice physDev = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    VkCommandPool cmdPool = VK_NULL_HANDLE;
    uint32_t computeFamily = 0;
};

static bool createContext(VulkanContext& ctx) {
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD Tensor Upload Test";
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo instInfo{};
    instInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instInfo.pApplicationInfo = &appInfo;
    CHECK_VK(vkCreateInstance(&instInfo, nullptr, &ctx.instance), "vkCreateInstance");

    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(ctx.instance, &deviceCount, nullptr);
    if (deviceCount == 0) { printf("No physical devices\n"); return false; }
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(ctx.instance, &deviceCount, devices.data());
    ctx.physDev = devices[0];
    for (auto dev : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(dev, &props);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            ctx.physDev = dev;
            printf("[TENSOR-UPLOAD] GPU: %s\n", props.deviceName);
            break;
        }
    }

    if (!findComputeQueueFamily(ctx.physDev, ctx.computeFamily)) {
        printf("No compute queue\n"); return false;
    }

    float priority = 1.0f;
    VkDeviceQueueCreateInfo qInfo{};
    qInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qInfo.queueFamilyIndex = ctx.computeFamily;
    qInfo.queueCount = 1;
    qInfo.pQueuePriorities = &priority;

    VkDeviceCreateInfo dInfo{};
    dInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dInfo.queueCreateInfoCount = 1;
    dInfo.pQueueCreateInfos = &qInfo;
    CHECK_VK(vkCreateDevice(ctx.physDev, &dInfo, nullptr, &ctx.device), "vkCreateDevice");
    vkGetDeviceQueue(ctx.device, ctx.computeFamily, 0, &ctx.queue);

    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = ctx.computeFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    CHECK_VK(vkCreateCommandPool(ctx.device, &poolInfo, nullptr, &ctx.cmdPool), "vkCreateCommandPool");
    return true;
}

static void destroyContext(VulkanContext& ctx) {
    if (ctx.cmdPool) vkDestroyCommandPool(ctx.device, ctx.cmdPool, nullptr);
    if (ctx.device) vkDestroyDevice(ctx.device, nullptr);
    if (ctx.instance) vkDestroyInstance(ctx.instance, nullptr);
}

// Create a buffer with given usage and memory properties
static bool createBuffer(VulkanContext& ctx, VkDeviceSize size, VkBufferUsageFlags usage,
                         VkMemoryPropertyFlags memProps, VkBuffer& outBuf, VkDeviceMemory& outMem) {
    VkBufferCreateInfo bufInfo{};
    bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufInfo.size = size;
    bufInfo.usage = usage;
    bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    CHECK_VK(vkCreateBuffer(ctx.device, &bufInfo, nullptr, &outBuf), "vkCreateBuffer");

    VkMemoryRequirements memReq;
    vkGetBufferMemoryRequirements(ctx.device, outBuf, &memReq);

    uint32_t memType = findMemoryType(ctx.physDev, memReq.memoryTypeBits, memProps);
    if (memType == 0xFFFFFFFFu) {
        printf("[TENSOR-UPLOAD] No suitable memory type for flags=0x%X\n", static_cast<unsigned>(memProps));
        vkDestroyBuffer(ctx.device, outBuf, nullptr);
        return false;
    }

    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memReq.size;
    allocInfo.memoryTypeIndex = memType;
    CHECK_VK(vkAllocateMemory(ctx.device, &allocInfo, nullptr, &outMem), "vkAllocateMemory");
    CHECK_VK(vkBindBufferMemory(ctx.device, outBuf, outMem, 0), "vkBindBufferMemory");
    return true;
}

// Record and submit a one-shot command buffer, wait on fence
static bool submitAndWait(VulkanContext& ctx, VkCommandBuffer cmdBuf) {
    CHECK_VK(vkEndCommandBuffer(cmdBuf), "vkEndCommandBuffer");

    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fInfo{};
    fInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    CHECK_VK(vkCreateFence(ctx.device, &fInfo, nullptr, &fence), "vkCreateFence");

    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuf;
    CHECK_VK(vkQueueSubmit(ctx.queue, 1, &submitInfo, fence), "vkQueueSubmit");
    CHECK_VK(vkWaitForFences(ctx.device, 1, &fence, VK_TRUE, 10000000000ULL), "vkWaitForFences");

    vkDestroyFence(ctx.device, fence, nullptr);
    return true;
}

bool RunTensorUploadTest() {
    printf("=================================================================\n");
    printf("RawrXD Vulkan Tensor Upload + Readback Test\n");
    printf("=================================================================\n");

    VulkanContext ctx{};
    if (!createContext(ctx)) return false;

    // Simulate token_embd.weight: 32000 tokens × 2048 dims × 4 bytes = ~256 MB
    // Use a smaller slice for fast test: 1024 tokens × 512 dims = 2 MB
    const size_t tokenCount = 1024;
    const size_t dimCount = 512;
    const size_t elementCount = tokenCount * dimCount;
    const size_t dataBytes = elementCount * sizeof(float);

    printf("[TENSOR-UPLOAD] Simulated tensor: %zu tokens × %zu dims = %zu floats (%zu MB)\n",
           tokenCount, dimCount, elementCount, dataBytes / (1024 * 1024));

    // 1. Generate synthetic source data (deterministic pattern)
    std::vector<float> srcData(elementCount);
    for (size_t i = 0; i < elementCount; ++i) {
        srcData[i] = static_cast<float>(i % 1000) * 0.001f; // 0.000, 0.001, ..., 0.999 repeating
    }

    // 2. Create device-local GPU buffer (destination)
    VkBuffer gpuBuffer = VK_NULL_HANDLE;
    VkDeviceMemory gpuMemory = VK_NULL_HANDLE;
    if (!createBuffer(ctx, dataBytes,
                      VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
                      gpuBuffer, gpuMemory)) {
        destroyContext(ctx);
        return false;
    }
    printf("[TENSOR-UPLOAD] Device-local GPU buffer allocated\n");

    // 3. Create host-visible staging buffer (upload)
    VkBuffer stagingBuffer = VK_NULL_HANDLE;
    VkDeviceMemory stagingMemory = VK_NULL_HANDLE;
    if (!createBuffer(ctx, dataBytes,
                      VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                      stagingBuffer, stagingMemory)) {
        vkDestroyBuffer(ctx.device, gpuBuffer, nullptr);
        vkFreeMemory(ctx.device, gpuMemory, nullptr);
        destroyContext(ctx);
        return false;
    }
    printf("[TENSOR-UPLOAD] Host-visible staging buffer allocated\n");

    // 4. Write source data to staging buffer
    void* mapped = nullptr;
    CHECK_VK(vkMapMemory(ctx.device, stagingMemory, 0, dataBytes, 0, &mapped), "vkMapMemory");
    std::memcpy(mapped, srcData.data(), dataBytes);
    vkUnmapMemory(ctx.device, stagingMemory);
    printf("[TENSOR-UPLOAD] Host write to staging complete\n");

    // 5. Record: copy staging → GPU
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = ctx.cmdPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    VkCommandBuffer cmdBuf = VK_NULL_HANDLE;
    CHECK_VK(vkAllocateCommandBuffers(ctx.device, &allocInfo, &cmdBuf), "vkAllocateCommandBuffers");

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    CHECK_VK(vkBeginCommandBuffer(cmdBuf, &beginInfo), "vkBeginCommandBuffer");

    VkBufferCopy copyRegion{};
    copyRegion.size = dataBytes;
    vkCmdCopyBuffer(cmdBuf, stagingBuffer, gpuBuffer, 1, &copyRegion);

    // Barrier: ensure copy completes before readback
    VkBufferMemoryBarrier barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    barrier.buffer = gpuBuffer;
    barrier.size = dataBytes;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         0, 0, nullptr, 1, &barrier, 0, nullptr);

    if (!submitAndWait(ctx, cmdBuf)) {
        vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf);
        destroyContext(ctx);
        return false;
    }
    printf("[TENSOR-UPLOAD] Staging → GPU copy complete\n");
    vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf);

    // 6. Create readback staging buffer
    VkBuffer readbackBuffer = VK_NULL_HANDLE;
    VkDeviceMemory readbackMemory = VK_NULL_HANDLE;
    if (!createBuffer(ctx, dataBytes,
                      VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                      readbackBuffer, readbackMemory)) {
        vkDestroyBuffer(ctx.device, stagingBuffer, nullptr);
        vkFreeMemory(ctx.device, stagingMemory, nullptr);
        vkDestroyBuffer(ctx.device, gpuBuffer, nullptr);
        vkFreeMemory(ctx.device, gpuMemory, nullptr);
        destroyContext(ctx);
        return false;
    }

    // 7. Record: GPU → readback
    VkCommandBuffer cmdBuf2 = VK_NULL_HANDLE;
    CHECK_VK(vkAllocateCommandBuffers(ctx.device, &allocInfo, &cmdBuf2), "vkAllocateCommandBuffers");
    CHECK_VK(vkBeginCommandBuffer(cmdBuf2, &beginInfo), "vkBeginCommandBuffer");

    VkBufferCopy copyBack{};
    copyBack.size = dataBytes;
    vkCmdCopyBuffer(cmdBuf2, gpuBuffer, readbackBuffer, 1, &copyBack);

    if (!submitAndWait(ctx, cmdBuf2)) {
        vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf2);
        destroyContext(ctx);
        return false;
    }
    printf("[TENSOR-UPLOAD] GPU → readback copy complete\n");
    vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf2);

    // 8. Verify readback data
    CHECK_VK(vkMapMemory(ctx.device, readbackMemory, 0, dataBytes, 0, &mapped), "vkMapMemory readback");
    const float* readbackData = static_cast<const float*>(mapped);
    bool ok = true;
    size_t mismatchCount = 0;
    for (size_t i = 0; i < elementCount; ++i) {
        if (std::fabs(readbackData[i] - srcData[i]) > 1e-6f) {
            if (mismatchCount < 5) {
                printf("[TENSOR-UPLOAD] Mismatch at [%zu]: expected %.6f, got %.6f\n",
                       i, srcData[i], readbackData[i]);
            }
            mismatchCount++;
            ok = false;
        }
    }
    vkUnmapMemory(ctx.device, readbackMemory);

    if (ok) {
        printf("[TENSOR-UPLOAD] Verification PASS: all %zu elements match\n", elementCount);
    } else {
        printf("[TENSOR-UPLOAD] Verification FAIL: %zu mismatches out of %zu elements\n", mismatchCount, elementCount);
    }

    // Cleanup
    vkDestroyBuffer(ctx.device, readbackBuffer, nullptr);
    vkFreeMemory(ctx.device, readbackMemory, nullptr);
    vkDestroyBuffer(ctx.device, stagingBuffer, nullptr);
    vkFreeMemory(ctx.device, stagingMemory, nullptr);
    vkDestroyBuffer(ctx.device, gpuBuffer, nullptr);
    vkFreeMemory(ctx.device, gpuMemory, nullptr);
    destroyContext(ctx);

    printf("=================================================================\n");
    printf("TENSOR UPLOAD TEST: %s\n", ok ? "PASS" : "FAIL");
    printf("  - Context creation (instance/device/queue/pool)\n");
    printf("  - Device-local buffer allocation\n");
    printf("  - Host-visible staging buffer allocation\n");
    printf("  - Host write to staging\n");
    printf("  - vkCmdCopyBuffer staging→GPU\n");
    printf("  - Memory barrier\n");
    printf("  - vkCmdCopyBuffer GPU→readback\n");
    printf("  - Host readback + element-wise verification\n");
    printf("=================================================================\n");
    return ok;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    bool ok = RunTensorUploadTest();
    return ok ? 0 : 1;
}
