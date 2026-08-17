// ============================================================================
// RawrXD Vulkan GEMM Verification Test
// Purpose: Run a compute shader GEMM (C = A × B) on GPU and compare against
//          CPU reference implementation with tolerance check.
// ============================================================================
#include <vulkan/vulkan.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>
#include <fstream>

#define CHECK_VK(result, msg) \
    if ((result) != VK_SUCCESS) { \
        printf("[GEMM-TEST] FAIL: %s (VkResult=%d)\n", (msg), static_cast<int>(result)); \
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
    appInfo.pApplicationName = "RawrXD GEMM Test";
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
            printf("[GEMM-TEST] GPU: %s\n", props.deviceName);
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

static std::vector<uint32_t> loadSpirv(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        printf("[GEMM-TEST] Failed to open SPIR-V: %s\n", path);
        return {};
    }
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> code(size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(code.data()), size);
    return code;
}

// CPU reference GEMM: C[M×N] = A[M×K] × B[K×N]
static void cpuGemm(const float* A, const float* B, float* C, uint32_t M, uint32_t N, uint32_t K) {
    for (uint32_t m = 0; m < M; ++m) {
        for (uint32_t n = 0; n < N; ++n) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < K; ++k) {
                sum += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = sum;
        }
    }
}

bool RunGemmTest() {
    printf("=================================================================\n");
    printf("RawrXD Vulkan GEMM Verification Test\n");
    printf("=================================================================\n");

    VulkanContext ctx{};
    if (!createContext(ctx)) return false;

    // Matrix dimensions: 64×64 for fast verification
    const uint32_t M = 64, N = 64, K = 64;
    const size_t bytesA = M * K * sizeof(float);
    const size_t bytesB = K * N * sizeof(float);
    const size_t bytesC = M * N * sizeof(float);

    printf("[GEMM-TEST] Matrix dimensions: A[%u×%u] × B[%u×%u] = C[%u×%u]\n", M, K, K, N, M, N);

    // Generate deterministic test data
    std::vector<float> A(M * K), B(K * N), cpuC(M * N);
    for (size_t i = 0; i < A.size(); ++i) A[i] = static_cast<float>((i % 17) * 0.1f);
    for (size_t i = 0; i < B.size(); ++i) B[i] = static_cast<float>((i % 13) * 0.1f);
    cpuGemm(A.data(), B.data(), cpuC.data(), M, N, K);
    printf("[GEMM-TEST] CPU reference computed\n");

    // Create GPU buffers
    VkBuffer bufA = VK_NULL_HANDLE, bufB = VK_NULL_HANDLE, bufC = VK_NULL_HANDLE;
    VkDeviceMemory memA = VK_NULL_HANDLE, memB = VK_NULL_HANDLE, memC = VK_NULL_HANDLE;
    if (!createBuffer(ctx, bytesA, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, bufA, memA)) return false;
    if (!createBuffer(ctx, bytesB, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, bufB, memB)) return false;
    if (!createBuffer(ctx, bytesC, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, bufC, memC)) return false;

    // Staging buffers for upload/download
    VkBuffer stageA = VK_NULL_HANDLE, stageB = VK_NULL_HANDLE, stageC = VK_NULL_HANDLE;
    VkDeviceMemory stageMemA = VK_NULL_HANDLE, stageMemB = VK_NULL_HANDLE, stageMemC = VK_NULL_HANDLE;
    createBuffer(ctx, bytesA, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                 VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, stageA, stageMemA);
    createBuffer(ctx, bytesB, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                 VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, stageB, stageMemB);
    createBuffer(ctx, bytesC, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                 VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, stageC, stageMemC);

    // Upload A and B
    void* mapped = nullptr;
    vkMapMemory(ctx.device, stageMemA, 0, bytesA, 0, &mapped);
    std::memcpy(mapped, A.data(), bytesA);
    vkUnmapMemory(ctx.device, stageMemA);
    vkMapMemory(ctx.device, stageMemB, 0, bytesB, 0, &mapped);
    std::memcpy(mapped, B.data(), bytesB);
    vkUnmapMemory(ctx.device, stageMemB);

    // Record upload commands
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = ctx.cmdPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    VkCommandBuffer cmdBuf = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(ctx.device, &allocInfo, &cmdBuf);

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmdBuf, &beginInfo);

    VkBufferCopy copyA{}; copyA.size = bytesA;
    VkBufferCopy copyB{}; copyB.size = bytesB;
    vkCmdCopyBuffer(cmdBuf, stageA, bufA, 1, &copyA);
    vkCmdCopyBuffer(cmdBuf, stageB, bufB, 1, &copyB);

    VkBufferMemoryBarrier barriers[2] = {};
    for (int i = 0; i < 2; ++i) {
        barriers[i].sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        barriers[i].srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barriers[i].dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barriers[i].size = VK_WHOLE_SIZE;
    }
    barriers[0].buffer = bufA;
    barriers[1].buffer = bufB;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         0, 0, nullptr, 2, barriers, 0, nullptr);

    // Load SPIR-V and create compute pipeline
    std::vector<uint32_t> spirv = loadSpirv("gemm_compute.spv");
    if (spirv.empty()) {
        printf("[GEMM-TEST] Failed to load SPIR-V\n");
        return false;
    }

    VkShaderModuleCreateInfo shaderInfo{};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = spirv.size() * sizeof(uint32_t);
    shaderInfo.pCode = spirv.data();
    VkShaderModule shaderModule = VK_NULL_HANDLE;
    CHECK_VK(vkCreateShaderModule(ctx.device, &shaderInfo, nullptr, &shaderModule), "vkCreateShaderModule");

    // Descriptor set layout
    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dslInfo{};
    dslInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dslInfo.bindingCount = 3;
    dslInfo.pBindings = bindings;
    VkDescriptorSetLayout dsl = VK_NULL_HANDLE;
    CHECK_VK(vkCreateDescriptorSetLayout(ctx.device, &dslInfo, nullptr, &dsl), "vkCreateDescriptorSetLayout");

    // Pipeline layout with push constants
    VkPushConstantRange pcRange{};
    pcRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pcRange.offset = 0;
    pcRange.size = sizeof(uint32_t) * 3;

    VkPipelineLayoutCreateInfo plInfo{};
    plInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    plInfo.setLayoutCount = 1;
    plInfo.pSetLayouts = &dsl;
    plInfo.pushConstantRangeCount = 1;
    plInfo.pPushConstantRanges = &pcRange;
    VkPipelineLayout pipelineLayout = VK_NULL_HANDLE;
    CHECK_VK(vkCreatePipelineLayout(ctx.device, &plInfo, nullptr, &pipelineLayout), "vkCreatePipelineLayout");

    VkPipelineShaderStageCreateInfo stageInfo{};
    stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stageInfo.module = shaderModule;
    stageInfo.pName = "main";

    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage = stageInfo;
    pipelineInfo.layout = pipelineLayout;
    VkPipeline pipeline = VK_NULL_HANDLE;
    CHECK_VK(vkCreateComputePipelines(ctx.device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline), "vkCreateComputePipelines");

    // Descriptor pool and set
    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 3;
    VkDescriptorPoolCreateInfo dpInfo{};
    dpInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpInfo.maxSets = 1;
    dpInfo.poolSizeCount = 1;
    dpInfo.pPoolSizes = &poolSize;
    VkDescriptorPool dp = VK_NULL_HANDLE;
    CHECK_VK(vkCreateDescriptorPool(ctx.device, &dpInfo, nullptr, &dp), "vkCreateDescriptorPool");

    VkDescriptorSetAllocateInfo dsAllocInfo{};
    dsAllocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dsAllocInfo.descriptorPool = dp;
    dsAllocInfo.descriptorSetCount = 1;
    dsAllocInfo.pSetLayouts = &dsl;
    VkDescriptorSet ds = VK_NULL_HANDLE;
    CHECK_VK(vkAllocateDescriptorSets(ctx.device, &dsAllocInfo, &ds), "vkAllocateDescriptorSets");

    VkDescriptorBufferInfo dbiA{bufA, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo dbiB{bufB, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo dbiC{bufC, 0, VK_WHOLE_SIZE};
    VkWriteDescriptorSet writes[3] = {};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiA;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiB;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiC;
    vkUpdateDescriptorSets(ctx.device, 3, writes, 0, nullptr);

    // Dispatch compute shader
    vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout, 0, 1, &ds, 0, nullptr);
    uint32_t pushConsts[3] = {M, N, K};
    vkCmdPushConstants(cmdBuf, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pushConsts), pushConsts);
    vkCmdDispatch(cmdBuf, (M + 7) / 8, (N + 7) / 8, 1);

    // Barrier before readback
    VkBufferMemoryBarrier barrierC{};
    barrierC.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrierC.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    barrierC.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    barrierC.buffer = bufC;
    barrierC.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         0, 0, nullptr, 1, &barrierC, 0, nullptr);

    // Copy result to readback staging
    VkBufferCopy copyC{}; copyC.size = bytesC;
    vkCmdCopyBuffer(cmdBuf, bufC, stageC, 1, &copyC);

    if (!submitAndWait(ctx, cmdBuf)) return false;
    printf("[GEMM-TEST] GPU compute dispatched and completed\n");

    // Readback and verify
    vkMapMemory(ctx.device, stageMemC, 0, bytesC, 0, &mapped);
    const float* gpuC = static_cast<const float*>(mapped);
    bool ok = true;
    size_t mismatchCount = 0;
    float maxError = 0.0f;
    for (size_t i = 0; i < M * N; ++i) {
        float err = std::fabs(gpuC[i] - cpuC[i]);
        if (err > maxError) maxError = err;
        if (err > 1e-4f) {
            if (mismatchCount < 5) {
                printf("[GEMM-TEST] Mismatch at [%zu]: CPU=%.6f GPU=%.6f err=%.6f\n", i, cpuC[i], gpuC[i], err);
            }
            mismatchCount++;
            ok = false;
        }
    }
    vkUnmapMemory(ctx.device, stageMemC);

    if (ok) {
        printf("[GEMM-TEST] Verification PASS: all %u elements match (max error=%.6e)\n", M * N, maxError);
    } else {
        printf("[GEMM-TEST] Verification FAIL: %zu mismatches (max error=%.6e)\n", mismatchCount, maxError);
    }

    // Cleanup
    vkDestroyDescriptorPool(ctx.device, dp, nullptr);
    vkDestroyPipeline(ctx.device, pipeline, nullptr);
    vkDestroyPipelineLayout(ctx.device, pipelineLayout, nullptr);
    vkDestroyDescriptorSetLayout(ctx.device, dsl, nullptr);
    vkDestroyShaderModule(ctx.device, shaderModule, nullptr);
    vkDestroyBuffer(ctx.device, stageA, nullptr); vkFreeMemory(ctx.device, stageMemA, nullptr);
    vkDestroyBuffer(ctx.device, stageB, nullptr); vkFreeMemory(ctx.device, stageMemB, nullptr);
    vkDestroyBuffer(ctx.device, stageC, nullptr); vkFreeMemory(ctx.device, stageMemC, nullptr);
    vkDestroyBuffer(ctx.device, bufA, nullptr); vkFreeMemory(ctx.device, memA, nullptr);
    vkDestroyBuffer(ctx.device, bufB, nullptr); vkFreeMemory(ctx.device, memB, nullptr);
    vkDestroyBuffer(ctx.device, bufC, nullptr); vkFreeMemory(ctx.device, memC, nullptr);
    destroyContext(ctx);

    printf("=================================================================\n");
    printf("GEMM VERIFICATION TEST: %s\n", ok ? "PASS" : "FAIL");
    printf("  - SPIR-V shader load + compute pipeline creation\n");
    printf("  - Descriptor set + push constants\n");
    printf("  - vkCmdDispatch compute execution\n");
    printf("  - Memory barrier shader→transfer\n");
    printf("  - Readback + CPU reference comparison\n");
    printf("=================================================================\n");
    return ok;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    bool ok = RunGemmTest();
    return ok ? 0 : 1;
}
