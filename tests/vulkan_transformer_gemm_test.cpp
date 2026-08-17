// ============================================================================
// RawrXD Transformer GEMM Vulkan Dispatch Integration Test
// ============================================================================
// Include the real Vulkan SDK header FIRST, before any RawrXD header that
// might define fallback stubs. This ensures real VkDevice/VkBuffer/etc. win.
#include <vulkan/vulkan.h>

#include "../src/rawrxd_inference.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>
#include <string>
#include <fstream>

#define CHECK_VK(result, msg) \
    if ((result) != VK_SUCCESS) { \
        printf("[XFORMER-GEMM] FAIL: %s (VkResult=%d)\n", (msg), static_cast<int>(result)); \
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
    appInfo.pApplicationName = "RawrXD Transformer GEMM Test";
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
            printf("[XFORMER-GEMM] GPU: %s\n", props.deviceName);
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
        printf("[XFORMER-GEMM] Failed to open SPIR-V: %s\n", path);
        return {};
    }
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> code(size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(code.data()), size);
    return code;
}

// CPU reference GEMV: output[M] = W[M×K] @ input[K]
static void cpuGemv(const float* W, const float* input, float* output, uint32_t M, uint32_t K) {
    for (uint32_t m = 0; m < M; ++m) {
        float sum = 0.0f;
        for (uint32_t k = 0; k < K; ++k) {
            sum += W[m * K + k] * input[k];
        }
        output[m] = sum;
    }
}

bool RunTransformerGemmTest(const wchar_t* modelPath) {
    printf("=================================================================\n");
    printf("RawrXD Transformer GEMM Vulkan Dispatch Integration Test\n");
    printf("=================================================================\n");

    // 1. Initialize inference (loads model, creates Vulkan device)
    RawrXDInference inference;
    printf("[XFORMER-GEMM] Loading model...\n");
    if (!inference.Initialize(modelPath, nullptr, nullptr)) {
        printf("[XFORMER-GEMM] FAIL: Model load failed: %s\n", inference.GetLastLoadErrorMessage().c_str());
        return false;
    }
    printf("[XFORMER-GEMM] Model loaded successfully\n");

    // 2. Get model dimensions
    RawrXDModelLoader& loader = inference.GetLoader();
    int dim = loader.getDim();
    int vocabSize = loader.getVocabSize();
    if (dim == 0) dim = 2048;
    if (vocabSize == 0) vocabSize = 32000;
    printf("[XFORMER-GEMM] Model dims: dim=%d vocab=%d\n", dim, vocabSize);

    // 3. Pick a weight tensor to test: output.weight (vocab_size × dim)
    // For large models, use a representative slice to avoid GPU OOM
    // while still proving the real RawrXD tensor → GPU GEMM path.
    const std::string tensorName = "output.weight";
    float* hostWeight = loader.GetTensor(tensorName);
    if (!hostWeight) {
        printf("[XFORMER-GEMM] FAIL: Could not load %s\n", tensorName.c_str());
        return false;
    }
    printf("[XFORMER-GEMM] Loaded %s from host memory\n", tensorName.c_str());

    // Use a slice: first SLICE_ROWS rows of the full vocab × dim matrix.
    // This keeps the test fast and within GPU memory limits while using
    // real Qwen weights and realistic transformer dimensions.
    const int SLICE_ROWS = 4096;  // Representative slice (adjust as needed)
    const int actualRows = std::min(SLICE_ROWS, vocabSize);
    const size_t sliceWeightBytes = static_cast<size_t>(actualRows) * dim * sizeof(float);
    printf("[XFORMER-GEMM] Using slice: %d rows × %d dims = %.1f MB\n",
           actualRows, dim, sliceWeightBytes / (1024.0 * 1024.0));

    // 4. Create a separate Vulkan context for the test
    VulkanContext ctx{};
    if (!createContext(ctx)) return false;

    // 5. Upload weight slice to GPU (device-local)
    VkBuffer weightBuf = VK_NULL_HANDLE;
    VkDeviceMemory weightMem = VK_NULL_HANDLE;
    if (!createBuffer(ctx, sliceWeightBytes,
                      VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, weightBuf, weightMem)) {
        destroyContext(ctx);
        return false;
    }

    // Staging upload for weight slice
    VkBuffer weightStage = VK_NULL_HANDLE;
    VkDeviceMemory weightStageMem = VK_NULL_HANDLE;
    if (!createBuffer(ctx, sliceWeightBytes, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                      weightStage, weightStageMem)) {
        vkDestroyBuffer(ctx.device, weightBuf, nullptr);
        vkFreeMemory(ctx.device, weightMem, nullptr);
        destroyContext(ctx);
        return false;
    }
    void* mapped = nullptr;
    vkMapMemory(ctx.device, weightStageMem, 0, sliceWeightBytes, 0, &mapped);
    std::memcpy(mapped, hostWeight, sliceWeightBytes);  // Only first slice
    vkUnmapMemory(ctx.device, weightStageMem);

    // 6. Create input and output GPU buffers (sized for the slice)
    const size_t inputBytes = static_cast<size_t>(dim) * sizeof(float);
    const size_t outputBytes = static_cast<size_t>(actualRows) * sizeof(float);

    std::vector<float> inputData(dim);
    for (int i = 0; i < dim; ++i) inputData[i] = static_cast<float>((i % 10) * 0.1f);

    VkBuffer inputBuf = VK_NULL_HANDLE, outputBuf = VK_NULL_HANDLE;
    VkDeviceMemory inputMem = VK_NULL_HANDLE, outputMem = VK_NULL_HANDLE;
    if (!createBuffer(ctx, inputBytes,
                      VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, inputBuf, inputMem)) {
        vkDestroyBuffer(ctx.device, weightStage, nullptr);
        vkFreeMemory(ctx.device, weightStageMem, nullptr);
        vkDestroyBuffer(ctx.device, weightBuf, nullptr);
        vkFreeMemory(ctx.device, weightMem, nullptr);
        destroyContext(ctx);
        return false;
    }
    if (!createBuffer(ctx, outputBytes,
                      VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, outputBuf, outputMem)) {
        vkDestroyBuffer(ctx.device, inputBuf, nullptr);
        vkFreeMemory(ctx.device, inputMem, nullptr);
        vkDestroyBuffer(ctx.device, weightStage, nullptr);
        vkFreeMemory(ctx.device, weightStageMem, nullptr);
        vkDestroyBuffer(ctx.device, weightBuf, nullptr);
        vkFreeMemory(ctx.device, weightMem, nullptr);
        destroyContext(ctx);
        return false;
    }

    // Staging upload for input
    VkBuffer inputStage = VK_NULL_HANDLE;
    VkDeviceMemory inputStageMem = VK_NULL_HANDLE;
    if (!createBuffer(ctx, inputBytes, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                      inputStage, inputStageMem)) {
        vkDestroyBuffer(ctx.device, outputBuf, nullptr);
        vkFreeMemory(ctx.device, outputMem, nullptr);
        vkDestroyBuffer(ctx.device, inputBuf, nullptr);
        vkFreeMemory(ctx.device, inputMem, nullptr);
        vkDestroyBuffer(ctx.device, weightStage, nullptr);
        vkFreeMemory(ctx.device, weightStageMem, nullptr);
        vkDestroyBuffer(ctx.device, weightBuf, nullptr);
        vkFreeMemory(ctx.device, weightMem, nullptr);
        destroyContext(ctx);
        return false;
    }
    vkMapMemory(ctx.device, inputStageMem, 0, inputBytes, 0, &mapped);
    std::memcpy(mapped, inputData.data(), inputBytes);
    vkUnmapMemory(ctx.device, inputStageMem);

    // 7. Record upload commands
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

    VkBufferCopy weightCopy{}; weightCopy.size = sliceWeightBytes;
    vkCmdCopyBuffer(cmdBuf, weightStage, weightBuf, 1, &weightCopy);
    VkBufferCopy inputCopy{}; inputCopy.size = inputBytes;
    vkCmdCopyBuffer(cmdBuf, inputStage, inputBuf, 1, &inputCopy);

    VkBufferMemoryBarrier barriers[2] = {};
    for (int i = 0; i < 2; ++i) {
        barriers[i].sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        barriers[i].srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barriers[i].dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barriers[i].size = VK_WHOLE_SIZE;
    }
    barriers[0].buffer = weightBuf;
    barriers[1].buffer = inputBuf;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         0, 0, nullptr, 2, barriers, 0, nullptr);

    // 8. Load SPIR-V and create compute pipeline
    std::vector<uint32_t> spirv = loadSpirv("gemm_compute.spv");
    if (spirv.empty()) {
        printf("[XFORMER-GEMM] FAIL: Could not load gemm_compute.spv\n");
        destroyContext(ctx);
        return false;
    }

    VkShaderModuleCreateInfo shaderInfo{};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = spirv.size() * sizeof(uint32_t);
    shaderInfo.pCode = spirv.data();
    VkShaderModule shaderModule = VK_NULL_HANDLE;
    CHECK_VK(vkCreateShaderModule(ctx.device, &shaderInfo, nullptr, &shaderModule), "vkCreateShaderModule");

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

    VkDescriptorBufferInfo dbiA{weightBuf, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo dbiB{inputBuf, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo dbiC{outputBuf, 0, VK_WHOLE_SIZE};
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

    // 9. Dispatch compute shader for GEMV: M=actualRows, N=1, K=dim
    vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout, 0, 1, &ds, 0, nullptr);
    uint32_t pushConsts[3] = {static_cast<uint32_t>(actualRows), 1u, static_cast<uint32_t>(dim)};
    vkCmdPushConstants(cmdBuf, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pushConsts), pushConsts);
    vkCmdDispatch(cmdBuf, (actualRows + 7) / 8, 1, 1);

    // Barrier: shader write → transfer read
    VkBufferMemoryBarrier barrierC{};
    barrierC.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrierC.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    barrierC.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    barrierC.buffer = outputBuf;
    barrierC.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         0, 0, nullptr, 1, &barrierC, 0, nullptr);

    // 10. Copy result to readback staging
    VkBuffer readbackBuf = VK_NULL_HANDLE;
    VkDeviceMemory readbackMem = VK_NULL_HANDLE;
    if (!createBuffer(ctx, outputBytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                      readbackBuf, readbackMem)) {
        printf("[XFORMER-GEMM] FAIL: Could not allocate readback buffer (%.1f MB)\n",
               outputBytes / (1024.0 * 1024.0));
        vkDestroyDescriptorPool(ctx.device, dp, nullptr);
        vkDestroyPipeline(ctx.device, pipeline, nullptr);
        vkDestroyPipelineLayout(ctx.device, pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(ctx.device, dsl, nullptr);
        vkDestroyShaderModule(ctx.device, shaderModule, nullptr);
        vkDestroyBuffer(ctx.device, inputStage, nullptr); vkFreeMemory(ctx.device, inputStageMem, nullptr);
        vkDestroyBuffer(ctx.device, inputBuf, nullptr); vkFreeMemory(ctx.device, inputMem, nullptr);
        vkDestroyBuffer(ctx.device, weightStage, nullptr); vkFreeMemory(ctx.device, weightStageMem, nullptr);
        vkDestroyBuffer(ctx.device, weightBuf, nullptr); vkFreeMemory(ctx.device, weightMem, nullptr);
        destroyContext(ctx);
        return false;
    }

    VkBufferCopy copyC{}; copyC.size = outputBytes;
    vkCmdCopyBuffer(cmdBuf, outputBuf, readbackBuf, 1, &copyC);

    if (!submitAndWait(ctx, cmdBuf)) {
        destroyContext(ctx);
        return false;
    }
    printf("[XFORMER-GEMM] GPU compute dispatched and completed\n");
    vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf);

    // 11. Readback and verify against CPU reference
    vkMapMemory(ctx.device, readbackMem, 0, outputBytes, 0, &mapped);
    const float* gpuOutput = static_cast<const float*>(mapped);

    std::vector<float> cpuOutput(vocabSize);
    cpuGemv(hostWeight, inputData.data(), cpuOutput.data(), static_cast<uint32_t>(vocabSize), static_cast<uint32_t>(dim));
    printf("[XFORMER-GEMM] CPU reference computed\n");

    bool ok = true;
    size_t mismatchCount = 0;
    float maxError = 0.0f;
    // Only verify the slice that the GPU actually computed (actualRows)
    for (int i = 0; i < actualRows; ++i) {
        float err = std::fabs(gpuOutput[i] - cpuOutput[i]);
        if (err > maxError) maxError = err;
        if (err > 1e-4f) {
            if (mismatchCount < 5) {
                printf("[XFORMER-GEMM] Mismatch at [%d]: CPU=%.6f GPU=%.6f err=%.6f\n", i, cpuOutput[i], gpuOutput[i], err);
            }
            mismatchCount++;
            ok = false;
        }
    }
    vkUnmapMemory(ctx.device, readbackMem);

    if (ok) {
        printf("[XFORMER-GEMM] Verification PASS: all %d elements match (max error=%.6e)\n", actualRows, maxError);
    } else {
        printf("[XFORMER-GEMM] Verification FAIL: %zu mismatches out of %d (max error=%.6e)\n", mismatchCount, actualRows, maxError);
    }

    // Cleanup
    vkDestroyDescriptorPool(ctx.device, dp, nullptr);
    vkDestroyPipeline(ctx.device, pipeline, nullptr);
    vkDestroyPipelineLayout(ctx.device, pipelineLayout, nullptr);
    vkDestroyDescriptorSetLayout(ctx.device, dsl, nullptr);
    vkDestroyShaderModule(ctx.device, shaderModule, nullptr);
    vkDestroyBuffer(ctx.device, readbackBuf, nullptr); vkFreeMemory(ctx.device, readbackMem, nullptr);
    vkDestroyBuffer(ctx.device, inputStage, nullptr); vkFreeMemory(ctx.device, inputStageMem, nullptr);
    vkDestroyBuffer(ctx.device, inputBuf, nullptr); vkFreeMemory(ctx.device, inputMem, nullptr);
    vkDestroyBuffer(ctx.device, outputBuf, nullptr); vkFreeMemory(ctx.device, outputMem, nullptr);
    vkDestroyBuffer(ctx.device, weightStage, nullptr); vkFreeMemory(ctx.device, weightStageMem, nullptr);
    vkDestroyBuffer(ctx.device, weightBuf, nullptr); vkFreeMemory(ctx.device, weightMem, nullptr);
    destroyContext(ctx);

    printf("=================================================================\n");
    printf("TRANSFORMER GEMM DISPATCH TEST: %s\n", ok ? "PASS" : "FAIL");
    printf("  - Model load via RawrXDInference\n");
    printf("  - Weight tensor extraction (output.weight)\n");
    printf("  - GPU buffer allocation + staging upload\n");
    printf("  - Input buffer upload\n");
    printf("  - SPIR-V compute pipeline creation\n");
    printf("  - vkCmdDispatch with real transformer dimensions\n");
    printf("  - Readback + CPU reference comparison\n");
    printf("=================================================================\n");
    return ok;
}

int wmain(int argc, wchar_t** argv) {
    (void)argc; (void)argv;
    const wchar_t* modelPath = L"d:\\rawrxd\\bench_min.gguf";
    if (argc > 1) modelPath = argv[1];
    bool ok = RunTransformerGemmTest(modelPath);
    return ok ? 0 : 1;
}
