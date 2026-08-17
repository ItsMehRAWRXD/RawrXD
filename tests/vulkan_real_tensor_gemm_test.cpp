// ============================================================================
// RawrXD Real Tensor GPU GEMM Standalone Test
// Loads a GGUF model tensor directly, uploads to GPU, runs gemm_compute.spv,
// and compares against CPU reference. No RawrXD inference stack dependencies.
// ============================================================================
#include <vulkan/vulkan.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>
#include <fstream>
#include <string>

#define CHECK_VK(result, msg) \
    if ((result) != VK_SUCCESS) { \
        printf("[REAL-GEMM] FAIL: %s (VkResult=%d)\n", (msg), static_cast<int>(result)); \
        return false; \
    }

// ============================================================================
// Minimal GGUF v3 header parser (just enough to read tensor metadata + data)
// ============================================================================
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t n_tensors;
    uint64_t n_metadata;
};
#pragma pack(pop)

static uint64_t readLEU64(const uint8_t*& p) {
    uint64_t v = *(const uint64_t*)p;
    p += 8;
    return v;
}
static uint32_t readLEU32(const uint8_t*& p) {
    uint32_t v = *(const uint32_t*)p;
    p += 4;
    return v;
}
static uint16_t readLEU16(const uint8_t*& p) {
    uint16_t v = *(const uint16_t*)p;
    p += 2;
    return v;
}
static float readF32(const uint8_t*& p) {
    float v = *(const float*)p;
    p += 4;
    return v;
}

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
    uint64_t byteSize;
};

static bool parseGGUF(const std::string& path, std::vector<TensorInfo>& outTensors, uint8_t*& fileData, size_t& fileSize) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) { printf("[REAL-GEMM] Cannot open %s\n", path.c_str()); return false; }
    fileSize = f.tellg();
    f.seekg(0, std::ios::beg);
    fileData = new uint8_t[fileSize];
    f.read((char*)fileData, fileSize);
    f.close();

    const uint8_t* p = fileData;
    GGUFHeader h = *(const GGUFHeader*)p; p += sizeof(GGUFHeader);
    if (h.magic != 0x46554747) { printf("[REAL-GEMM] Bad GGUF magic\n"); return false; }

    // Skip metadata (simplified: just walk past them)
    for (uint64_t i = 0; i < h.n_metadata; ++i) {
        uint64_t keyLen = readLEU64(p);
        p += keyLen; // skip key string
        uint32_t valType = readLEU32(p);
        // Skip value based on type (simplified)
        if (valType == 0) { p += 4; } // U32
        else if (valType == 1) { p += 8; } // U64
        else if (valType == 2) { p += 4; } // I32
        else if (valType == 3) { p += 8; } // I64
        else if (valType == 4) { p += 4; } // F32
        else if (valType == 5) { p += 8; } // F64
        else if (valType == 6) { p += 1; } // BOOL
        else if (valType == 7) { uint64_t slen = readLEU64(p); p += slen; } // STRING
        else if (valType == 8) { // ARRAY
            uint32_t arrType = readLEU32(p);
            uint64_t arrCount = readLEU64(p);
            for (uint64_t j = 0; j < arrCount; ++j) {
                if (arrType == 7) { uint64_t slen = readLEU64(p); p += slen; }
                else if (arrType == 0) { p += 4; }
                else if (arrType == 1) { p += 8; }
                else { p += 4; }
            }
        }
        else { p += 4; }
    }

    // Parse tensor info array
    for (uint64_t i = 0; i < h.n_tensors; ++i) {
        TensorInfo t;
        uint64_t nameLen = readLEU64(p);
        t.name.assign((const char*)p, nameLen);
        p += nameLen;
        uint32_t n_dims = readLEU32(p);
        for (uint32_t d = 0; d < n_dims; ++d) {
            t.dims.push_back(readLEU64(p));
        }
        t.type = readLEU32(p);
        t.offset = readLEU64(p);
        // Calculate byte size (simplified: assume contiguous, no padding)
        uint64_t nelem = 1;
        for (auto d : t.dims) nelem *= d;
        static const uint64_t typeSizes[19] = {
            4,2,18,19,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
        };
        if (t.type < 19) t.byteSize = nelem * typeSizes[t.type] / (t.type <= 1 ? 1 : (t.type <= 3 ? 2 : 1));
        else t.byteSize = nelem;
        outTensors.push_back(t);
    }
    return true;
}

// ============================================================================
// Q4_0 dequantization (CPU reference)
// ============================================================================
static void dequantQ4_0(const uint8_t* src, float* dst, size_t n) {
    size_t nblocks = n / 32;
    for (size_t b = 0; b < nblocks; ++b) {
        const uint8_t* blk = src + b * 18;
        float d = *(const uint16_t*)blk; // fp16 scale — simplified
        // Actually fp16: just treat as float for now
        float scale = (float)(*(const uint16_t*)blk) / 1.0f;
        if (scale == 0) scale = 1.0f;
        const uint8_t* qs = blk + 2;
        for (int i = 0; i < 16; ++i) {
            uint8_t v = qs[i];
            int x0 = (v & 0x0F) - 8;
            int x1 = (v >> 4) - 8;
            dst[b * 32 + i] = x0 * scale;
            dst[b * 32 + i + 16] = x1 * scale;
        }
    }
}

// ============================================================================
// Vulkan helpers
// ============================================================================
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
    appInfo.pApplicationName = "RawrXD Real GEMM";
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
            printf("[REAL-GEMM] GPU: %s\n", props.deviceName);
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
        printf("[REAL-GEMM] Failed to open SPIR-V: %s\n", path);
        return {};
    }
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> code(size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(code.data()), size);
    return code;
}

// CPU reference GEMV: output[M] = W[M×K] @ input[K]
static void cpuGemv(const float* W, const float* input, float* output, int M, int K) {
    for (int m = 0; m < M; ++m) {
        float sum = 0.0f;
        for (int k = 0; k < K; ++k) {
            sum += W[m * K + k] * input[k];
        }
        output[m] = sum;
    }
}

// ============================================================================
// Main test
// ============================================================================
bool RunRealTensorGemmTest(const char* modelPath, const char* spvPath) {
    printf("=================================================================\n");
    printf("RawrXD Real Tensor GPU GEMM Test\n");
    printf("=================================================================\n");

    // 1. Parse GGUF
    std::vector<TensorInfo> tensors;
    uint8_t* fileData = nullptr;
    size_t fileSize = 0;
    if (!parseGGUF(modelPath, tensors, fileData, fileSize)) {
        return false;
    }
    printf("[REAL-GEMM] Parsed GGUF: %zu tensors\n", tensors.size());

    // Find output.weight or token_embd.weight
    const TensorInfo* weightTensor = nullptr;
    for (const auto& t : tensors) {
        if (t.name.find("output.weight") != std::string::npos ||
            t.name.find("token_embd.weight") != std::string::npos) {
            weightTensor = &t;
            break;
        }
    }
    if (!weightTensor) {
        printf("[REAL-GEMM] No suitable weight tensor found\n");
        delete[] fileData;
        return false;
    }
    printf("[REAL-GEMM] Selected tensor: %s dims=[", weightTensor->name.c_str());
    for (size_t i = 0; i < weightTensor->dims.size(); ++i) {
        printf("%llu%s", (unsigned long long)weightTensor->dims[i], i + 1 < weightTensor->dims.size() ? "," : "");
    }
    printf("] type=%u\n", weightTensor->type);

    // 2. Dequantize to float (CPU)
    uint64_t nelem = 1;
    for (auto d : weightTensor->dims) nelem *= d;
    std::vector<float> weightFloat(nelem);
    const uint8_t* tensorData = fileData + weightTensor->offset;

    if (weightTensor->type == 2) { // Q4_0
        dequantQ4_0(tensorData, weightFloat.data(), nelem);
        printf("[REAL-GEMM] Dequantized Q4_0 → %llu floats\n", (unsigned long long)nelem);
    } else if (weightTensor->type == 0) { // F32
        std::memcpy(weightFloat.data(), tensorData, nelem * sizeof(float));
        printf("[REAL-GEMM] Copied F32 → %llu floats\n", (unsigned long long)nelem);
    } else {
        printf("[REAL-GEMM] Unsupported tensor type %u\n", weightTensor->type);
        delete[] fileData;
        return false;
    }

    // Determine dimensions: assume 2D weight [M × K]
    int M = (int)weightTensor->dims[0];
    int K = (int)(nelem / weightTensor->dims[0]);
    printf("[REAL-GEMM] GEMM dimensions: M=%d K=%d\n", M, K);

    // 3. Create Vulkan context
    VulkanContext ctx{};
    if (!createContext(ctx)) {
        delete[] fileData;
        return false;
    }

    // 4. Upload weight to GPU
    size_t weightBytes = nelem * sizeof(float);
    VkBuffer weightBuf = VK_NULL_HANDLE;
    VkDeviceMemory weightMem = VK_NULL_HANDLE;
    if (!createBuffer(ctx, weightBytes,
                      VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, weightBuf, weightMem)) {
        destroyContext(ctx);
        delete[] fileData;
        return false;
    }

    VkBuffer stageBuf = VK_NULL_HANDLE;
    VkDeviceMemory stageMem = VK_NULL_HANDLE;
    createBuffer(ctx, weightBytes, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                 VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                 stageBuf, stageMem);
    void* mapped = nullptr;
    vkMapMemory(ctx.device, stageMem, 0, weightBytes, 0, &mapped);
    std::memcpy(mapped, weightFloat.data(), weightBytes);
    vkUnmapMemory(ctx.device, stageMem);

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

    VkBufferCopy copy{}; copy.size = weightBytes;
    vkCmdCopyBuffer(cmdBuf, stageBuf, weightBuf, 1, &copy);
    VkBufferMemoryBarrier barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    barrier.buffer = weightBuf;
    barrier.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         0, 0, nullptr, 1, &barrier, 0, nullptr);

    if (!submitAndWait(ctx, cmdBuf)) {
        destroyContext(ctx);
        delete[] fileData;
        return false;
    }
    printf("[REAL-GEMM] Weight uploaded to GPU\n");
    vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf);

    // 5. Create input and output buffers
    size_t inputBytes = K * sizeof(float);
    size_t outputBytes = M * sizeof(float);
    std::vector<float> inputData(K);
    for (int i = 0; i < K; ++i) inputData[i] = static_cast<float>((i % 10) * 0.1f);

    VkBuffer inputBuf = VK_NULL_HANDLE, outputBuf = VK_NULL_HANDLE;
    VkDeviceMemory inputMem = VK_NULL_HANDLE, outputMem = VK_NULL_HANDLE;
    createBuffer(ctx, inputBytes,
                 VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                 VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, inputBuf, inputMem);
    createBuffer(ctx, outputBytes,
                 VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                 VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, outputBuf, outputMem);

    // Upload input
    VkBuffer inputStage = VK_NULL_HANDLE;
    VkDeviceMemory inputStageMem = VK_NULL_HANDLE;
    createBuffer(ctx, inputBytes, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                 VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                 inputStage, inputStageMem);
    vkMapMemory(ctx.device, inputStageMem, 0, inputBytes, 0, &mapped);
    std::memcpy(mapped, inputData.data(), inputBytes);
    vkUnmapMemory(ctx.device, inputStageMem);

    // 6. Load SPIR-V and create compute pipeline
    std::vector<uint32_t> spirv = loadSpirv(spvPath);
    if (spirv.empty()) {
        destroyContext(ctx);
        delete[] fileData;
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

    // 7. Record: upload input + dispatch + barrier
    VkCommandBuffer cmdBuf2 = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(ctx.device, &allocInfo, &cmdBuf2);
    vkBeginCommandBuffer(cmdBuf2, &beginInfo);

    VkBufferCopy inputCopy{}; inputCopy.size = inputBytes;
    vkCmdCopyBuffer(cmdBuf2, inputStage, inputBuf, 1, &inputCopy);
    VkBufferMemoryBarrier inputBarrier{};
    inputBarrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    inputBarrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    inputBarrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    inputBarrier.buffer = inputBuf;
    inputBarrier.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(cmdBuf2, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         0, 0, nullptr, 1, &inputBarrier, 0, nullptr);

    vkCmdBindPipeline(cmdBuf2, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(cmdBuf2, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout, 0, 1, &ds, 0, nullptr);
    uint32_t pushConsts[3] = {(uint32_t)M, 1, (uint32_t)K}; // N=1 for GEMV
    vkCmdPushConstants(cmdBuf2, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pushConsts), pushConsts);
    vkCmdDispatch(cmdBuf2, (M + 7) / 8, 1, 1);

    VkBufferMemoryBarrier outputBarrier{};
    outputBarrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    outputBarrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    outputBarrier.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    outputBarrier.buffer = outputBuf;
    outputBarrier.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(cmdBuf2, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         0, 0, nullptr, 1, &outputBarrier, 0, nullptr);

    if (!submitAndWait(ctx, cmdBuf2)) {
        destroyContext(ctx);
        delete[] fileData;
        return false;
    }
    printf("[REAL-GEMM] GPU compute dispatched\n");
    vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf2);

    // 8. Readback and verify
    VkBuffer readbackBuf = VK_NULL_HANDLE;
    VkDeviceMemory readbackMem = VK_NULL_HANDLE;
    createBuffer(ctx, outputBytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                 VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                 readbackBuf, readbackMem);

    VkCommandBuffer cmdBuf3 = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(ctx.device, &allocInfo, &cmdBuf3);
    vkBeginCommandBuffer(cmdBuf3, &beginInfo);
    VkBufferCopy readbackCopy{}; readbackCopy.size = outputBytes;
    vkCmdCopyBuffer(cmdBuf3, outputBuf, readbackBuf, 1, &readbackCopy);
    if (!submitAndWait(ctx, cmdBuf3)) {
        destroyContext(ctx);
        delete[] fileData;
        return false;
    }
    vkFreeCommandBuffers(ctx.device, ctx.cmdPool, 1, &cmdBuf3);

    vkMapMemory(ctx.device, readbackMem, 0, outputBytes, 0, &mapped);
    const float* gpuOutput = static_cast<const float*>(mapped);

    // CPU reference
    std::vector<float> cpuOutput(M);
    cpuGemv(weightFloat.data(), inputData.data(), cpuOutput.data(), M, K);

    bool ok = true;
    size_t mismatchCount = 0;
    float maxError = 0.0f;
    for (int i = 0; i < M; ++i) {
        float err = std::fabs(gpuOutput[i] - cpuOutput[i]);
        if (err > maxError) maxError = err;
        if (err > 1e-3f) {
            if (mismatchCount < 5) {
                printf("[REAL-GEMM] Mismatch at [%d]: CPU=%.6f GPU=%.6f err=%.6f\n", i, cpuOutput[i], gpuOutput[i], err);
            }
            mismatchCount++;
            ok = false;
        }
    }
    vkUnmapMemory(ctx.device, readbackMem);

    if (ok) {
        printf("[REAL-GEMM] Verification PASS: all %d elements match (max error=%.6e)\n", M, maxError);
    } else {
        printf("[REAL-GEMM] Verification FAIL: %zu mismatches (max error=%.6e)\n", mismatchCount, maxError);
    }

    // Cleanup
    vkDestroyDescriptorPool(ctx.device, dp, nullptr);
    vkDestroyPipeline(ctx.device, pipeline, nullptr);
    vkDestroyPipelineLayout(ctx.device, pipelineLayout, nullptr);
    vkDestroyDescriptorSetLayout(ctx.device, dsl, nullptr);
    vkDestroyShaderModule(ctx.device, shaderModule, nullptr);
    vkDestroyBuffer(ctx.device, inputStage, nullptr); vkFreeMemory(ctx.device, inputStageMem, nullptr);
    vkDestroyBuffer(ctx.device, readbackBuf, nullptr); vkFreeMemory(ctx.device, readbackMem, nullptr);
    vkDestroyBuffer(ctx.device, inputBuf, nullptr); vkFreeMemory(ctx.device, inputMem, nullptr);
    vkDestroyBuffer(ctx.device, outputBuf, nullptr); vkFreeMemory(ctx.device, outputMem, nullptr);
    vkDestroyBuffer(ctx.device, stageBuf, nullptr); vkFreeMemory(ctx.device, stageMem, nullptr);
    vkDestroyBuffer(ctx.device, weightBuf, nullptr); vkFreeMemory(ctx.device, weightMem, nullptr);
    destroyContext(ctx);
    delete[] fileData;

    printf("=================================================================\n");
    printf("REAL TENSOR GEMM TEST: %s\n", ok ? "PASS" : "FAIL");
    printf("=================================================================\n");
    return ok;
}

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1] : "d:\\rawrxd\\bench_min.gguf";
    const char* spvPath = (argc > 2) ? argv[2] : "gemm_compute.spv";
    bool ok = RunRealTensorGemmTest(modelPath, spvPath);
    return ok ? 0 : 1;
}
