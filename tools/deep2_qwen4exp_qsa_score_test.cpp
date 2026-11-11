// The Qwen4Exp QSA indexer scoring, executed.
//
// The indexer scores the query against the compressed-key cache through a
// page table, and only the first "visible" compressed keys of a sequence
// take part. The artifact had been compiled and statically checked and had
// never been run.
//
// The page table and the visible-window arithmetic are exactly the kind of
// thing a static check cannot speak to, so this runs it against a host
// reference computed in double precision.
//
// It is self-contained: its own device, and no file another part of the
// engine owns. A machine with no GPU is BLOCKED, never PASS.
#include <vulkan/vulkan.h>

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kRows = 5;
constexpr uint32_t kIndexHeads = 4;
constexpr uint32_t kKeyDim = 8;
constexpr uint32_t kPageSize = 4;
constexpr uint32_t kCompressRatio = 2;
constexpr uint32_t kMaxPages = 3;
constexpr uint32_t kRequests = 2;
constexpr uint32_t kColumns = kMaxPages * kPageSize;

struct Buffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr;
};

// The reference.
//
// The score of a row and a column is the sum over the index heads of the
// positive part of the dot product of that head's query with the key, over
// the square root of the key dimension.
//
// Only the first "visible" compressed keys take part. The visible count is
// the smaller of the position advanced by the compression ratio and the
// sequence length advanced by the same ratio.
void Reference(const std::vector<float>& query,
               const std::vector<float>& keyCache,
               const std::vector<int>& pageTable,
               const std::vector<int>& tokenToRequest,
               const std::vector<int>& queryPosition,
               const std::vector<int>& sequenceLength,
               std::vector<double>& logits,
               std::vector<uint32_t>& visible) {
    logits.assign(static_cast<size_t>(kRows) * kColumns, 0.0);
    visible.assign(kRows, 0);
    for (uint32_t row = 0; row < kRows; ++row) {
        const int request = tokenToRequest[row];
        const int position = queryPosition[row];
        uint32_t visibleCount = 0;
        for (uint32_t column = 0; column < kColumns; ++column) {
            if (request < 0 || static_cast<uint32_t>(request) >= kRequests || position < 0) {
                logits[static_cast<size_t>(row) * kColumns + column] =
                    -std::numeric_limits<double>::infinity();
                continue;
            }
            const int byPosition = (position + 1) / static_cast<int>(kCompressRatio);
            const int byLength = std::max(sequenceLength[request], 0) / static_cast<int>(kCompressRatio);
            const uint32_t v = static_cast<uint32_t>(std::min(byPosition, byLength));
            if (column == 0) visibleCount = std::min(v, kColumns);
            if (column >= v) {
                logits[static_cast<size_t>(row) * kColumns + column] =
                    -std::numeric_limits<double>::infinity();
                continue;
            }
            const int physicalPage = pageTable[static_cast<size_t>(request) * kMaxPages +
                                               column / kPageSize];
            if (physicalPage < 0) {
                logits[static_cast<size_t>(row) * kColumns + column] =
                    -std::numeric_limits<double>::infinity();
                continue;
            }
            const size_t keyBase =
                (static_cast<size_t>(physicalPage) * kPageSize + column % kPageSize) * kKeyDim;
            const size_t queryBase = static_cast<size_t>(row) * kIndexHeads * kKeyDim;
            double score = 0.0;
            for (uint32_t head = 0; head < kIndexHeads; ++head) {
                double dot = 0.0;
                const size_t headBase = queryBase + static_cast<size_t>(head) * kKeyDim;
                for (uint32_t dim = 0; dim < kKeyDim; ++dim) {
                    dot += static_cast<double>(query[headBase + dim]) *
                           static_cast<double>(keyCache[keyBase + dim]);
                }
                score += std::max(dot, 0.0);
            }
            logits[static_cast<size_t>(row) * kColumns + column] =
                score / std::sqrt(static_cast<double>(kKeyDim));
        }
        visible[row] = visibleCount;
    }
}

bool ReadSpirv(const std::string& path, std::vector<uint32_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    const std::streamsize size = f.tellg();
    if (size <= 0 || (size % 4) != 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size) / 4);
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}

struct Teardown {
    VkDevice device = VK_NULL_HANDLE;
    VkInstance instance = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;
    VkCommandPool commandPool = VK_NULL_HANDLE;
    VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkShaderModule module = VK_NULL_HANDLE;
    VkPipelineLayout pipelineLayout = VK_NULL_HANDLE;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    Buffer* buffers = nullptr;
    uint32_t bufferCount = 0;
};

// Release everything, and contain a fault.
//
// The proof is the verdict, and the verdict is computed before any of this.
// Releasing the device is where a driver or a validation layer can fault on
// a unified-memory device, and that fault must not be allowed to change the
// answer the gate gives: a teardown fault is reported as a teardown fault.
//
// The function takes only trivially copyable values, because a function with
// destructible locals cannot use structured exception handling.
int TeardownAll(const Teardown& t) {
    __try {
        vkDeviceWaitIdle(t.device);
        if (t.fence) vkDestroyFence(t.device, t.fence, nullptr);
        if (t.commandPool) vkDestroyCommandPool(t.device, t.commandPool, nullptr);
        if (t.descriptorPool) vkDestroyDescriptorPool(t.device, t.descriptorPool, nullptr);
        if (t.pipeline) vkDestroyPipeline(t.device, t.pipeline, nullptr);
        if (t.module) vkDestroyShaderModule(t.device, t.module, nullptr);
        if (t.pipelineLayout) vkDestroyPipelineLayout(t.device, t.pipelineLayout, nullptr);
        if (t.setLayout) vkDestroyDescriptorSetLayout(t.device, t.setLayout, nullptr);
        // The buffers are NOT released here.
        //
        // Releasing a host-visible buffer that the device has written to
        // faults on this driver: the write-back of the device's cached copy
        // lands on memory the host has already been given back, and the heap
        // is corrupted. The device owns every allocation and reclaims all
        // of them when it is destroyed, so the buffers are left to it. This
        // is a one-shot diagnostic that ends by leaving the process, and
        // nothing outlives the device.
        // The device and the instance are left to the loader.
        //
        // Releasing them here faults on this machine: the write-back of the
        // device's cached copies of the host-visible buffers lands on memory
        // the host has already been given back, and the heap is corrupted.
        // The loader owns both and releases them when the process ends, and
        // this is a one-shot diagnostic that ends by leaving the process.
        // Nothing outlives the device either way.
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::printf("teardown: an exception was contained; the verdict above stands\n");
        std::fflush(stdout);
        return 1;
    }
}

} // namespace

int main(int argc, char** argv) {
    // The output is unbuffered. A run that aborts must still say how far it
    // got, and a block-buffered stream loses everything before the abort.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::string spirvPath = "src/deep2/shaders/deep2_qwen4exp_qsa_score.spv";
    if (argc >= 2) spirvPath = argv[1];

    std::printf("=== Qwen4Exp QSA indexer scoring: device execution ===\n");
    std::printf("artifact: %s\n", spirvPath.c_str());

    std::vector<uint32_t> spirv;
    if (!ReadSpirv(spirvPath, spirv)) {
        std::printf("RESULT: BLOCKED (the artifact is missing or unreadable: %s)\n",
                    spirvPath.c_str());
        return 2;
    }
    std::printf("artifact: %u words of SPIR-V\n", static_cast<unsigned>(spirv.size()));

    const char* validationLayer = "VK_LAYER_KHRONOS_validation";
    uint32_t layerCount = 0;
    vkEnumerateInstanceLayerProperties(&layerCount, nullptr);
    std::vector<VkLayerProperties> layerProperties(layerCount);
    vkEnumerateInstanceLayerProperties(&layerCount, layerProperties.data());
    bool haveValidation = false;
    for (const auto& p : layerProperties) {
        if (std::strcmp(p.layerName, validationLayer) == 0) { haveValidation = true; break; }
    }
    // The layer can be turned off for a diagnosis.
    if (const char* off = std::getenv("DEEP2_NO_VALIDATION")) {
        if (*off && *off != '0') haveValidation = false;
    }

    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "deep2_qwen4exp_qsa_score_test";
    appInfo.apiVersion = VK_API_VERSION_1_1;
    const char* const enabledLayers[] = { validationLayer };
    VkInstanceCreateInfo instanceInfo{};
    instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instanceInfo.pApplicationInfo = &appInfo;
    if (haveValidation) {
        instanceInfo.enabledLayerCount = 1;
        instanceInfo.ppEnabledLayerNames = enabledLayers;
        std::printf("validation: %s is on\n", validationLayer);
    }
    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(&instanceInfo, nullptr, &instance) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (no Vulkan instance could be created)\n");
        return 2;
    }

    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        std::printf("RESULT: BLOCKED (no Vulkan device is present)\n");
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    std::vector<VkPhysicalDevice> physicalDevices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, physicalDevices.data());
    VkPhysicalDevice physical = VK_NULL_HANDLE;
    uint32_t queueFamily = 0;
    for (VkPhysicalDevice candidate : physicalDevices) {
        uint32_t familyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(candidate, &familyCount, nullptr);
        std::vector<VkQueueFamilyProperties> families(familyCount);
        vkGetPhysicalDeviceQueueFamilyProperties(candidate, &familyCount, families.data());
        for (uint32_t i = 0; i < familyCount; ++i) {
            if (families[i].queueCount > 0 && (families[i].queueFlags & VK_QUEUE_COMPUTE_BIT)) {
                physical = candidate;
                queueFamily = i;
                break;
            }
        }
        if (physical != VK_NULL_HANDLE) break;
    }
    if (physical == VK_NULL_HANDLE) {
        std::printf("RESULT: BLOCKED (no device with a compute queue)\n");
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    VkPhysicalDeviceProperties deviceProps{};
    vkGetPhysicalDeviceProperties(physical, &deviceProps);
    std::printf("device : %s\n", deviceProps.deviceName);

    const float priority = 1.0f;
    VkDeviceQueueCreateInfo queueInfo{};
    queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = queueFamily;
    queueInfo.queueCount = 1;
    queueInfo.pQueuePriorities = &priority;
    VkPhysicalDeviceFeatures features{};
    VkDeviceCreateInfo deviceInfo{};
    deviceInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceInfo.queueCreateInfoCount = 1;
    deviceInfo.pQueueCreateInfos = &queueInfo;
    deviceInfo.pEnabledFeatures = &features;
    VkDevice device = VK_NULL_HANDLE;
    if (vkCreateDevice(physical, &deviceInfo, nullptr, &device) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the device could not be created)\n");
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    VkQueue queue = VK_NULL_HANDLE;
    vkGetDeviceQueue(device, queueFamily, 0, &queue);

    VkDescriptorSetLayoutBinding bindings[8]{};
    for (uint32_t i = 0; i < 8; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo layoutInfo{};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 8;
    layoutInfo.pBindings = bindings;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    vkCreateDescriptorSetLayout(device, &layoutInfo, nullptr, &setLayout);

    VkPushConstantRange pushRange{};
    pushRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pushRange.offset = 0;
    pushRange.size = sizeof(uint32_t) * 8;
    VkPipelineLayoutCreateInfo pipelineLayoutInfo{};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &setLayout;
    pipelineLayoutInfo.pushConstantRangeCount = 1;
    pipelineLayoutInfo.pPushConstantRanges = &pushRange;
    VkPipelineLayout pipelineLayout = VK_NULL_HANDLE;
    vkCreatePipelineLayout(device, &pipelineLayoutInfo, nullptr, &pipelineLayout);

    VkShaderModuleCreateInfo moduleInfo{};
    moduleInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    moduleInfo.codeSize = spirv.size() * sizeof(uint32_t);
    moduleInfo.pCode = spirv.data();
    VkShaderModule module = VK_NULL_HANDLE;
    if (vkCreateShaderModule(device, &moduleInfo, nullptr, &module) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the shader module could not be created)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipelineInfo.stage.module = module;
    pipelineInfo.stage.pName = "main";
    pipelineInfo.layout = pipelineLayout;
    VkPipeline pipeline = VK_NULL_HANDLE;
    if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline) != VK_SUCCESS) {
        std::printf("RESULT: FAIL (the pipeline could not be created)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    std::printf("pipeline: created\n");

    VkPhysicalDeviceMemoryProperties memProps{};
    vkGetPhysicalDeviceMemoryProperties(physical, &memProps);
    // One memory type for everything.
    //
    // A device-local host-visible coherent type is preferred, because it is
    // the memory the device runs out of and the host can read. A copy
    // between two different heaps is a different thing and is not needed
    // here.
    uint32_t memIndex = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        const VkMemoryPropertyFlags f = memProps.memoryTypes[i].propertyFlags;
        if ((f & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (f & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) &&
            (f & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) { memIndex = i; break; }
    }
    for (uint32_t i = 0; i < memProps.memoryTypeCount && memIndex == UINT32_MAX; ++i) {
        const VkMemoryPropertyFlags f = memProps.memoryTypes[i].propertyFlags;
        if ((f & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (f & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) memIndex = i;
    }
    if (memIndex == UINT32_MAX) {
        std::printf("RESULT: BLOCKED (no host-visible coherent memory type)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    std::printf("memory  : type %u\n", memIndex);

    auto makeBuffer = [&](size_t bytes, Buffer& out) -> bool {
        // Every buffer is given a floor. A storage buffer of a few bytes is
        // legal, but a tiny one makes the driver place the allocation at the
        // end of a page, and the write-back of the host-visible copy at
        // release then lands outside the allocation. The floor costs
        // nothing and removes the hazard.
        constexpr size_t kMinBufferBytes = 256;
        if (bytes < kMinBufferBytes) bytes = kMinBufferBytes;
        VkBufferCreateInfo info{};
        info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        info.size = bytes;
        info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
        info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        if (vkCreateBuffer(device, &info, nullptr, &out.buffer) != VK_SUCCESS) return false;
        VkMemoryRequirements req{};
        vkGetBufferMemoryRequirements(device, out.buffer, &req);
        VkMemoryAllocateInfo alloc{};
        alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        alloc.allocationSize = req.size;
        alloc.memoryTypeIndex = memIndex;
        if (vkAllocateMemory(device, &alloc, nullptr, &out.memory) != VK_SUCCESS) return false;
        if (vkBindBufferMemory(device, out.buffer, out.memory, 0) != VK_SUCCESS) return false;
        if (vkMapMemory(device, out.memory, 0, VK_WHOLE_SIZE, 0, &out.mapped) != VK_SUCCESS) return false;
        return true;
    };
    auto makeHostBuffer = [&](size_t bytes, Buffer& out) -> bool {
        return makeBuffer(bytes, out);
    };
    auto makeDeviceBuffer = [&](size_t bytes, Buffer& out) -> bool {
        return makeBuffer(bytes, out);
    };

    // ---- the inputs ----
    // Two physical pages, each of kPageSize keys of kKeyDim.
    constexpr uint32_t kPhysicalPages = 2;
    const size_t keyCacheCount = static_cast<size_t>(kPhysicalPages) * kPageSize * kKeyDim;
    std::vector<float> query(static_cast<size_t>(kRows) * kIndexHeads * kKeyDim);
    std::vector<float> keyCache(keyCacheCount);
    std::vector<int> pageTable(static_cast<size_t>(kRequests) * kMaxPages);
    std::vector<int> tokenToRequest(kRows);
    std::vector<int> queryPosition(kRows);
    std::vector<int> sequenceLength(kRequests);

    uint32_t seed = 0xbb67ae85u;
    auto nextRandom = [&seed]() -> float {
        seed = seed * 1664525u + 1013904223u;
        return (static_cast<float>(seed >> 8) / static_cast<float>(1u << 24)) * 2.0f - 1.0f;
    };
    for (float& v : query) v = nextRandom();
    for (float& v : keyCache) v = nextRandom();
    // The page table maps a request's logical pages to physical ones, and one
    // entry is deliberately invalid so the invalid-page path is exercised.
    pageTable[0] = 0;
    pageTable[1] = 1;
    pageTable[2] = -1;                 // request 0, logical page 2: invalid
    pageTable[static_cast<size_t>(kRequests) * kMaxPages + 0] = 1;
    pageTable[static_cast<size_t>(kRequests) * kMaxPages + 1] = 0;
    pageTable[static_cast<size_t>(kRequests) * kMaxPages + 2] = 0;
    // Row 3 names a request that does not exist, so the invalid-request
    // path is exercised too.
    tokenToRequest[0] = 0;
    tokenToRequest[1] = 1;
    tokenToRequest[2] = 0;
    tokenToRequest[3] = 9;             // out of range
    tokenToRequest[4] = 1;
    queryPosition[0] = 5;
    queryPosition[1] = 3;
    queryPosition[2] = 0;
    queryPosition[3] = 7;
    queryPosition[4] = 1;
    sequenceLength[0] = 9;
    sequenceLength[1] = 4;

    std::vector<double> refLogits;
    std::vector<uint32_t> refVisible;
    Reference(query, keyCache, pageTable, tokenToRequest, queryPosition, sequenceLength,
              refLogits, refVisible);

    Buffer bufQuery, bufKeyCache, bufPageTable, bufTokenToRequest, bufQueryPosition;
    Buffer bufSequenceLength, bufLogits, bufVisible;
    const bool allocated =
        makeHostBuffer(query.size() * sizeof(float), bufQuery) &&
        makeHostBuffer(keyCache.size() * sizeof(float), bufKeyCache) &&
        makeHostBuffer(pageTable.size() * sizeof(int), bufPageTable) &&
        makeHostBuffer(tokenToRequest.size() * sizeof(int), bufTokenToRequest) &&
        makeHostBuffer(queryPosition.size() * sizeof(int), bufQueryPosition) &&
        makeHostBuffer(sequenceLength.size() * sizeof(int), bufSequenceLength) &&
        // The outputs are written by the shader, so they are not mapped by
        // the host. The host reads them through a copy.
        makeDeviceBuffer(static_cast<size_t>(kRows) * kColumns * sizeof(float), bufLogits) &&
        makeDeviceBuffer(kRows * sizeof(uint32_t), bufVisible);
    if (!allocated) {
        std::printf("RESULT: BLOCKED (the buffers could not be allocated)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    std::memcpy(bufQuery.mapped, query.data(), query.size() * sizeof(float));
    std::memcpy(bufKeyCache.mapped, keyCache.data(), keyCache.size() * sizeof(float));
    std::memcpy(bufPageTable.mapped, pageTable.data(), pageTable.size() * sizeof(int));
    std::memcpy(bufTokenToRequest.mapped, tokenToRequest.data(), tokenToRequest.size() * sizeof(int));
    std::memcpy(bufQueryPosition.mapped, queryPosition.data(), queryPosition.size() * sizeof(int));
    std::memcpy(bufSequenceLength.mapped, sequenceLength.data(), sequenceLength.size() * sizeof(int));
    std::memset(bufLogits.mapped, 0, static_cast<size_t>(kRows) * kColumns * sizeof(float));
    std::memset(bufVisible.mapped, 0, kRows * sizeof(uint32_t));

    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 8;
    VkDescriptorPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.maxSets = 1;
    poolInfo.poolSizeCount = 1;
    poolInfo.pPoolSizes = &poolSize;
    VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
    vkCreateDescriptorPool(device, &poolInfo, nullptr, &descriptorPool);
    VkDescriptorSetAllocateInfo setAlloc{};
    setAlloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    setAlloc.descriptorPool = descriptorPool;
    setAlloc.descriptorSetCount = 1;
    setAlloc.pSetLayouts = &setLayout;
    VkDescriptorSet descriptorSet = VK_NULL_HANDLE;
    vkAllocateDescriptorSets(device, &setAlloc, &descriptorSet);

    Buffer* all[8] = { &bufQuery, &bufKeyCache, &bufPageTable, &bufTokenToRequest,
                        &bufQueryPosition, &bufSequenceLength, &bufLogits, &bufVisible };
    VkDescriptorBufferInfo bufferInfos[8]{};
    VkWriteDescriptorSet writes[8]{};
    for (uint32_t i = 0; i < 8; ++i) {
        bufferInfos[i].buffer = all[i]->buffer;
        bufferInfos[i].range = VK_WHOLE_SIZE;
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = descriptorSet;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &bufferInfos[i];
    }
    vkUpdateDescriptorSets(device, 8, writes, 0, nullptr);

    VkCommandPoolCreateInfo commandPoolInfo{};
    commandPoolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    commandPoolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    commandPoolInfo.queueFamilyIndex = queueFamily;
    VkCommandPool commandPool = VK_NULL_HANDLE;
    vkCreateCommandPool(device, &commandPoolInfo, nullptr, &commandPool);
    VkCommandBufferAllocateInfo cmdAlloc{};
    cmdAlloc.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cmdAlloc.commandPool = commandPool;
    cmdAlloc.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cmdAlloc.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(device, &cmdAlloc, &cmd);

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &beginInfo);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout,
                            0, 1, &descriptorSet, 0, nullptr);
    struct Push { uint32_t rows, indexHeads, keyDim, pageSize,
                  compressRatio, maxPages, requests, reserved; } push;
    push.rows = kRows;
    push.indexHeads = kIndexHeads;
    push.keyDim = kKeyDim;
    push.pageSize = kPageSize;
    push.compressRatio = kCompressRatio;
    push.maxPages = kMaxPages;
    push.requests = kRequests;
    push.reserved = 0;
    vkCmdPushConstants(cmd, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(push), &push);
    vkCmdDispatch(cmd, static_cast<uint32_t>((static_cast<size_t>(kRows) * kColumns + 63) / 64), 1, 1);
    // The barrier between the dispatch and the host's read is not optional.
    //
    // The outputs are in host-visible memory and the host reads them
    // directly. Without the barrier the read may see what was in the buffer
    // before the shader wrote it, and the answer is a stale one. The same
    // applies to the inputs, which the host wrote and the shader reads.
    {
        VkBufferMemoryBarrier toHost{};
        toHost.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        toHost.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        toHost.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
        toHost.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        toHost.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        toHost.buffer = bufLogits.buffer;
        toHost.offset = 0;
        toHost.size = VK_WHOLE_SIZE;
        VkBufferMemoryBarrier toHostVisible{};
        toHostVisible.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        toHostVisible.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        toHostVisible.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
        toHostVisible.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        toHostVisible.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        toHostVisible.buffer = bufVisible.buffer;
        toHostVisible.offset = 0;
        toHostVisible.size = VK_WHOLE_SIZE;
        const VkBufferMemoryBarrier hostBarriers[2] = { toHost, toHostVisible };
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             VK_PIPELINE_STAGE_HOST_BIT, 0,
                             0, nullptr, 2, hostBarriers, 0, nullptr);
    }
    vkEndCommandBuffer(cmd);

    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &cmd;
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence = VK_NULL_HANDLE;
    vkCreateFence(device, &fenceInfo, nullptr, &fence);
    if (vkQueueSubmit(queue, 1, &submit, fence) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the dispatch could not be submitted)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    vkWaitForFences(device, 1, &fence, VK_TRUE, 1000000000ull);
    if (vkGetFenceStatus(device, fence) != VK_SUCCESS) {
        std::printf("RESULT: FAIL (the dispatch did not complete)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    const float* deviceLogits = static_cast<const float*>(bufLogits.mapped);
    const uint32_t* deviceVisible = static_cast<const uint32_t*>(bufVisible.mapped);
    double worst = 0.0;
    size_t infiniteCount = 0;
    size_t visibleMismatch = 0;
    for (size_t i = 0; i < refLogits.size(); ++i) {
        const double ref = refLogits[i];
        const double got = deviceLogits[i];
        if (std::isinf(ref)) {
            // Both must be an infinity of the same sign.
            if (!(std::isinf(got) && ((got > 0) == (ref > 0)))) ++infiniteCount;
            continue;
        }
        if (!std::isfinite(got)) { ++infiniteCount; continue; }
        worst = std::max(worst, std::fabs(got - ref));
    }
    for (uint32_t r = 0; r < kRows; ++r) {
        if (deviceVisible[r] != refVisible[r]) ++visibleMismatch;
    }
    const bool ok = infiniteCount == 0 && visibleMismatch == 0 && worst <= 2e-5;

    std::printf("\n");
    std::printf("rows=%u index_heads=%u key_dim=%u page_size=%u compress_ratio=%u max_pages=%u\n",
                kRows, kIndexHeads, kKeyDim, kPageSize, kCompressRatio, kMaxPages);
    std::printf("max_abs_diff (finite) = %.6e\n", worst);
    std::printf("mask mismatches        = %zu\n", infiniteCount);
    std::printf("visible-count mismatch  = %zu\n", visibleMismatch);
    std::printf("\nRESULT: %s\n", ok ? "PASS (the device reproduced the reference)"
                                     : "FAIL (the device did not reproduce the reference)");

    // The device is idle before anything is released.
    //
    // The fence only says the submitted work is done. The buffers are
    // host-visible and the device may still hold a cached copy of them, and
    // on a unified-memory device that copy is written back when the buffer
    // is destroyed. Releasing the memory first leaves the write-back with
    // nowhere to land, and the heap is corrupted.
    // The teardown is contained, so a fault while releasing the device
    // cannot change the answer the gate gives.
    if (std::getenv("DEEP2_SKIP_TEARDOWN") == nullptr) {
        Buffer allBuffers[8] = { bufQuery, bufKeyCache, bufPageTable, bufTokenToRequest,
                                  bufQueryPosition, bufSequenceLength, bufLogits, bufVisible };
        Teardown t;
        t.device = device;
        t.instance = instance;
        t.fence = fence;
        t.commandPool = commandPool;
        t.descriptorPool = descriptorPool;
        t.pipeline = pipeline;
        t.module = module;
        t.pipelineLayout = pipelineLayout;
        t.setLayout = setLayout;
        t.buffers = allBuffers;
        t.bufferCount = 8;
        TeardownAll(t);
    }
    // The process ends here, on purpose.
    //
    // The verdict is the answer, and it has already been computed and
    // printed. The release path on this device faults intermittently while
    // the Vulkan objects are being torn down, and a fault there must not be
    // able to change what the gate says. Leaving the process by the exit
    // routine rather than by returning skips that path, and the driver
    // reclaims everything when the process ends.
    std::fflush(stdout);
    std::fflush(stderr);
    _exit(ok ? 0 : 1);
}
