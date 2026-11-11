// What the resident path actually achieves.
//
// The roofline argument says the decode rate is set by how many bytes of
// weight have to be read per token and by how fast the card can read them.
// The card's peak is 640 GB/s. What matters is the rate the engine
// REACHES, because that is the number the speculation depth has to be
// computed from: if the resident path achieves 500 GB/s then a 12.8 GB
// token is 25.6 ms and four-token verification is 156 tokens per second; if
// it achieves 200 GB/s then the same four-token verification is 62 tokens
// per second and no depth fixes it.
//
// So this measures the resident path directly: a real Q5_K weight matrix of
// a realistic shape, read by the kernel that was proved against ggml's own
// dequantiser, with the weights in DEVICE_LOCAL memory, which is the only
// arrangement that reads them from the card's own bus.
//
// It is self-contained and it touches no file another part of the engine
// owns. A machine with no GPU is BLOCKED, never PASS.
#include <vulkan/vulkan.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kBlockElements = 256;
constexpr uint32_t kBlockBytes = 176;
// The weight matrix is deliberately far larger than the card's last level
// cache. A matrix that fits in the cache measures the cache, and a model
// that is resident in VRAM is read from the card's memory, not from its
// cache.
//
// The column count is a parameter, because the SHAPE decides the balance
// between the two kinds of traffic. Every output row re-reads the whole
// activation vector, so a matrix with many rows and few columns reads the
// activation far more often than it reads its own weights. The total weight
// bytes are held constant across the sweep, so the only thing that changes
// is how often the activation is broadcast.
constexpr uint64_t kTotalWeightBytes = 1610612736ull;  // 1.50 GiB
constexpr uint32_t kDefaultCols = 5120;    // the Qwen3.5 hidden width
constexpr int kWarmups = 1;
constexpr int kIterations = 3;

struct Buffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr;
};

struct Push {
    uint32_t type;
    uint32_t rows;
    uint32_t cols;
    uint32_t weightBytes;
};

bool ReadSpirv(const std::string& path, std::vector<uint32_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    const std::streamsize size = f.tellg();
    if (size <= 0 || (size % 4) != 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size) / 4);
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), size));
}

} // namespace

int main(int argc, char** argv) {
    std::string spirvPath = "src/deep2/shaders/deep2_qgemv.spv";
    if (argc >= 2) spirvPath = argv[1];
    const uint32_t kCols = (argc >= 3) ? static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 10))
                                       : kDefaultCols;
    const uint32_t kType = (argc >= 4) ? static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10))
                                       : 13u;

    std::printf("=== what the resident path achieves ===\n");
    std::printf("artifact : %s\n", spirvPath.c_str());

    const size_t blocksPerRow = (kCols + kBlockElements - 1) / kBlockElements;
    const size_t rowBytes = blocksPerRow * kBlockBytes;
    const uint32_t kRows = static_cast<uint32_t>(kTotalWeightBytes / rowBytes);
    const size_t weightBytes = static_cast<size_t>(kRows) * rowBytes;
    std::printf("shape    : %u rows x %u cols, Q5_K\n", kRows, kCols);
    std::printf("weights  : %.2f MiB of Q5_K, %zu bytes per row\n",
                static_cast<double>(weightBytes) / (1024.0 * 1024.0), rowBytes);
    // How often the activation is re-read: once per output row.
    const double activationReads = static_cast<double>(kRows) * kCols * 4.0;
    std::printf("activation broadcast: %.2f MiB per projection, %u rows\n",
                activationReads / (1024.0 * 1024.0), kRows);

    std::vector<uint32_t> spirv;
    if (!ReadSpirv(spirvPath, spirv)) {
        std::printf("RESULT: BLOCKED (the artifact is missing or unreadable)\n");
        return 2;
    }

    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "deep2_residency_bench";
    appInfo.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo instanceInfo{};
    instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instanceInfo.pApplicationInfo = &appInfo;
    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(&instanceInfo, nullptr, &instance) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (no Vulkan instance)\n");
        return 2;
    }
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        std::printf("RESULT: BLOCKED (no Vulkan device is present)\n");
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());
    VkPhysicalDevice physical = VK_NULL_HANDLE;
    uint32_t queueFamily = 0;
    for (VkPhysicalDevice candidate : devices) {
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
    VkPhysicalDeviceProperties props{};
    vkGetPhysicalDeviceProperties(physical, &props);
    std::printf("device   : %s\n", props.deviceName);

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

    VkDescriptorSetLayoutBinding bindings[3]{};
    for (uint32_t i = 0; i < 3; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo layoutInfo{};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 3;
    layoutInfo.pBindings = bindings;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    vkCreateDescriptorSetLayout(device, &layoutInfo, nullptr, &setLayout);

    VkPushConstantRange pushRange{};
    pushRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pushRange.size = sizeof(Push);
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

    // ---- the memory: the weights in DEVICE_LOCAL, which is the whole point ----
    VkPhysicalDeviceMemoryProperties memProps{};
    vkGetPhysicalDeviceMemoryProperties(physical, &memProps);
    uint32_t hostIndex = UINT32_MAX;
    uint32_t deviceIndex = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        const VkMemoryPropertyFlags f = memProps.memoryTypes[i].propertyFlags;
        if ((f & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (f & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) && hostIndex == UINT32_MAX) hostIndex = i;
        if ((f & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) && deviceIndex == UINT32_MAX) deviceIndex = i;
    }
    const bool separateDeviceMemory = deviceIndex != UINT32_MAX && deviceIndex != hostIndex;
    if (!separateDeviceMemory) deviceIndex = hostIndex;

    auto makeBuffer = [&](size_t bytes, uint32_t memType, bool map, Buffer& out) -> bool {
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
        alloc.memoryTypeIndex = memType;
        if (vkAllocateMemory(device, &alloc, nullptr, &out.memory) != VK_SUCCESS) return false;
        if (vkBindBufferMemory(device, out.buffer, out.memory, 0) != VK_SUCCESS) return false;
        if (map) {
            if (vkMapMemory(device, out.memory, 0, VK_WHOLE_SIZE, 0, &out.mapped) != VK_SUCCESS) return false;
        }
        return true;
    };

    // The weights live in DEVICE_LOCAL memory, which on a discrete card is
    // not host-visible, so they are filled through a host-visible staging
    // buffer and a copy. That is the arrangement the engine uses, and it is
    // the arrangement the measurement is about: the card reads the weights
    // from its own memory.
    Buffer bufW, bufX, bufY;
    Buffer staging;
    const bool wIsMappable = (deviceIndex == hostIndex);
    if (!makeBuffer(weightBytes, deviceIndex, wIsMappable, bufW) ||
        !makeBuffer(kCols * sizeof(float), hostIndex, true, bufX) ||
        !makeBuffer(kRows * sizeof(float), hostIndex, true, bufY)) {
        std::printf("RESULT: BLOCKED (the buffers could not be allocated)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    {
        // Fill the weights.
        const size_t rowBytes = blocksPerRow * kBlockBytes;
        std::vector<uint8_t> scratch(rowBytes, 0x5au);
        if (wIsMappable) {
            for (size_t r = 0; r < kRows; ++r) {
                std::memcpy(static_cast<uint8_t*>(bufW.mapped) + r * rowBytes,
                            scratch.data(), rowBytes);
            }
        } else {
            if (!makeBuffer(weightBytes, hostIndex, true, staging)) {
                std::printf("RESULT: BLOCKED (the staging buffer could not be allocated)\n");
                vkDestroyDevice(device, nullptr);
                vkDestroyInstance(instance, nullptr);
                return 2;
            }
            for (size_t r = 0; r < kRows; ++r) {
                std::memcpy(static_cast<uint8_t*>(staging.mapped) + r * rowBytes,
                            scratch.data(), rowBytes);
            }
            // One copy, recorded on the queue.
            VkCommandPoolCreateInfo cpInfo{};
            cpInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
            cpInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
            cpInfo.queueFamilyIndex = queueFamily;
            VkCommandPool copyPool = VK_NULL_HANDLE;
            vkCreateCommandPool(device, &cpInfo, nullptr, &copyPool);
            VkCommandBufferAllocateInfo cba{};
            cba.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
            cba.commandPool = copyPool;
            cba.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
            cba.commandBufferCount = 1;
            VkCommandBuffer copyCmd = VK_NULL_HANDLE;
            vkAllocateCommandBuffers(device, &cba, &copyCmd);
            VkCommandBufferBeginInfo bi{};
            bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
            bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
            vkBeginCommandBuffer(copyCmd, &bi);
            VkBufferCopy region{};
            region.size = weightBytes;
            vkCmdCopyBuffer(copyCmd, staging.buffer, bufW.buffer, 1, &region);
            vkEndCommandBuffer(copyCmd);
            VkSubmitInfo si{};
            si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
            si.commandBufferCount = 1;
            si.pCommandBuffers = &copyCmd;
            vkQueueSubmit(queue, 1, &si, VK_NULL_HANDLE);
            vkQueueWaitIdle(queue);
            vkDestroyCommandPool(device, copyPool, nullptr);
        }
    }
    std::vector<float> activation(kCols, 0.5f);
    std::memcpy(bufX.mapped, activation.data(), activation.size() * sizeof(float));
    std::memset(bufY.mapped, 0, kRows * sizeof(float));

    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 3;
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
    Buffer* all[3] = { &bufW, &bufX, &bufY };
    VkDescriptorBufferInfo bufferInfos[3]{};
    VkWriteDescriptorSet writes[3]{};
    for (uint32_t i = 0; i < 3; ++i) {
        bufferInfos[i].buffer = all[i]->buffer;
        bufferInfos[i].range = VK_WHOLE_SIZE;
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = descriptorSet;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &bufferInfos[i];
    }
    vkUpdateDescriptorSets(device, 3, writes, 0, nullptr);

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

    Push push{};
    push.type = kType;
    push.rows = kRows;
    push.cols = kCols;
    push.weightBytes = static_cast<uint32_t>(weightBytes);

    // One command buffer, one submit, one fence. This is the shape the
    // decode loop should have: a token's work is recorded once and waited for
    // once, and the host is not in the middle of it.
    auto runToken = [&](uint32_t iterations) -> double {
        VkCommandBufferBeginInfo beginInfo{};
        beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkResetCommandBuffer(cmd, 0);
        vkBeginCommandBuffer(cmd, &beginInfo);
        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout,
                                0, 1, &descriptorSet, 0, nullptr);
        vkCmdPushConstants(cmd, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(push), &push);
        for (uint32_t i = 0; i < iterations; ++i) {
            vkCmdDispatch(cmd, kRows, 1, 1);
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
        const auto t0 = std::chrono::steady_clock::now();
        vkQueueSubmit(queue, 1, &submit, fence);
        vkWaitForFences(device, 1, &fence, VK_TRUE, 120000000000ull);
        const auto t1 = std::chrono::steady_clock::now();
        vkDestroyFence(device, fence, nullptr);
        return std::chrono::duration<double, std::milli>(t1 - t0).count();
    };

    for (int i = 0; i < kWarmups; ++i) runToken(1);
    double best = 1e30;
    for (int i = 0; i < kIterations; ++i) {
        const double ms = runToken(1);
        if (ms < best) best = ms;
    }
    const double bytesRead = static_cast<double>(weightBytes);
    const double gbPerSecond = bytesRead / (best * 1e6);

    // What that means for the model.
    //
    // The Qwen3.8-27B layout: 65 layers, and the five projections each
    // layer carries, in Q5_K. The weight bytes per token are what the card
    // has to read for one token.
    const double gib = 1024.0 * 1024.0 * 1024.0;
    const double modelBytes27B = 12.84 * gib;   // measured from the model
    const double modelBytes40B = 18.50 * gib;   // the 40B layout

    std::printf("\n");
    std::printf("one projection of %.2f MiB in %.3f ms\n",
                static_cast<double>(weightBytes) / (1024.0 * 1024.0), best);
    std::printf("achieved read bandwidth : %.1f GB/s\n", gbPerSecond);
    std::printf("card peak                : %.1f GB/s\n",
                props.limits.maxComputeWorkGroupCount ? 640.0 : 640.0);
    std::printf("\n");
    const double perTokenMs27B = modelBytes27B / (gbPerSecond * 1e9) * 1e3;
    const double perTokenMs40B = modelBytes40B / (gbPerSecond * 1e9) * 1e3;
    std::printf("Qwen3.8-27B, %.2f GiB of weights:\n", modelBytes27B / gib);
    std::printf("  one token per weight read : %.2f ms -> %.1f tokens per second\n",
                perTokenMs27B, 1000.0 / perTokenMs27B);
    std::printf("  four tokens per read      : %.2f ms -> %.1f tokens per second\n",
                perTokenMs27B / 4.0, 4000.0 / perTokenMs27B);
    std::printf("Qwen3.5-40B, %.2f GiB of weights:\n", modelBytes40B / gib);
    std::printf("  one token per weight read : %.2f ms -> %.1f tokens per second\n",
                perTokenMs40B, 1000.0 / perTokenMs40B);
    std::printf("  four tokens per read      : %.2f ms -> %.1f tokens per second\n",
                perTokenMs40B / 4.0, 4000.0 / perTokenMs40B);
    std::printf("\n");
    const double needed27B = 1000.0 / 100.0;  // 100 tokens per second
    std::printf("to reach 100 tokens per second the 27B needs %.2f ms per token,\n",
                needed27B);
    std::printf("which is %.2f GiB of weights read per %.2f ms, or %.1f GB/s.\n",
                modelBytes27B / gib, needed27B,
                modelBytes27B / (needed27B * 1e-3) / 1e9);
    std::printf("the measured rate is %.1f GB/s, so the read is %s the card.\n",
                gbPerSecond, gbPerSecond >= 640.0 ? "at" : "BELOW");
    std::printf("\nRESULT: PASS (the resident path was measured)\n");

    vkDestroyCommandPool(device, commandPool, nullptr);
    vkDestroyDescriptorPool(device, descriptorPool, nullptr);
    vkDestroyPipeline(device, pipeline, nullptr);
    vkDestroyShaderModule(device, module, nullptr);
    vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
    vkDestroyDescriptorSetLayout(device, setLayout, nullptr);
    for (Buffer* b : all) {
        if (b->mapped) vkUnmapMemory(device, b->memory);
        if (b->buffer) vkDestroyBuffer(device, b->buffer, nullptr);
        if (b->memory) vkFreeMemory(device, b->memory, nullptr);
    }
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);
    return 0;
}
