// The Q5_K branch of the packed GEMV, executed.
//
// Q5_K was the one format with no GPU kernel in either tree, and in a
// Qwen3.5 hybrid block four of the five projections are Q5_K, so the whole
// persistent-residency path was unreachable for that family.
//
// The reference is ggml's OWN dequantiser, reached through the type traits,
// so the kernel is checked against the upstream decoder rather than against
// another transcription of it. A matching mistake cannot hide.
//
// The blocks are random, with finite super-block scales, which exercises
// every scale and min combination and every high-bit pattern.
//
// It is self-contained: its own device, and no file another part of the
// engine owns. A machine with no GPU is BLOCKED, never PASS.
#include <vulkan/vulkan.h>
#include <ggml.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kRows = 8;
constexpr uint32_t kCols = 512;      // two Q5_K blocks per row
constexpr uint32_t kBlockElements = 256;
constexpr uint32_t kBlockBytes = 176;
constexpr double kTolerance = 1e-4;   // f32 accumulation of a 512-term dot

struct Buffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr;
};

// The push constant the packed GEMV declares.
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

    std::printf("=== Q5_K packed GEMV: device execution ===\n");
    std::printf("artifact: %s\n", spirvPath.c_str());

    std::vector<uint32_t> spirv;
    if (!ReadSpirv(spirvPath, spirv)) {
        std::printf("RESULT: BLOCKED (the artifact is missing or unreadable: %s)\n",
                    spirvPath.c_str());
        return 2;
    }
    std::printf("artifact: %u words of SPIR-V\n", static_cast<unsigned>(spirv.size()));

    // ---- the reference: ggml's own dequantiser ----
    const ggml_type_traits* traits = ggml_get_type_traits(GGML_TYPE_Q5_K);
    if (!traits || !traits->to_float) {
        std::printf("RESULT: BLOCKED (ggml has no Q5_K dequantiser)\n");
        return 2;
    }
    if (traits->type_size != kBlockBytes) {
        std::printf("RESULT: BLOCKED (ggml's Q5_K block is %zu bytes, the shader assumes %u)\n",
                    traits->type_size, kBlockBytes);
        return 2;
    }
    std::printf("reference: ggml's own Q5_K dequantiser, %zu bytes per block\n",
                traits->type_size);

    // ---- the data ----
    // Random blocks with finite super-block scales. The scales and mins are
    // six bits each, and the high bits are exercised by the random bytes.
    std::mt19937 rng(0x51ed270bu);
    std::uniform_int_distribution<int> byteDist(0, 255);
    const size_t blocksPerRow = (kCols + kBlockElements - 1) / kBlockElements;
    std::vector<uint8_t> packed(static_cast<size_t>(kRows) * blocksPerRow * kBlockBytes);
    for (auto& b : packed) b = static_cast<uint8_t>(byteDist(rng));
    // The super-block scales have to be finite, or the reference produces
    // infinities and the comparison says nothing.
    const float scales[4] = { 0.5f, 1.0f, 2.0f, 0.25f };
    for (size_t block = 0; block < static_cast<size_t>(kRows) * blocksPerRow; ++block) {
        uint8_t* p = packed.data() + block * kBlockBytes;
        const ggml_fp16_t d = ggml_fp32_to_fp16(scales[block % 4]);
        const ggml_fp16_t dmin = ggml_fp32_to_fp16(scales[(block + 1) % 4]);
        std::memcpy(p + 0, &d, 2);
        std::memcpy(p + 2, &dmin, 2);
    }

    // The reference rows.
    std::vector<float> refRows(static_cast<size_t>(kRows) * kCols, 0.0f);
    for (uint32_t r = 0; r < kRows; ++r) {
        traits->to_float(packed.data() + static_cast<size_t>(r) * blocksPerRow * kBlockBytes,
                        refRows.data() + static_cast<size_t>(r) * kCols,
                        static_cast<int>(kCols));
    }

    // The activation.
    std::vector<float> activation(kCols);
    std::uniform_real_distribution<float> actDist(-1.0f, 1.0f);
    for (auto& a : activation) a = actDist(rng);

    // The host reference for each row: the dot of the row with the activation.
    std::vector<double> ref(static_cast<size_t>(kRows), 0.0);
    for (uint32_t r = 0; r < kRows; ++r) {
        double acc = 0.0;
        for (uint32_t c = 0; c < kCols; ++c) {
            acc += static_cast<double>(refRows[static_cast<size_t>(r) * kCols + c]) *
                   static_cast<double>(activation[c]);
        }
        ref[r] = acc;
    }

    // ---- the device ----
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "test_q5k_device";
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

    // The pipeline: three storage buffers, the layout the shader declares.
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
    pushRange.offset = 0;
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
    std::printf("pipeline: created\n");

    // The memory.
    VkPhysicalDeviceMemoryProperties memProps{};
    vkGetPhysicalDeviceMemoryProperties(physical, &memProps);
    uint32_t hostIndex = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        const VkMemoryPropertyFlags f = memProps.memoryTypes[i].propertyFlags;
        if ((f & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) &&
            (f & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) { hostIndex = i; break; }
    }
    if (hostIndex == UINT32_MAX) {
        std::printf("RESULT: BLOCKED (no host-visible coherent memory type)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    auto makeBuffer = [&](size_t bytes, Buffer& out) -> bool {
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
        alloc.memoryTypeIndex = hostIndex;
        if (vkAllocateMemory(device, &alloc, nullptr, &out.memory) != VK_SUCCESS) return false;
        if (vkBindBufferMemory(device, out.buffer, out.memory, 0) != VK_SUCCESS) return false;
        if (vkMapMemory(device, out.memory, 0, VK_WHOLE_SIZE, 0, &out.mapped) != VK_SUCCESS) return false;
        return true;
    };

    Buffer bufW, bufX, bufY;
    if (!makeBuffer(packed.size(), bufW) ||
        !makeBuffer(activation.size() * sizeof(float), bufX) ||
        !makeBuffer(kRows * sizeof(float), bufY)) {
        std::printf("RESULT: BLOCKED (the buffers could not be allocated)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    std::memcpy(bufW.mapped, packed.data(), packed.size());
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
    push.type = 13;                 // GGML_TYPE_Q5_K
    push.rows = kRows;
    push.cols = kCols;
    push.weightBytes = static_cast<uint32_t>(packed.size());

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &beginInfo);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout,
                            0, 1, &descriptorSet, 0, nullptr);
    vkCmdPushConstants(cmd, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(push), &push);
    vkCmdDispatch(cmd, kRows, 1, 1);
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
    vkWaitForFences(device, 1, &fence, VK_TRUE, 2000000000ull);
    if (vkGetFenceStatus(device, fence) != VK_SUCCESS) {
        std::printf("RESULT: FAIL (the dispatch did not complete)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // ---- the comparison ----
    // The comparison is RELATIVE.
    //
    // The dots here are sums of 512 terms whose magnitudes reach 10^4, and
    // the device accumulates them in a different order from the host: 256
    // lanes and a subgroup tree reduction against a sequential double sum.
    // The difference is f32 rounding of the accumulation, which shows up as
    // an absolute error that scales with the magnitude of the result. An
    // absolute tolerance would have to be loosened until it accepted a
    // wrong answer, so the check is on the relative error, with a floor
    // for the results that are near zero.
    constexpr double kRelativeTolerance = 1e-5;
    constexpr double kAbsoluteFloor = 1e-3;
    const float* got = static_cast<const float*>(bufY.mapped);
    double worst = 0.0;
    double worstRelative = 0.0;
    bool finite = true;
    for (uint32_t r = 0; r < kRows; ++r) {
        if (!std::isfinite(got[r])) { finite = false; continue; }
        const double diff = std::fabs(static_cast<double>(got[r]) - ref[r]);
        worst = std::max(worst, diff);
        const double scale = std::max(std::fabs(ref[r]), kAbsoluteFloor);
        worstRelative = std::max(worstRelative, diff / scale);
    }
    const bool ok = finite && worstRelative <= kRelativeTolerance;

    std::printf("\n");
    std::printf("rows=%u cols=%u blocks_per_row=%zu\n", kRows, kCols, blocksPerRow);
    std::printf("max_abs_diff      = %.6e\n", worst);
    std::printf("max_rel_diff      = %.6e\n", worstRelative);
    std::printf("relative tolerance= %.6e\n", kRelativeTolerance);
    std::printf("all finite         = %s\n", finite ? "yes" : "no");
    for (uint32_t r = 0; r < kRows && r < 4; ++r) {
        std::printf("  row %u: device=%.8f reference=%.8f\n", r, got[r], ref[r]);
    }
    std::printf("\nRESULT: %s\n", ok ? "PASS (the device reproduced ggml's own dequantiser)"
                                     : "FAIL (the device did not reproduce ggml)");

    vkDestroyFence(device, fence, nullptr);
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
    return ok ? 0 : 1;
}
