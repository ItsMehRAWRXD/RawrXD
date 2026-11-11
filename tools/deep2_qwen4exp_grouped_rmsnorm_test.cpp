// The Qwen4Exp grouped RMSNorm lowering, executed.
//
// The hyperconnection mix needs a per-stream RMSNorm before the down
// projection, and nothing in the tree provides one: the generic ops shader
// has OP_RMSNORM, which normalises over the whole row rather than over a
// stream of it.
//
// This runs the lowering on the device and compares it against a reference
// computed on the host in double precision. It is self-contained, it creates
// its own device, and it touches no file another part of the engine owns.
//
// A machine with no GPU is BLOCKED, never PASS.
#include <vulkan/vulkan.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kHcCount = 4;
constexpr uint32_t kHeadDim = 16;
constexpr uint32_t kTokens = 7;
constexpr float kEpsilon = 1e-5f;
constexpr double kTolerance = 2e-5;

struct Buffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr;
};

// The reference: each stream is normalised on its own, Gemma style.
//
// The scale is (1 + w), because that is what the reference's
// grouped_gemma_rmsnorm does, and the sum of squares is over the stream's
// slice rather than over the whole row, which is what makes it grouped.
void Reference(const std::vector<float>& x,
               const std::vector<float>& normWeight,
               std::vector<double>& y) {
    const size_t width = static_cast<size_t>(kHeadDim) * kHcCount;
    y.assign(static_cast<size_t>(kTokens) * width, 0.0);
    for (uint32_t t = 0; t < kTokens; ++t) {
        for (uint32_t s = 0; s < kHcCount; ++s) {
            double ss = 0.0;
            for (uint32_t j = 0; j < kHeadDim; ++j) {
                const double q = x[static_cast<size_t>(t) * width + s * kHeadDim + j];
                ss += q * q;
            }
            const double inv = 1.0 / std::sqrt(ss / static_cast<double>(kHeadDim) +
                                                static_cast<double>(kEpsilon));
            for (uint32_t col = 0; col < kHeadDim; ++col) {
                const size_t e = static_cast<size_t>(t) * width + s * kHeadDim + col;
                const double v = static_cast<double>(x[e]) * inv;
                y[e] = v + v * static_cast<double>(normWeight[col]);
            }
        }
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

} // namespace

int main(int argc, char** argv) {
    std::string spirvPath = "src/deep2/shaders/deep2_qwen4exp_grouped_rmsnorm.spv";
    if (argc >= 2) spirvPath = argv[1];

    std::printf("=== Qwen4Exp grouped RMSNorm: device execution ===\n");
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

    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "deep2_qwen4exp_grouped_rmsnorm_test";
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
    pushRange.size = sizeof(uint32_t) * 4 + sizeof(float);
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

    const size_t width = static_cast<size_t>(kHeadDim) * kHcCount;
    std::vector<float> x(static_cast<size_t>(kTokens) * width);
    std::vector<float> normWeight(kHeadDim);
    uint32_t seed = 0xb7e15162u;
    auto nextRandom = [&seed]() -> float {
        seed = seed * 1664525u + 1013904223u;
        return (static_cast<float>(seed >> 8) / static_cast<float>(1u << 24)) * 2.0f - 1.0f;
    };
    for (float& v : x) v = nextRandom();
    for (float& v : normWeight) v = nextRandom();

    std::vector<double> ref;
    Reference(x, normWeight, ref);

    Buffer bufX, bufNorm, bufY;
    const bool allocated =
        makeBuffer(x.size() * sizeof(float), bufX) &&
        makeBuffer(normWeight.size() * sizeof(float), bufNorm) &&
        makeBuffer(x.size() * sizeof(float), bufY);
    if (!allocated) {
        std::printf("RESULT: BLOCKED (the buffers could not be allocated)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    std::memcpy(bufX.mapped, x.data(), x.size() * sizeof(float));
    std::memcpy(bufNorm.mapped, normWeight.data(), normWeight.size() * sizeof(float));
    std::memset(bufY.mapped, 0, x.size() * sizeof(float));

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

    Buffer* all[3] = { &bufX, &bufNorm, &bufY };
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

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &beginInfo);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout,
                            0, 1, &descriptorSet, 0, nullptr);
    struct Push { uint32_t tokens, headDim, hcCount, reserved; float epsilon; } push;
    push.tokens = kTokens;
    push.headDim = kHeadDim;
    push.hcCount = kHcCount;
    push.reserved = 0;
    push.epsilon = kEpsilon;
    vkCmdPushConstants(cmd, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(push), &push);
    vkCmdDispatch(cmd, static_cast<uint32_t>((x.size() + 63) / 64), 1, 1);
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

    const float* deviceY = static_cast<const float*>(bufY.mapped);
    double worst = 0.0;
    bool finite = true;
    for (size_t i = 0; i < ref.size(); ++i) {
        if (!std::isfinite(deviceY[i])) finite = false;
        worst = std::max(worst, std::fabs(static_cast<double>(deviceY[i]) - ref[i]));
    }
    const bool ok = finite && worst <= kTolerance;

    std::printf("\n");
    std::printf("tokens=%u head_dim=%u hc_count=%u width=%zu\n", kTokens, kHeadDim, kHcCount, width);
    std::printf("max_abs_diff = %.6e\n", worst);
    std::printf("tolerance    = %.6e\n", kTolerance);
    std::printf("all finite   = %s\n", finite ? "yes" : "no");
    std::printf("\nRESULT: %s\n", ok ? "PASS (the device reproduced the reference)"
                                     : "FAIL (the device did not reproduce the reference)");

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
