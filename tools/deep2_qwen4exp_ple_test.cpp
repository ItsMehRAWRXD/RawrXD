// The Qwen4Exp PLE short-convolution lowering, executed.
//
// Like the hyperconnection combine, this artifact has been compiled and
// statically checked and has never been run. The causal state carry is
// exactly the kind of thing a static check cannot speak to: the shader
// reads a history window that spans the boundary between two dispatches,
// and only running it shows whether the window is the right one.
//
// The test runs two dispatches in a row. The first starts from a cold state
// and the second starts from the state the first produced, so the carry is
// exercised rather than assumed. The reference is computed on the host in
// double precision, from the causal definition, independently of the
// shader.
//
// It is self-contained: its own device, and no file another part of the
// engine owns. A machine with no GPU is BLOCKED, never PASS.
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

constexpr uint32_t kKernel = 4;
constexpr uint32_t kChannels = 8;
constexpr uint32_t kTokens1 = 6;   // the first dispatch
constexpr uint32_t kTokens2 = 3;   // the second, which leans on the carry

struct Buffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr;
};

// The causal depthwise short convolution, with a carried history.
//
// The history window is the kernel-1 samples immediately before the
// dispatch, oldest first. The sample at relative offset -(kernel-1-tap)
// before the dispatch start is therefore history[kernel-1-tap], and a
// sample at or after the start is x[token + offset].
//
// The output is silu of the weighted sum, and the carry is the last
// kernel-1 samples of the input.
void Reference(const std::vector<double>& x,
               const std::vector<double>& w,
               const std::vector<double>& history,
               uint32_t tokens,
               std::vector<double>& y,
               std::vector<double>& historyOut) {
    y.assign(static_cast<size_t>(tokens) * kChannels, 0.0);
    historyOut.assign(static_cast<size_t>(kKernel - 1) * kChannels, 0.0);

    for (uint32_t token = 0; token < tokens; ++token) {
        for (uint32_t channel = 0; channel < kChannels; ++channel) {
            double acc = 0.0;
            for (uint32_t tap = 0; tap < kKernel; ++tap) {
                const int offset = -static_cast<int>(kKernel - 1 - tap);
                const int index = static_cast<int>(token) + offset;
                double sample;
                if (index < 0) {
                    // Before the dispatch started: the carried history.
                    // The state holds the kernel-1 samples immediately before
                    // the dispatch, oldest first, so the sample at offset
                    // tap-(kernel-1) is the tap-th slot.
                    sample = history[static_cast<size_t>(tap) * kChannels + channel];
                } else {
                    sample = x[static_cast<size_t>(index) * kChannels + channel];
                }
                acc += sample * w[static_cast<size_t>(tap) * kChannels + channel];
            }
            y[static_cast<size_t>(token) * kChannels + channel] =
                acc / (1.0 + std::exp(-acc));
        }
    }

    // The carry: the last kernel-1 samples of the input.
    for (uint32_t tap = 0; tap + 1 < kKernel; ++tap) {
        for (uint32_t channel = 0; channel < kChannels; ++channel) {
            const long long index = static_cast<long long>(tokens) -
                                    static_cast<long long>(kKernel - 1) + tap;
            double sample;
            if (index >= 0 && index < static_cast<long long>(tokens)) {
                sample = x[static_cast<size_t>(index) * kChannels + channel];
            } else {
                // The dispatch was shorter than the window: take the carry
                // from the history the same way the shader does.
                sample = history[static_cast<size_t>(tap) * kChannels + channel];
            }
            historyOut[static_cast<size_t>(tap) * kChannels + channel] = sample;
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
    std::string spirvPath = "src/deep2/shaders/deep2_qwen4exp_ple.spv";
    if (argc >= 2) spirvPath = argv[1];

    std::printf("=== Qwen4Exp PLE short convolution: device execution ===\n");
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
    appInfo.pApplicationName = "deep2_qwen4exp_ple_test";
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

    // ---- the pipeline ----
    VkDescriptorSetLayoutBinding bindings[5]{};
    for (uint32_t i = 0; i < 5; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo layoutInfo{};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 5;
    layoutInfo.pBindings = bindings;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    vkCreateDescriptorSetLayout(device, &layoutInfo, nullptr, &setLayout);

    VkPushConstantRange pushRange{};
    pushRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pushRange.offset = 0;
    pushRange.size = sizeof(uint32_t) * 4;
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

    // ---- the memory ----
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

    // ---- the inputs ----
    std::vector<double> x1(kTokens1 * kChannels), w(kKernel * kChannels);
    std::vector<double> x2(kTokens2 * kChannels);
    std::vector<double> coldState((kKernel - 1) * kChannels, 0.0);
    uint32_t seed = 0x243f6a88u;
    auto nextRandom = [&seed]() -> double {
        seed = seed * 1664525u + 1013904223u;
        return (static_cast<double>(seed >> 8) / static_cast<double>(1u << 24)) * 2.0 - 1.0;
    };
    for (double& v : x1) v = nextRandom();
    for (double& v : w) v = nextRandom();
    for (double& v : x2) v = nextRandom();

    std::vector<double> refY1, refH1, refY2, refH2;
    Reference(x1, w, coldState, kTokens1, refY1, refH1);
    Reference(x2, w, refH1, kTokens2, refY2, refH2);

    Buffer bufX, bufW, bufState, bufY, bufStateOut;
    const bool allocated =
        makeBuffer(std::max(x1.size(), x2.size()) * sizeof(float), bufX) &&
        makeBuffer(w.size() * sizeof(float), bufW) &&
        makeBuffer(coldState.size() * sizeof(float), bufState) &&
        makeBuffer(std::max(x1.size(), x2.size()) * sizeof(float), bufY) &&
        makeBuffer(coldState.size() * sizeof(float), bufStateOut);
    if (!allocated) {
        std::printf("RESULT: BLOCKED (the buffers could not be allocated)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }

    // ---- the descriptor set ----
    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 5;
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

    Buffer* all[5] = { &bufX, &bufW, &bufState, &bufY, &bufStateOut };
    VkDescriptorBufferInfo bufferInfos[5]{};
    VkWriteDescriptorSet writes[5]{};
    for (uint32_t i = 0; i < 5; ++i) {
        bufferInfos[i].buffer = all[i]->buffer;
        bufferInfos[i].range = VK_WHOLE_SIZE;
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = descriptorSet;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &bufferInfos[i];
    }
    vkUpdateDescriptorSets(device, 5, writes, 0, nullptr);

    // ---- the command pool ----
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
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence = VK_NULL_HANDLE;
    vkCreateFence(device, &fenceInfo, nullptr, &fence);

    // One dispatch, and the bytes it produced.
    auto runDispatch = [&](const std::vector<double>& x, uint32_t tokens) -> bool {
        std::vector<float> xf(x.begin(), x.end());
        std::memcpy(bufX.mapped, xf.data(), xf.size() * sizeof(float));
        std::memset(bufY.mapped, 0, xf.size() * sizeof(float));

        VkCommandBufferBeginInfo beginInfo{};
        beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkResetCommandBuffer(cmd, 0);
        vkBeginCommandBuffer(cmd, &beginInfo);
        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout,
                                0, 1, &descriptorSet, 0, nullptr);
        struct Push { uint32_t tokens, channels, kernel, reserved; } push;
        push.tokens = tokens;
        push.channels = kChannels;
        push.kernel = kKernel;
        push.reserved = 0;
        vkCmdPushConstants(cmd, pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(push), &push);
        vkCmdDispatch(cmd, static_cast<uint32_t>((tokens * kChannels + 63) / 64), 1, 1);
        vkEndCommandBuffer(cmd);

        VkSubmitInfo submit{};
        submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit.commandBufferCount = 1;
        submit.pCommandBuffers = &cmd;
        vkResetFences(device, 1, &fence);
        if (vkQueueSubmit(queue, 1, &submit, fence) != VK_SUCCESS) return false;
        vkWaitForFences(device, 1, &fence, VK_TRUE, 1000000000ull);
        return vkGetFenceStatus(device, fence) == VK_SUCCESS;
    };

    // The weight is uploaded once: it is the same for every dispatch.
    {
        std::vector<float> wf(w.begin(), w.end());
        std::memcpy(bufW.mapped, wf.data(), wf.size() * sizeof(float));
    }

    // The first dispatch starts from a cold state.
    std::vector<float> cold(coldState.size());
    std::memcpy(bufState.mapped, cold.data(), cold.size() * sizeof(float));
    if (!runDispatch(x1, kTokens1)) {
        std::printf("RESULT: FAIL (the first dispatch did not complete)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    // The outputs are copied out here, and not read from the mapped memory
    // later: the next dispatch writes the same buffers, and a pointer held
    // across it would read the next dispatch's answer.
    std::vector<float> deviceY1(static_cast<const float*>(bufY.mapped),
                                 static_cast<const float*>(bufY.mapped) + refY1.size());
    std::vector<float> deviceState1(static_cast<const float*>(bufStateOut.mapped),
                                     static_cast<const float*>(bufStateOut.mapped) + refH1.size());

    // The second dispatch leans on the carry the first produced.
    std::memcpy(bufState.mapped, deviceState1.data(), deviceState1.size() * sizeof(float));
    if (!runDispatch(x2, kTokens2)) {
        std::printf("RESULT: FAIL (the second dispatch did not complete)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    std::vector<float> deviceY2(static_cast<const float*>(bufY.mapped),
                                 static_cast<const float*>(bufY.mapped) + refY2.size());
    std::vector<float> deviceState2(static_cast<const float*>(bufStateOut.mapped),
                                     static_cast<const float*>(bufStateOut.mapped) + refH2.size());

    // ---- the comparison ----
    double worstY1 = 0.0, worstH1 = 0.0, worstY2 = 0.0, worstH2 = 0.0;
    for (size_t i = 0; i < refY1.size(); ++i)
        worstY1 = std::max(worstY1, std::fabs(static_cast<double>(deviceY1[i]) - refY1[i]));
    for (size_t i = 0; i < refH1.size(); ++i)
        worstH1 = std::max(worstH1, std::fabs(static_cast<double>(deviceState1[i]) - refH1[i]));
    for (size_t i = 0; i < refY2.size(); ++i)
        worstY2 = std::max(worstY2, std::fabs(static_cast<double>(deviceY2[i]) - refY2[i]));
    for (size_t i = 0; i < refH2.size(); ++i)
        worstH2 = std::max(worstH2, std::fabs(static_cast<double>(deviceState2[i]) - refH2[i]));

    const double tolerance = 2e-5;
    const bool ok = worstY1 <= tolerance && worstH1 <= tolerance &&
                    worstY2 <= tolerance && worstH2 <= tolerance;

    std::printf("\n");
    std::printf("kernel=%u channels=%u\n", kKernel, kChannels);
    std::printf("dispatch 1: tokens=%u  y max_abs_diff = %.6e   carry max_abs_diff = %.6e\n",
                kTokens1, worstY1, worstH1);
    std::printf("dispatch 2: tokens=%u  y max_abs_diff = %.6e   carry max_abs_diff = %.6e\n",
                kTokens2, worstY2, worstH2);
    std::printf("tolerance                       = %.6e\n", tolerance);

    if (!ok) {
        std::printf("\n");
        std::printf("--- what the host put in the buffers ---\n");
        const float* hostX = static_cast<const float*>(bufX.mapped);
        const float* hostW = static_cast<const float*>(bufW.mapped);
        const float* hostState = static_cast<const float*>(bufState.mapped);
        std::printf("x[0..5]      host =");
        for (uint32_t i = 0; i < 6; ++i) std::printf(" %8.5f", hostX[i]);
        std::printf("\nw[24..29]    host =");
        for (uint32_t i = 0; i < 6; ++i) std::printf(" %8.5f", hostW[24 + i]);
        std::printf("\nstate[0..5]   host =");
        for (uint32_t i = 0; i < 6; ++i) std::printf(" %8.5f", hostState[i]);
        std::printf("\n");
        std::printf("--- the first token of dispatch 1, where the history is read ---\n");
        std::printf("%6s %12s %12s %12s\n", "channel", "device", "reference", "diff");
        for (uint32_t c = 0; c < kChannels && c < 6; ++c) {
            std::printf("%6u %12.6f %12.6f %12.6f\n", c, deviceY1[c], refY1[c],
                        std::fabs(static_cast<double>(deviceY1[c]) - refY1[c]));
        }
    }
    std::printf("\n");
    std::printf("RESULT: %s\n", ok ? "PASS (the device reproduced the reference)"
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
