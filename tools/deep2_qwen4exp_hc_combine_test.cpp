// The Qwen4Exp hyperconnection combine lowering, executed.
//
// The shader artifact has been compiled and statically validated, and it has
// never been run. A correctness kernel that has never executed is an
// untested artifact: it may not even compile in the driver's hands, let
// alone produce the numbers it claims.
//
// This runs it on the device and compares what comes back against a
// reference computed on the host in double precision. The reference is
// written from the recovered equation rather than from the shader, so a
// mistake in the shader cannot hide inside a matching mistake in the
// reference.
//
// It is deliberately self-contained. It creates its own device, so it does
// not depend on the state of anything else in the tree, and it touches no
// file that another part of the engine owns.
//
// The verdict is one of:
//   PASS     the device produced the reference within the tolerance
//   FAIL     the device produced something else
//   BLOCKED  there is no device, or the artifact is missing
// A machine with no GPU is BLOCKED. It is never a PASS, because a gate that
// cannot run has not passed anything.
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

constexpr uint32_t kHcCount = 4;      // the four streams
constexpr uint32_t kHeadDim = 16;     // per-stream width
constexpr uint32_t kTokens = 5;       // tokens in the batch
constexpr float kEpsilon = 1e-5f;
constexpr double kTolerance = 2e-5;   // f32 rounding of the same arithmetic

struct Buffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr;
};

// ---------------------------------------------------------------------------
// The reference, computed on the host in double precision.
//
// The recovered contract is:
//   injection = 2 * sigmoid(logits / hc_count)
//   out       = residual + block_output * injection
//   normalized = grouped RMSNorm(out) with a Gemma-style (1 + w) affine
// where the norm is taken per stream, over that stream's slice of the
// combined buffer.
// ---------------------------------------------------------------------------
double Sigmoid(double x) { return 1.0 / (1.0 + std::exp(-x)); }

void Reference(const std::vector<float>& residual,
               const std::vector<float>& block,
               const std::vector<float>& injection,
               const std::vector<float>& normWeight,
               std::vector<double>& combined,
               std::vector<double>& normalized) {
    const size_t width = static_cast<size_t>(kHeadDim) * kHcCount;
    combined.assign(static_cast<size_t>(kTokens) * width, 0.0);
    normalized.assign(static_cast<size_t>(kTokens) * width, 0.0);

    for (uint32_t t = 0; t < kTokens; ++t) {
        for (uint32_t s = 0; s < kHcCount; ++s) {
            const double factor =
                2.0 * Sigmoid(static_cast<double>(injection[t * kHcCount + s]) /
                               static_cast<double>(kHcCount));
            // The stream's own slice, and the block output's slice.
            double ss = 0.0;
            for (uint32_t j = 0; j < kHeadDim; ++j) {
                const size_t e = static_cast<size_t>(s) * kHeadDim + j;
                const double q = static_cast<double>(residual[t * width + e]) +
                                 static_cast<double>(block[t * kHeadDim + j]) * factor;
                ss += q * q;
            }
            const double inv = 1.0 / std::sqrt(ss / static_cast<double>(kHeadDim) +
                                                static_cast<double>(kEpsilon));
            for (uint32_t col = 0; col < kHeadDim; ++col) {
                const size_t e = static_cast<size_t>(s) * kHeadDim + col;
                const double v = static_cast<double>(residual[t * width + e]) +
                                 static_cast<double>(block[t * kHeadDim + col]) * factor;
                const double y = v * inv;
                combined[t * width + e] = v;
                normalized[t * width + e] = y + y * static_cast<double>(normWeight[col]);
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
    std::string spirvPath = "src/deep2/shaders/deep2_qwen4exp_hc_combine.spv";
    if (argc >= 2) spirvPath = argv[1];

    std::printf("=== Qwen4Exp hyperconnection combine: device execution ===\n");
    std::printf("artifact: %s\n", spirvPath.c_str());

    std::vector<uint32_t> spirv;
    if (!ReadSpirv(spirvPath, spirv)) {
        std::printf("RESULT: BLOCKED (the artifact is missing or unreadable: %s)\n",
                    spirvPath.c_str());
        return 2;
    }
    std::printf("artifact: %u words of SPIR-V\n", static_cast<unsigned>(spirv.size()));

    // ---- the instance and the device ----
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "deep2_qwen4exp_hc_combine_test";
    appInfo.apiVersion = VK_API_VERSION_1_1;

    // The validation layer is on, and it prints what it finds. A test that
    // reports a number without saying whether the API was used correctly
    // cannot tell a wrong answer from a wrong setup.
    const char* validationLayer = "VK_LAYER_KHRONOS_validation";
    uint32_t layerCount = 0;
    vkEnumerateInstanceLayerProperties(&layerCount, nullptr);
    std::vector<VkLayerProperties> layerProperties(layerCount);
    vkEnumerateInstanceLayerProperties(&layerCount, layerProperties.data());
    bool haveValidation = false;
    for (const auto& p : layerProperties) {
        if (std::strcmp(p.layerName, validationLayer) == 0) { haveValidation = true; break; }
    }

    const char* const enabledLayers[] = { validationLayer };
    VkInstanceCreateInfo instanceInfo{};
    instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instanceInfo.pApplicationInfo = &appInfo;
    if (haveValidation) {
        instanceInfo.enabledLayerCount = 1;
        instanceInfo.ppEnabledLayerNames = enabledLayers;
    }

    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(&instanceInfo, nullptr, &instance) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (no Vulkan instance could be created)\n");
        return 2;
    }
    if (haveValidation) {
        std::printf("validation: %s is on\n", validationLayer);
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
    VkQueueFamilyProperties queueProps{};
    for (VkPhysicalDevice candidate : physicalDevices) {
        uint32_t familyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(candidate, &familyCount, nullptr);
        std::vector<VkQueueFamilyProperties> families(familyCount);
        vkGetPhysicalDeviceQueueFamilyProperties(candidate, &familyCount, families.data());
        for (uint32_t i = 0; i < familyCount; ++i) {
            if (families[i].queueCount > 0 &&
                (families[i].queueFlags & VK_QUEUE_COMPUTE_BIT)) {
                physical = candidate;
                queueFamily = i;
                queueProps = families[i];
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
    VkDescriptorSetLayoutBinding bindings[6]{};
    for (uint32_t i = 0; i < 6; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo layoutInfo{};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 6;
    layoutInfo.pBindings = bindings;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    if (vkCreateDescriptorSetLayout(device, &layoutInfo, nullptr, &setLayout) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the descriptor layout could not be created)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }

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
    if (vkCreatePipelineLayout(device, &pipelineLayoutInfo, nullptr, &pipelineLayout) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the pipeline layout could not be created)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }

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
    const VkResult pipelineResult =
        vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline);
    if (pipelineResult != VK_SUCCESS) {
        std::printf("RESULT: FAIL (the pipeline could not be created, vkResult=%d)\n",
                    static_cast<int>(pipelineResult));
        std::printf("  the artifact does not build on this device\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    std::printf("pipeline: created\n");

    // ---- the buffers ----
    const size_t width = static_cast<size_t>(kHeadDim) * kHcCount;
    const size_t residualCount = static_cast<size_t>(kTokens) * width;
    const size_t blockCount = static_cast<size_t>(kTokens) * kHeadDim;
    const size_t injectionCount = static_cast<size_t>(kTokens) * kHcCount;

    // The inputs, on the host, in a shape the reference and the device share.
    std::vector<float> residual(residualCount);
    std::vector<float> block(blockCount);
    std::vector<float> injection(injectionCount);
    std::vector<float> normWeight(kHeadDim);
    // A deterministic pattern that is not symmetric, so a transposed or
    // mis-strided read cannot produce the same answer.
    uint32_t seed = 0x9e3779b9u;
    auto nextRandom = [&seed]() -> float {
        seed = seed * 1664525u + 1013904223u;
        return (static_cast<float>(seed >> 8) / static_cast<float>(1u << 24)) * 2.0f - 1.0f;
    };
    for (float& v : residual) v = nextRandom();
    for (float& v : block) v = nextRandom();
    for (float& v : injection) v = nextRandom() * 4.0f;
    for (float& v : normWeight) v = nextRandom();

    std::vector<double> refCombined, refNormalized;
    Reference(residual, block, injection, normWeight, refCombined, refNormalized);

    VkPhysicalDeviceMemoryProperties memProps{};
    vkGetPhysicalDeviceMemoryProperties(physical, &memProps);
    // The memory type has to be host visible AND host coherent.
    //
    // Testing the two flags with one mask is not the same thing: a mask
    // matches when EITHER bit is set, so a type that is host visible but
    // not host coherent passes, and then neither the host's writes nor the
    // device's writes are visible without an explicit flush. The symptom is
    // a device that reads zeros and a host that reads zeros, which looks
    // exactly like a shader that computed nothing.
    //
    // A device-local host-visible type is preferred: it is both coherent
    // and the memory the device actually runs out of.
    uint32_t hostIndex = UINT32_MAX;
    uint32_t hostCoherentIndex = UINT32_MAX;
    uint32_t deviceHostIndex = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        const VkMemoryPropertyFlags f = memProps.memoryTypes[i].propertyFlags;
        const bool visible = (f & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) != 0;
        const bool coherent = (f & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;
        const bool local = (f & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) != 0;
        if (visible && coherent) {
            if (hostCoherentIndex == UINT32_MAX) hostCoherentIndex = i;
            if (local && deviceHostIndex == UINT32_MAX) deviceHostIndex = i;
        }
    }
    if (deviceHostIndex != UINT32_MAX) {
        hostIndex = deviceHostIndex;
    } else if (hostCoherentIndex != UINT32_MAX) {
        hostIndex = hostCoherentIndex;
    }
    if (hostIndex == UINT32_MAX) {
        std::printf("RESULT: BLOCKED (no host-visible coherent memory type)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    std::printf("memory  : type %u (host visible, host coherent)\n", hostIndex);

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

    Buffer bufResidual, bufBlock, bufInjection, bufNorm, bufCombined, bufNormalized;
    const bool allocated =
        makeBuffer(residualCount * sizeof(float), bufResidual) &&
        makeBuffer(blockCount * sizeof(float), bufBlock) &&
        makeBuffer(injectionCount * sizeof(float), bufInjection) &&
        makeBuffer(kHeadDim * sizeof(float), bufNorm) &&
        makeBuffer(residualCount * sizeof(float), bufCombined) &&
        makeBuffer(residualCount * sizeof(float), bufNormalized);
    if (!allocated) {
        std::printf("RESULT: BLOCKED (the buffers could not be allocated)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }

    std::memcpy(bufResidual.mapped, residual.data(), residual.size() * sizeof(float));
    std::memcpy(bufBlock.mapped, block.data(), block.size() * sizeof(float));
    std::memcpy(bufInjection.mapped, injection.data(), injection.size() * sizeof(float));
    std::memcpy(bufNorm.mapped, normWeight.data(), normWeight.size() * sizeof(float));
    std::memset(bufCombined.mapped, 0, residualCount * sizeof(float));
    std::memset(bufNormalized.mapped, 0, residualCount * sizeof(float));

    // ---- the descriptor set ----
    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 6;
    VkDescriptorPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.maxSets = 1;
    poolInfo.poolSizeCount = 1;
    poolInfo.pPoolSizes = &poolSize;
    VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
    if (vkCreateDescriptorPool(device, &poolInfo, nullptr, &descriptorPool) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the descriptor pool could not be created)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    VkDescriptorSetAllocateInfo setAlloc{};
    setAlloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    setAlloc.descriptorPool = descriptorPool;
    setAlloc.descriptorSetCount = 1;
    setAlloc.pSetLayouts = &setLayout;
    VkDescriptorSet descriptorSet = VK_NULL_HANDLE;
    if (vkAllocateDescriptorSets(device, &setAlloc, &descriptorSet) != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the descriptor set could not be allocated)\n");
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    const Buffer* bound[6] = { &bufResidual, &bufBlock, &bufInjection,
                               &bufNorm, &bufCombined, &bufNormalized };
    VkDescriptorBufferInfo bufferInfos[6]{};
    VkWriteDescriptorSet writes[6]{};
    for (uint32_t i = 0; i < 6; ++i) {
        bufferInfos[i].buffer = bound[i]->buffer;
        // The range has to be stated. A range of zero is not the whole
        // buffer: it is a descriptor over no bytes at all, and the shader
        // then reads zeros and writes nothing while reporting no error.
        bufferInfos[i].range = VK_WHOLE_SIZE;
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = descriptorSet;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &bufferInfos[i];
    }
    vkUpdateDescriptorSets(device, 6, writes, 0, nullptr);

    // ---- the dispatch ----
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
    const uint32_t groups = static_cast<uint32_t>((residualCount + 63) / 64);
    vkCmdDispatch(cmd, groups, 1, 1);
    vkEndCommandBuffer(cmd);

    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &cmd;
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence = VK_NULL_HANDLE;
    vkCreateFence(device, &fenceInfo, nullptr, &fence);
    const VkResult submitResult = vkQueueSubmit(queue, 1, &submit, fence);
    if (submitResult != VK_SUCCESS) {
        std::printf("RESULT: BLOCKED (the dispatch could not be submitted, vkResult=%d)\n",
                    static_cast<int>(submitResult));
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 2;
    }
    vkWaitForFences(device, 1, &fence, VK_TRUE, 1000000000ull);
    const VkResult fenceResult = vkGetFenceStatus(device, fence);
    if (fenceResult != VK_SUCCESS) {
        std::printf("RESULT: FAIL (the dispatch did not complete, fence status=%d)\n",
                    static_cast<int>(fenceResult));
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // ---- the comparison ----
    const float* deviceCombined = static_cast<const float*>(bufCombined.mapped);
    const float* deviceNormalized = static_cast<const float*>(bufNormalized.mapped);
    double worstCombined = 0.0;
    double worstNormalized = 0.0;
    for (size_t i = 0; i < residualCount; ++i) {
        worstCombined = std::max(worstCombined,
                                 std::fabs(static_cast<double>(deviceCombined[i]) - refCombined[i]));
        worstNormalized = std::max(worstNormalized,
                                   std::fabs(static_cast<double>(deviceNormalized[i]) - refNormalized[i]));
    }
    const bool finite = std::all_of(deviceNormalized, deviceNormalized + residualCount,
                                    [](float v) { return std::isfinite(v); });
    const bool ok = finite && worstNormalized <= kTolerance && worstCombined <= kTolerance;

    // ---- the diagnosis ----
    //
    // The first few values, so a disagreement can be read rather than
    // guessed at. For each one the value the recovered equation predicts is
    // shown next to what the device produced.
    std::printf("\n--- the first values of token 0 ---\n");
    std::printf("%6s %12s %12s %12s %12s\n", "index", "residual", "block", "device", "reference");
    for (uint32_t i = 0; i < 8 && i < residualCount; ++i) {
        const uint32_t stream = i / kHeadDim;
        const uint32_t col = i % kHeadDim;
        const double factor =
            2.0 * Sigmoid(static_cast<double>(injection[stream]) / static_cast<double>(kHcCount));
        const double predicted = static_cast<double>(residual[i]) +
                                 static_cast<double>(block[col]) * factor;
        std::printf("%6u %12.5f %12.5f %12.5f %12.5f\n", i, residual[i], block[col],
                    deviceCombined[i], refCombined[i]);
        if (i == 0) {
            std::printf("       (stream %u col %u, factor %.6f, predicted %.6f)\n",
                        stream, col, factor, predicted);
        }
    }

    std::printf("\n");
    std::printf("tokens=%u head_dim=%u hc_count=%u width=%zu\n",
                kTokens, kHeadDim, kHcCount, width);
    std::printf("combined   max_abs_diff = %.3e\n", worstCombined);
    std::printf("normalized max_abs_diff = %.3e\n", worstNormalized);
    std::printf("tolerance                = %.3e\n", kTolerance);
    std::printf("all values finite        = %s\n", finite ? "yes" : "no");
    std::printf("\n");
    if (!finite) {
        std::printf("RESULT: FAIL (the device produced a non-finite value)\n");
    } else if (!ok) {
        std::printf("RESULT: FAIL (the device did not reproduce the reference)\n");
    } else {
        std::printf("RESULT: PASS (the device reproduced the reference)\n");
    }

    vkDestroyFence(device, fence, nullptr);
    vkDestroyCommandPool(device, commandPool, nullptr);
    vkDestroyDescriptorPool(device, descriptorPool, nullptr);
    vkDestroyPipeline(device, pipeline, nullptr);
    vkDestroyShaderModule(device, module, nullptr);
    vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
    vkDestroyDescriptorSetLayout(device, setLayout, nullptr);
    // The buffers and their memory, before the device goes. A validation
    // layer reports a leak when they are not, and a test that leaves the
    // device in a bad state teaches the next reader nothing.
    {
        Buffer* all[6] = { &bufResidual, &bufBlock, &bufInjection,
                           &bufNorm, &bufCombined, &bufNormalized };
        for (Buffer* b : all) {
            if (b->mapped) vkUnmapMemory(device, b->memory);
            if (b->buffer) vkDestroyBuffer(device, b->buffer, nullptr);
            if (b->memory) vkFreeMemory(device, b->memory, nullptr);
            b->buffer = VK_NULL_HANDLE;
            b->memory = VK_NULL_HANDLE;
            b->mapped = nullptr;
        }
    }
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);
    return ok ? 0 : 1;
}
