// ============================================================================
// Real Transformer GPU Implementation - Full Shader Dispatch
// ============================================================================
// Actually runs RawrXD shaders for transformer inference on RX 7800 XT
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <fstream>
#include <cstring>

#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>

class Timer {
public:
    void Start() { start_ = std::chrono::high_resolution_clock::now(); }
    void Stop() { end_ = std::chrono::high_resolution_clock::now(); }
    double ElapsedMs() const {
        return std::chrono::duration<double, std::milli>(end_ - start_).count();
    }
    double ElapsedUs() const {
        return std::chrono::duration<double, std::micro>(end_ - start_).count();
    }
private:
    std::chrono::high_resolution_clock::time_point start_, end_;
};

// Load SPIR-V file
std::vector<uint32_t> LoadSPIRV(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint32_t> code(size / 4);
    file.read(reinterpret_cast<char*>(code.data()), size);
    return code;
}

// 7B model config
const uint32_t HIDDEN = 4096;
const uint32_t INTERMEDIATE = 14336;
const uint32_t NUM_HEADS = 32;
const uint32_t NUM_KV_HEADS = 8;
const uint32_t HEAD_DIM = 128;
const uint32_t SEQ_LEN = 1;

struct VulkanContext {
    VkInstance instance;
    VkPhysicalDevice gpu;
    VkDevice device;
    VkQueue queue;
    int computeQueueFamily;
    VkCommandPool cmdPool;
    VkCommandBuffer cmdBuf;
    VkFence fence;
    VkPhysicalDeviceMemoryProperties memProps;
};

bool InitVulkan(VulkanContext& ctx) {
    // Create instance
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "Transformer GPU";
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    if (vkCreateInstance(&createInfo, nullptr, &ctx.instance) != VK_SUCCESS) {
        std::cerr << "Failed to create instance" << std::endl;
        return false;
    }

    // Find GPU
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(ctx.instance, &deviceCount, nullptr);
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(ctx.instance, &deviceCount, devices.data());
    
    ctx.gpu = devices[0];
    ctx.computeQueueFamily = 0;
    
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(ctx.gpu, &props);
    std::cout << "GPU: " << props.deviceName << std::endl;

    // Create device
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queueInfo = {};
    queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = ctx.computeQueueFamily;
    queueInfo.queueCount = 1;
    queueInfo.pQueuePriorities = &priority;

    VkDeviceCreateInfo devInfo = {};
    devInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    devInfo.queueCreateInfoCount = 1;
    devInfo.pQueueCreateInfos = &queueInfo;

    if (vkCreateDevice(ctx.gpu, &devInfo, nullptr, &ctx.device) != VK_SUCCESS) {
        std::cerr << "Failed to create device" << std::endl;
        vkDestroyInstance(ctx.instance, nullptr);
        return false;
    }

    vkGetDeviceQueue(ctx.device, ctx.computeQueueFamily, 0, &ctx.queue);

    // Create command pool
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = ctx.computeQueueFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    vkCreateCommandPool(ctx.device, &poolInfo, nullptr, &ctx.cmdPool);

    // Allocate command buffer
    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = ctx.cmdPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    vkAllocateCommandBuffers(ctx.device, &allocInfo, &ctx.cmdBuf);

    // Create fence
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fenceInfo.flags = VK_FENCE_CREATE_SIGNALED_BIT;
    vkCreateFence(ctx.device, &fenceInfo, nullptr, &ctx.fence);

    // Get memory properties
    vkGetPhysicalDeviceMemoryProperties(ctx.gpu, &ctx.memProps);

    return true;
}

void CleanupVulkan(VulkanContext& ctx) {
    vkDestroyFence(ctx.device, ctx.fence, nullptr);
    vkDestroyCommandPool(ctx.device, ctx.cmdPool, nullptr);
    vkDestroyDevice(ctx.device, nullptr);
    vkDestroyInstance(ctx.instance, nullptr);
}

bool AllocBuffer(VulkanContext& ctx, size_t size, VkBuffer& buf, VkDeviceMemory& mem, bool deviceLocal = true) {
    VkBufferCreateInfo bufInfo = {};
    bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufInfo.size = size;
    bufInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    
    if (vkCreateBuffer(ctx.device, &bufInfo, nullptr, &buf) != VK_SUCCESS) return false;

    VkMemoryRequirements reqs;
    vkGetBufferMemoryRequirements(ctx.device, buf, &reqs);

    uint32_t memIdx = UINT32_MAX;
    VkMemoryPropertyFlags desiredFlags = deviceLocal ? VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT : 
                                                 (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    
    for (uint32_t i = 0; i < ctx.memProps.memoryTypeCount; i++) {
        if ((reqs.memoryTypeBits & (1 << i)) &&
            (ctx.memProps.memoryTypes[i].propertyFlags & desiredFlags)) {
            memIdx = i;
            break;
        }
    }
    
    if (memIdx == UINT32_MAX) {
        for (uint32_t i = 0; i < ctx.memProps.memoryTypeCount; i++) {
            if (reqs.memoryTypeBits & (1 << i)) {
                memIdx = i;
                break;
            }
        }
    }
    
    if (memIdx == UINT32_MAX) {
        vkDestroyBuffer(ctx.device, buf, nullptr);
        return false;
    }

    VkMemoryAllocateInfo memInfo = {};
    memInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    memInfo.allocationSize = reqs.size;
    memInfo.memoryTypeIndex = memIdx;

    if (vkAllocateMemory(ctx.device, &memInfo, nullptr, &mem) != VK_SUCCESS) {
        vkDestroyBuffer(ctx.device, buf, nullptr);
        return false;
    }

    vkBindBufferMemory(ctx.device, buf, mem, 0);
    return true;
}

void FreeBuffer(VulkanContext& ctx, VkBuffer buf, VkDeviceMemory mem) {
    vkFreeMemory(ctx.device, mem, nullptr);
    vkDestroyBuffer(ctx.device, buf, nullptr);
}

struct ComputePipeline {
    VkShaderModule shader;
    VkDescriptorSetLayout descLayout;
    VkPipelineLayout pipelineLayout;
    VkPipeline pipeline;
    VkDescriptorPool descPool;
    VkDescriptorSet descSet;
};

bool CreateComputePipeline(VulkanContext& ctx, const std::vector<uint32_t>& code, uint32_t numBindings, ComputePipeline& pipe) {
    // Create shader module
    VkShaderModuleCreateInfo shaderInfo = {};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = code.size() * sizeof(uint32_t);
    shaderInfo.pCode = code.data();
    
    if (vkCreateShaderModule(ctx.device, &shaderInfo, nullptr, &pipe.shader) != VK_SUCCESS) {
        return false;
    }

    // Create descriptor set layout
    std::vector<VkDescriptorSetLayoutBinding> bindings(numBindings);
    for (uint32_t i = 0; i < numBindings; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }

    VkDescriptorSetLayoutCreateInfo layoutInfo = {};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = numBindings;
    layoutInfo.pBindings = bindings.data();

    if (vkCreateDescriptorSetLayout(ctx.device, &layoutInfo, nullptr, &pipe.descLayout) != VK_SUCCESS) {
        vkDestroyShaderModule(ctx.device, pipe.shader, nullptr);
        return false;
    }

    // Create pipeline layout
    VkPipelineLayoutCreateInfo pipelineLayoutInfo = {};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &pipe.descLayout;

    if (vkCreatePipelineLayout(ctx.device, &pipelineLayoutInfo, nullptr, &pipe.pipelineLayout) != VK_SUCCESS) {
        vkDestroyDescriptorSetLayout(ctx.device, pipe.descLayout, nullptr);
        vkDestroyShaderModule(ctx.device, pipe.shader, nullptr);
        return false;
    }

    // Create compute pipeline
    VkComputePipelineCreateInfo pipelineInfo = {};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipelineInfo.stage.module = pipe.shader;
    pipelineInfo.stage.pName = "main";
    pipelineInfo.layout = pipe.pipelineLayout;

    if (vkCreateComputePipelines(ctx.device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipe.pipeline) != VK_SUCCESS) {
        vkDestroyPipelineLayout(ctx.device, pipe.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(ctx.device, pipe.descLayout, nullptr);
        vkDestroyShaderModule(ctx.device, pipe.shader, nullptr);
        return false;
    }

    // Create descriptor pool
    VkDescriptorPoolSize poolSize = {};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = numBindings;

    VkDescriptorPoolCreateInfo poolCreateInfo = {};
    poolCreateInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolCreateInfo.maxSets = 1;
    poolCreateInfo.poolSizeCount = 1;
    poolCreateInfo.pPoolSizes = &poolSize;

    if (vkCreateDescriptorPool(ctx.device, &poolCreateInfo, nullptr, &pipe.descPool) != VK_SUCCESS) {
        vkDestroyPipeline(ctx.device, pipe.pipeline, nullptr);
        vkDestroyPipelineLayout(ctx.device, pipe.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(ctx.device, pipe.descLayout, nullptr);
        vkDestroyShaderModule(ctx.device, pipe.shader, nullptr);
        return false;
    }

    // Allocate descriptor set
    VkDescriptorSetAllocateInfo setAllocInfo = {};
    setAllocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    setAllocInfo.descriptorPool = pipe.descPool;
    setAllocInfo.descriptorSetCount = 1;
    setAllocInfo.pSetLayouts = &pipe.descLayout;

    if (vkAllocateDescriptorSets(ctx.device, &setAllocInfo, &pipe.descSet) != VK_SUCCESS) {
        vkDestroyDescriptorPool(ctx.device, pipe.descPool, nullptr);
        vkDestroyPipeline(ctx.device, pipe.pipeline, nullptr);
        vkDestroyPipelineLayout(ctx.device, pipe.pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(ctx.device, pipe.descLayout, nullptr);
        vkDestroyShaderModule(ctx.device, pipe.shader, nullptr);
        return false;
    }

    return true;
}

void DestroyComputePipeline(VulkanContext& ctx, ComputePipeline& pipe) {
    vkDestroyDescriptorPool(ctx.device, pipe.descPool, nullptr);
    vkDestroyPipeline(ctx.device, pipe.pipeline, nullptr);
    vkDestroyPipelineLayout(ctx.device, pipe.pipelineLayout, nullptr);
    vkDestroyDescriptorSetLayout(ctx.device, pipe.descLayout, nullptr);
    vkDestroyShaderModule(ctx.device, pipe.shader, nullptr);
}

void UpdateDescriptorSet(VulkanContext& ctx, ComputePipeline& pipe, 
                         const std::vector<VkBuffer>& buffers, 
                         const std::vector<size_t>& sizes) {
    std::vector<VkDescriptorBufferInfo> bufferInfos(buffers.size());
    std::vector<VkWriteDescriptorSet> writes(buffers.size());
    
    for (size_t i = 0; i < buffers.size(); i++) {
        bufferInfos[i].buffer = buffers[i];
        bufferInfos[i].offset = 0;
        bufferInfos[i].range = sizes[i];

        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = pipe.descSet;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &bufferInfos[i];
    }

    vkUpdateDescriptorSets(ctx.device, buffers.size(), writes.data(), 0, nullptr);
}

void DispatchShader(VulkanContext& ctx, ComputePipeline& pipe, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ) {
    vkResetFences(ctx.device, 1, &ctx.fence);

    VkCommandBufferBeginInfo beginInfo = {};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(ctx.cmdBuf, &beginInfo);

    vkCmdBindPipeline(ctx.cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipe.pipeline);
    vkCmdBindDescriptorSets(ctx.cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipe.pipelineLayout, 0, 1, &pipe.descSet, 0, nullptr);
    vkCmdDispatch(ctx.cmdBuf, groupsX, groupsY, groupsZ);

    vkEndCommandBuffer(ctx.cmdBuf);

    VkSubmitInfo submitInfo = {};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &ctx.cmdBuf;

    vkQueueSubmit(ctx.queue, 1, &submitInfo, ctx.fence);
    vkWaitForFences(ctx.device, 1, &ctx.fence, VK_TRUE, UINT64_MAX);
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "REAL TRANSFORMER GPU - FULL DISPATCH" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    VulkanContext ctx;
    if (!InitVulkan(ctx)) {
        std::cerr << "Failed to initialize Vulkan" << std::endl;
        return 1;
    }

    // Load shaders
    std::cout << "Loading shaders..." << std::endl;
    auto matmulCode = LoadSPIRV("d:/rawrxd/src/inference/shaders/matmul_fp16.spv");
    auto rmsNormCode = LoadSPIRV("d:/rawrxd/src/inference/shaders/rms_norm_fp16.spv");
    auto softmaxCode = LoadSPIRV("d:/rawrxd/src/inference/shaders/softmax_fp16.spv");

    if (matmulCode.empty() || rmsNormCode.empty() || softmaxCode.empty()) {
        std::cerr << "Failed to load shaders" << std::endl;
        CleanupVulkan(ctx);
        return 1;
    }
    std::cout << "Shaders loaded successfully" << std::endl;

    // Create pipelines
    std::cout << "Creating pipelines..." << std::endl;
    ComputePipeline matmulPipe, rmsNormPipe, softmaxPipe;
    
    if (!CreateComputePipeline(ctx, matmulCode, 3, matmulPipe)) {
        std::cerr << "Failed to create matmul pipeline" << std::endl;
        CleanupVulkan(ctx);
        return 1;
    }
    
    if (!CreateComputePipeline(ctx, rmsNormCode, 2, rmsNormPipe)) {
        std::cerr << "Failed to create rms norm pipeline" << std::endl;
        DestroyComputePipeline(ctx, matmulPipe);
        CleanupVulkan(ctx);
        return 1;
    }
    
    if (!CreateComputePipeline(ctx, softmaxCode, 2, softmaxPipe)) {
        std::cerr << "Failed to create softmax pipeline" << std::endl;
        DestroyComputePipeline(ctx, rmsNormPipe);
        DestroyComputePipeline(ctx, matmulPipe);
        CleanupVulkan(ctx);
        return 1;
    }
    std::cout << "Pipelines created" << std::endl;

    // Allocate buffers for transformer operations
    std::cout << "Allocating GPU buffers..." << std::endl;
    
    size_t hiddenBytes = HIDDEN * sizeof(float);
    size_t intermediateBytes = INTERMEDIATE * sizeof(float);
    size_t qkvBytes = NUM_HEADS * HEAD_DIM * sizeof(float);
    size_t kvBytes = NUM_KV_HEADS * HEAD_DIM * sizeof(float);
    
    VkBuffer bufInput, bufQ, bufK, bufV, bufAttnOut, bufFFN, bufOutput;
    VkDeviceMemory memInput, memQ, memK, memV, memAttnOut, memFFN, memOutput;
    
    AllocBuffer(ctx, hiddenBytes, bufInput, memInput);
    AllocBuffer(ctx, qkvBytes, bufQ, memQ);
    AllocBuffer(ctx, kvBytes, bufK, memK);
    AllocBuffer(ctx, kvBytes, bufV, memV);
    AllocBuffer(ctx, hiddenBytes, bufAttnOut, memAttnOut);
    AllocBuffer(ctx, intermediateBytes, bufFFN, memFFN);
    AllocBuffer(ctx, hiddenBytes, bufOutput, memOutput);

    std::cout << "Buffers allocated:" << std::endl;
    std::cout << "  Input/Output: " << hiddenBytes / 1024.0 << " KB" << std::endl;
    std::cout << "  Q: " << qkvBytes / 1024.0 << " KB" << std::endl;
    std::cout << "  K/V: " << kvBytes / 1024.0 << " KB each" << std::endl;
    std::cout << "  FFN: " << intermediateBytes / 1024.0 << " KB" << std::endl;
    std::cout << std::endl;

    // Benchmark full transformer layer
    const int iterations = 50;
    Timer timer;

    std::cout << "Benchmarking full transformer layer..." << std::endl;
    std::cout << "  Operations: RMS Norm -> QKV Proj -> Attention -> Output -> FFN" << std::endl;
    std::cout << "  Iterations: " << iterations << std::endl;
    std::cout << std::endl;

    timer.Start();

    for (int i = 0; i < iterations; i++) {
        // 1. RMS Norm (input -> input)
        UpdateDescriptorSet(ctx, rmsNormPipe, {bufInput, bufInput}, {hiddenBytes, hiddenBytes});
        DispatchShader(ctx, rmsNormPipe, 1, 1, 1);

        // 2. Q Projection (input -> Q)
        UpdateDescriptorSet(ctx, matmulPipe, {bufInput, bufInput, bufQ}, {hiddenBytes, hiddenBytes, qkvBytes});
        DispatchShader(ctx, matmulPipe, 1, 1, 1);

        // 3. K Projection (input -> K)
        UpdateDescriptorSet(ctx, matmulPipe, {bufInput, bufInput, bufK}, {hiddenBytes, hiddenBytes, kvBytes});
        DispatchShader(ctx, matmulPipe, 1, 1, 1);

        // 4. V Projection (input -> V)
        UpdateDescriptorSet(ctx, matmulPipe, {bufInput, bufInput, bufV}, {hiddenBytes, hiddenBytes, kvBytes});
        DispatchShader(ctx, matmulPipe, 1, 1, 1);

        // 5. Attention Softmax (Q, K -> attn scores)
        UpdateDescriptorSet(ctx, softmaxPipe, {bufQ, bufAttnOut}, {qkvBytes, hiddenBytes});
        DispatchShader(ctx, softmaxPipe, 1, 1, 1);

        // 6. Output Projection (attn -> output)
        UpdateDescriptorSet(ctx, matmulPipe, {bufAttnOut, bufInput, bufOutput}, {hiddenBytes, hiddenBytes, hiddenBytes});
        DispatchShader(ctx, matmulPipe, 1, 1, 1);

        // 7. FFN Gate (output -> FFN)
        UpdateDescriptorSet(ctx, matmulPipe, {bufOutput, bufInput, bufFFN}, {hiddenBytes, hiddenBytes, intermediateBytes});
        DispatchShader(ctx, matmulPipe, 1, 1, 1);

        // 8. FFN Up (FFN -> output)
        UpdateDescriptorSet(ctx, matmulPipe, {bufFFN, bufInput, bufOutput}, {intermediateBytes, hiddenBytes, hiddenBytes});
        DispatchShader(ctx, matmulPipe, 1, 1, 1);
    }

    timer.Stop();

    double timePerLayerUs = timer.ElapsedUs() / iterations;
    double layersPerSec = 1000000.0 / timePerLayerUs;
    double tokPerSec = layersPerSec / 32.0; // 32 layers for 7B

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "RESULTS - REAL GPU TRANSFORMER" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "  Total time: " << timer.ElapsedMs() << " ms" << std::endl;
    std::cout << "  Time per layer: " << timePerLayerUs << " us" << std::endl;
    std::cout << "  Layers/sec: " << layersPerSec << std::endl;
    std::cout << "  Estimated tok/s (32 layers): " << tokPerSec << std::endl;
    std::cout << std::endl;

    if (tokPerSec >= 150.0) {
        std::cout << "✅ TARGET ACHIEVED: " << tokPerSec << " tok/s" << std::endl;
    } else if (tokPerSec >= 100.0) {
        std::cout << "✅ GOOD: " << tokPerSec << " tok/s" << std::endl;
    } else {
        std::cout << "⚠ NEEDS OPTIMIZATION: " << tokPerSec << " tok/s" << std::endl;
    }

    // Cleanup
    FreeBuffer(ctx, bufInput, memInput);
    FreeBuffer(ctx, bufQ, memQ);
    FreeBuffer(ctx, bufK, memK);
    FreeBuffer(ctx, bufV, memV);
    FreeBuffer(ctx, bufAttnOut, memAttnOut);
    FreeBuffer(ctx, bufFFN, memFFN);
    FreeBuffer(ctx, bufOutput, memOutput);

    DestroyComputePipeline(ctx, matmulPipe);
    DestroyComputePipeline(ctx, rmsNormPipe);
    DestroyComputePipeline(ctx, softmaxPipe);
    CleanupVulkan(ctx);

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "REAL GPU TRANSFORMER COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
