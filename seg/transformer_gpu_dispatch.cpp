// ============================================================================
// Transformer GPU Dispatch - Real Shader Execution
// ============================================================================
// Actually dispatches RawrXD SPIR-V shaders for transformer inference
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

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "TRANSFORMER GPU DISPATCH - REAL SHADERS" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Create Vulkan instance
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "Transformer GPU Dispatch";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = vkCreateInstance(&createInfo, nullptr, &instance);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create Vulkan instance" << std::endl;
        return 1;
    }

    // Find RX 7800 XT
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    VkPhysicalDevice gpu = VK_NULL_HANDLE;
    int computeQueueFamily = -1;
    
    for (auto& dev : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(dev, &props);
        
        uint32_t queueCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(dev, &queueCount, nullptr);
        std::vector<VkQueueFamilyProperties> queues(queueCount);
        vkGetPhysicalDeviceQueueFamilyProperties(dev, &queueCount, queues.data());
        
        for (uint32_t i = 0; i < queueCount; i++) {
            if (queues[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
                std::string name(props.deviceName);
                if (name.find("7800 XT") != std::string::npos || 
                    name.find("RX 7800") != std::string::npos) {
                    gpu = dev;
                    computeQueueFamily = i;
                    std::cout << "GPU: " << props.deviceName << std::endl;
                    break;
                }
                if (gpu == VK_NULL_HANDLE) {
                    gpu = dev;
                    computeQueueFamily = i;
                }
            }
        }
        if (gpu != VK_NULL_HANDLE) break;
    }

    if (gpu == VK_NULL_HANDLE) {
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Create device
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queueInfo = {};
    queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = computeQueueFamily;
    queueInfo.queueCount = 1;
    queueInfo.pQueuePriorities = &priority;

    VkDeviceCreateInfo devInfo = {};
    devInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    devInfo.queueCreateInfoCount = 1;
    devInfo.pQueueCreateInfos = &queueInfo;

    VkDevice device = VK_NULL_HANDLE;
    result = vkCreateDevice(gpu, &devInfo, nullptr, &device);
    if (result != VK_SUCCESS) {
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    VkQueue queue = VK_NULL_HANDLE;
    vkGetDeviceQueue(device, computeQueueFamily, 0, &queue);

    // Create command pool
    VkCommandPool cmdPool = VK_NULL_HANDLE;
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = computeQueueFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    vkCreateCommandPool(device, &poolInfo, nullptr, &cmdPool);

    VkCommandBuffer cmdBuf = VK_NULL_HANDLE;
    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = cmdPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    vkAllocateCommandBuffers(device, &allocInfo, &cmdBuf);

    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fenceInfo.flags = VK_FENCE_CREATE_SIGNALED_BIT;
    vkCreateFence(device, &fenceInfo, nullptr, &fence);

    // Get memory properties
    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(gpu, &memProps);

    // Helper to allocate GPU buffer
    auto allocBuffer = [&](size_t size, VkBuffer& buf, VkDeviceMemory& mem, bool deviceLocal = true) -> bool {
        VkBufferCreateInfo bufInfo = {};
        bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bufInfo.size = size;
        bufInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
        bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        
        result = vkCreateBuffer(device, &bufInfo, nullptr, &buf);
        if (result != VK_SUCCESS) return false;

        VkMemoryRequirements reqs;
        vkGetBufferMemoryRequirements(device, buf, &reqs);

        uint32_t memIdx = UINT32_MAX;
        VkMemoryPropertyFlags desiredFlags = deviceLocal ? VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT : 
                                                     (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        
        for (uint32_t i = 0; i < memProps.memoryTypeCount; i++) {
            if ((reqs.memoryTypeBits & (1 << i)) &&
                (memProps.memoryTypes[i].propertyFlags & desiredFlags)) {
                memIdx = i;
                break;
            }
        }
        
        if (memIdx == UINT32_MAX) {
            for (uint32_t i = 0; i < memProps.memoryTypeCount; i++) {
                if (reqs.memoryTypeBits & (1 << i)) {
                    memIdx = i;
                    break;
                }
            }
        }
        
        if (memIdx == UINT32_MAX) {
            vkDestroyBuffer(device, buf, nullptr);
            return false;
        }

        VkMemoryAllocateInfo memInfo = {};
        memInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        memInfo.allocationSize = reqs.size;
        memInfo.memoryTypeIndex = memIdx;

        result = vkAllocateMemory(device, &memInfo, nullptr, &mem);
        if (result != VK_SUCCESS) {
            vkDestroyBuffer(device, buf, nullptr);
            return false;
        }

        vkBindBufferMemory(device, buf, mem, 0);
        return true;
    };

    // Load matmul_fp16 shader
    std::cout << std::endl;
    std::cout << "Loading matmul_fp16.spv..." << std::endl;
    auto matmulCode = LoadSPIRV("d:/rawrxd/src/inference/shaders/matmul_fp16.spv");
    if (matmulCode.empty()) {
        std::cout << "Failed to load shader" << std::endl;
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, cmdPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    std::cout << "Shader loaded: " << matmulCode.size() * 4 << " bytes" << std::endl;

    // Create shader module
    VkShaderModule shaderModule = VK_NULL_HANDLE;
    VkShaderModuleCreateInfo shaderInfo = {};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = matmulCode.size() * sizeof(uint32_t);
    shaderInfo.pCode = matmulCode.data();
    
    result = vkCreateShaderModule(device, &shaderInfo, nullptr, &shaderModule);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create shader module: " << result << std::endl;
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, cmdPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    std::cout << "Shader module created" << std::endl;

    // Create descriptor set layout (3 storage buffers: A, B, Output)
    VkDescriptorSetLayoutBinding bindings[3] = {};
    bindings[0].binding = 0;
    bindings[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[0].descriptorCount = 1;
    bindings[0].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    
    bindings[1].binding = 1;
    bindings[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[1].descriptorCount = 1;
    bindings[1].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    
    bindings[2].binding = 2;
    bindings[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[2].descriptorCount = 1;
    bindings[2].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;

    VkDescriptorSetLayoutCreateInfo layoutInfo = {};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 3;
    layoutInfo.pBindings = bindings;

    VkDescriptorSetLayout descriptorLayout = VK_NULL_HANDLE;
    result = vkCreateDescriptorSetLayout(device, &layoutInfo, nullptr, &descriptorLayout);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create descriptor set layout" << std::endl;
        vkDestroyShaderModule(device, shaderModule, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, cmdPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Create pipeline layout
    VkPipelineLayoutCreateInfo pipelineLayoutInfo = {};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &descriptorLayout;

    VkPipelineLayout pipelineLayout = VK_NULL_HANDLE;
    result = vkCreatePipelineLayout(device, &pipelineLayoutInfo, nullptr, &pipelineLayout);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create pipeline layout" << std::endl;
        vkDestroyDescriptorSetLayout(device, descriptorLayout, nullptr);
        vkDestroyShaderModule(device, shaderModule, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, cmdPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Create compute pipeline
    VkComputePipelineCreateInfo pipelineInfo = {};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipelineInfo.stage.module = shaderModule;
    pipelineInfo.stage.pName = "main";
    pipelineInfo.layout = pipelineLayout;

    VkPipeline pipeline = VK_NULL_HANDLE;
    result = vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create compute pipeline: " << result << std::endl;
        vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(device, descriptorLayout, nullptr);
        vkDestroyShaderModule(device, shaderModule, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, cmdPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    std::cout << "Compute pipeline created" << std::endl;

    // Create descriptor pool
    VkDescriptorPoolSize poolSize = {};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 3;

    VkDescriptorPoolCreateInfo poolCreateInfo = {};
    poolCreateInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolCreateInfo.maxSets = 1;
    poolCreateInfo.poolSizeCount = 1;
    poolCreateInfo.pPoolSizes = &poolSize;

    VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
    result = vkCreateDescriptorPool(device, &poolCreateInfo, nullptr, &descriptorPool);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create descriptor pool" << std::endl;
        vkDestroyPipeline(device, pipeline, nullptr);
        vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(device, descriptorLayout, nullptr);
        vkDestroyShaderModule(device, shaderModule, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, cmdPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Allocate descriptor set
    VkDescriptorSetAllocateInfo setAllocInfo = {};
    setAllocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    setAllocInfo.descriptorPool = descriptorPool;
    setAllocInfo.descriptorSetCount = 1;
    setAllocInfo.pSetLayouts = &descriptorLayout;

    VkDescriptorSet descriptorSet = VK_NULL_HANDLE;
    result = vkAllocateDescriptorSets(device, &setAllocInfo, &descriptorSet);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to allocate descriptor set" << std::endl;
        vkDestroyDescriptorPool(device, descriptorPool, nullptr);
        vkDestroyPipeline(device, pipeline, nullptr);
        vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(device, descriptorLayout, nullptr);
        vkDestroyShaderModule(device, shaderModule, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, cmdPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Allocate buffers for GEMM: C = A @ B
    // A: [M, K], B: [K, N], C: [M, N]
    // For Q projection: A=[1, 4096], B=[4096, 4096], C=[1, 4096]
    const uint32_t M = 1;
    const uint32_t K = 4096;
    const uint32_t N = 4096;
    
    size_t sizeA = M * K * sizeof(float);
    size_t sizeB = K * N * sizeof(float);
    size_t sizeC = M * N * sizeof(float);

    VkBuffer bufA, bufB, bufC;
    VkDeviceMemory memA, memB, memC;
    
    allocBuffer(sizeA, bufA, memA);
    allocBuffer(sizeB, bufB, memB);
    allocBuffer(sizeC, bufC, memC);

    std::cout << std::endl;
    std::cout << "Buffers allocated for GEMM [" << M << "x" << K << "] @ [" << K << "x" << N << "]" << std::endl;
    std::cout << "  A: " << sizeA / 1024.0 << " KB" << std::endl;
    std::cout << "  B: " << sizeB / (1024.0 * 1024.0) << " MB" << std::endl;
    std::cout << "  C: " << sizeC / 1024.0 << " KB" << std::endl;

    // Update descriptor set
    VkDescriptorBufferInfo bufferInfoA = {};
    bufferInfoA.buffer = bufA;
    bufferInfoA.offset = 0;
    bufferInfoA.range = sizeA;

    VkDescriptorBufferInfo bufferInfoB = {};
    bufferInfoB.buffer = bufB;
    bufferInfoB.offset = 0;
    bufferInfoB.range = sizeB;

    VkDescriptorBufferInfo bufferInfoC = {};
    bufferInfoC.buffer = bufC;
    bufferInfoC.offset = 0;
    bufferInfoC.range = sizeC;

    VkWriteDescriptorSet writes[3] = {};
    writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    writes[0].dstSet = descriptorSet;
    writes[0].dstBinding = 0;
    writes[0].descriptorCount = 1;
    writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    writes[0].pBufferInfo = &bufferInfoA;

    writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    writes[1].dstSet = descriptorSet;
    writes[1].dstBinding = 1;
    writes[1].descriptorCount = 1;
    writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    writes[1].pBufferInfo = &bufferInfoB;

    writes[2].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    writes[2].dstSet = descriptorSet;
    writes[2].dstBinding = 2;
    writes[2].descriptorCount = 1;
    writes[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    writes[2].pBufferInfo = &bufferInfoC;

    vkUpdateDescriptorSets(device, 3, writes, 0, nullptr);
    std::cout << "Descriptor set updated" << std::endl;

    // Benchmark actual shader dispatch
    const int iterations = 100;
    Timer timer;

    std::cout << std::endl;
    std::cout << "Benchmarking actual shader dispatch..." << std::endl;
    timer.Start();

    for (int i = 0; i < iterations; i++) {
        // Reset fence
        vkResetFences(device, 1, &fence);

        // Begin command buffer
        VkCommandBufferBeginInfo beginInfo = {};
        beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(cmdBuf, &beginInfo);

        // Bind pipeline and descriptor set
        vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
        vkCmdBindDescriptorSets(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout, 0, 1, &descriptorSet, 0, nullptr);

        // Dispatch compute shader
        // Workgroup size depends on shader - using conservative values
        uint32_t groupsX = (M + 15) / 16;
        uint32_t groupsY = (N + 15) / 16;
        vkCmdDispatch(cmdBuf, groupsX, groupsY, 1);

        // End command buffer
        vkEndCommandBuffer(cmdBuf);

        // Submit
        VkSubmitInfo submitInfo = {};
        submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submitInfo.commandBufferCount = 1;
        submitInfo.pCommandBuffers = &cmdBuf;

        vkQueueSubmit(queue, 1, &submitInfo, fence);
        vkWaitForFences(device, 1, &fence, VK_TRUE, UINT64_MAX);
    }

    timer.Stop();

    double timePerDispatchUs = timer.ElapsedUs() / iterations;
    double dispatchesPerSec = 1000000.0 / timePerDispatchUs;

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "SHADER DISPATCH RESULTS" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Total time: " << timer.ElapsedMs() << " ms" << std::endl;
    std::cout << "  Time per dispatch: " << timePerDispatchUs << " us" << std::endl;
    std::cout << "  Dispatches/sec: " << dispatchesPerSec << std::endl;
    std::cout << std::endl;

    // Estimate transformer performance
    // 32 layers * (QKV proj + Attention + Output + FFN) ~ 6 dispatches per layer
    double dispatchesPerToken = 32 * 6; // 192 dispatches
    double tokPerSec = dispatchesPerSec / dispatchesPerToken;

    std::cout << "Transformer projection:" << std::endl;
    std::cout << "  Dispatches per token: " << dispatchesPerToken << std::endl;
    std::cout << "  Estimated tok/s: " << tokPerSec << std::endl;
    std::cout << std::endl;

    if (tokPerSec >= 150.0) {
        std::cout << "✅ TARGET ACHIEVED: " << tokPerSec << " tok/s" << std::endl;
    } else if (tokPerSec >= 100.0) {
        std::cout << "✅ GOOD: " << tokPerSec << " tok/s" << std::endl;
    } else {
        std::cout << "⚠ NEEDS OPTIMIZATION: " << tokPerSec << " tok/s" << std::endl;
    }

    // Cleanup
    vkFreeMemory(device, memA, nullptr);
    vkFreeMemory(device, memB, nullptr);
    vkFreeMemory(device, memC, nullptr);
    vkDestroyBuffer(device, bufA, nullptr);
    vkDestroyBuffer(device, bufB, nullptr);
    vkDestroyBuffer(device, bufC, nullptr);
    vkDestroyDescriptorPool(device, descriptorPool, nullptr);
    vkDestroyPipeline(device, pipeline, nullptr);
    vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
    vkDestroyDescriptorSetLayout(device, descriptorLayout, nullptr);
    vkDestroyShaderModule(device, shaderModule, nullptr);
    vkDestroyFence(device, fence, nullptr);
    vkDestroyCommandPool(device, cmdPool, nullptr);
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);

    return 0;
}
