// ============================================================================
// Vulkan Executor - Real GPU Kernel Execution
// ============================================================================

#include "vulkan_executor.hpp"
#include "shaders/embedded_shaders.hpp"

namespace RawrXD {
namespace Inference {

// FP16 conversion helpers are inline in header

bool VulkanExecutor::Initialize() {
    if (initialized_) return true;

    std::cout << "[VulkanExecutor] Initializing...\n";

    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD";
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    if (vkCreateInstance(&createInfo, nullptr, &instance_) != VK_SUCCESS) {
        std::cerr << "[VulkanExecutor] Failed to create instance\n";
        return false;
    }

    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance_, &deviceCount, nullptr);
    if (deviceCount == 0) {
        std::cerr << "[VulkanExecutor] No Vulkan devices found\n";
        return false;
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance_, &deviceCount, devices.data());

    for (auto& dev : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(dev, &props);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            physicalDevice_ = dev;
            deviceName_ = props.deviceName;
            std::cout << "[VulkanExecutor] GPU: " << props.deviceName << "\n";
            break;
        }
    }

    if (!physicalDevice_) {
        physicalDevice_ = devices[0];
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(physicalDevice_, &props);
        deviceName_ = props.deviceName;
        std::cout << "[VulkanExecutor] GPU: " << props.deviceName << " (fallback)\n";
    }

    uint32_t queueFamilyCount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice_, &queueFamilyCount, nullptr);
    std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
    vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice_, &queueFamilyCount, queueFamilies.data());

    computeQueueFamily_ = 0;
    for (uint32_t i = 0; i < queueFamilyCount; i++) {
        if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            computeQueueFamily_ = i;
            break;
        }
    }

    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo = {};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = computeQueueFamily_;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkDeviceCreateInfo deviceCreateInfo = {};
    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;

    if (vkCreateDevice(physicalDevice_, &deviceCreateInfo, nullptr, &device_) != VK_SUCCESS) {
        std::cerr << "[VulkanExecutor] Failed to create device\n";
        return false;
    }

    vkGetDeviceQueue(device_, computeQueueFamily_, 0, &queue_);

    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = computeQueueFamily_;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    if (vkCreateCommandPool(device_, &poolInfo, nullptr, &commandPool_) != VK_SUCCESS) {
        std::cerr << "[VulkanExecutor] Failed to create command pool\n";
        return false;
    }

    VkDescriptorPoolSize poolSize = {};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 100;

    VkDescriptorPoolCreateInfo descriptorPoolInfo = {};
    descriptorPoolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    descriptorPoolInfo.maxSets = 100;
    descriptorPoolInfo.poolSizeCount = 1;
    descriptorPoolInfo.pPoolSizes = &poolSize;

    if (vkCreateDescriptorPool(device_, &descriptorPoolInfo, nullptr, &descriptorPool_) != VK_SUCCESS) {
        std::cerr << "[VulkanExecutor] Failed to create descriptor pool\n";
        return false;
    }

    if (!LoadShaders()) {
        std::cerr << "[VulkanExecutor] Failed to load shaders\n";
        return false;
    }

    initialized_ = true;
    std::cout << "[VulkanExecutor] Ready for GPU execution\n";
    return true;
}

void VulkanExecutor::Cleanup() {
    if (!initialized_) return;

    for (auto& pipeline : pipelines_) {
        if (pipeline.second.pipeline) vkDestroyPipeline(device_, pipeline.second.pipeline, nullptr);
        if (pipeline.second.layout) vkDestroyPipelineLayout(device_, pipeline.second.layout, nullptr);
        if (pipeline.second.descriptorSetLayout) vkDestroyDescriptorSetLayout(device_, pipeline.second.descriptorSetLayout, nullptr);
    }
    pipelines_.clear();

    if (descriptorPool_) vkDestroyDescriptorPool(device_, descriptorPool_, nullptr);
    if (commandPool_) vkDestroyCommandPool(device_, commandPool_, nullptr);
    if (device_) vkDestroyDevice(device_, nullptr);
    if (instance_) vkDestroyInstance(instance_, nullptr);

    initialized_ = false;
}

bool VulkanExecutor::ExecuteMatMulFP16(const std::vector<float>& A, const std::vector<float>& B,
                                       std::vector<float>& C, uint32_t M, uint32_t N, uint32_t K) {
    if (!initialized_) {
        std::cerr << "[VulkanExecutor] Not initialized\n";
        return false;
    }

    std::cout << "[VulkanExecutor] MatMul: " << M << "x" << K << " * " << K << "x" << N << " = " << M << "x" << N << "\n";

    std::vector<uint16_t> A_fp16(A.size());
    std::vector<uint16_t> B_fp16(B.size());
    for (size_t i = 0; i < A.size(); i++) A_fp16[i] = FloatToFP16(A[i]);
    for (size_t i = 0; i < B.size(); i++) B_fp16[i] = FloatToFP16(B[i]);

    VkDeviceSize sizeA = A_fp16.size() * sizeof(uint16_t);
    VkDeviceSize sizeB = B_fp16.size() * sizeof(uint16_t);
    VkDeviceSize sizeC = M * N * sizeof(uint16_t);

    VulkanBuffer bufferA, bufferB, bufferC;
    if (!CreateBuffer(sizeA, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, bufferA)) return false;
    if (!CreateBuffer(sizeB, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, bufferB)) return false;
    if (!CreateBuffer(sizeC, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, bufferC)) return false;

    UploadBuffer(bufferA, A_fp16.data(), sizeA);
    UploadBuffer(bufferB, B_fp16.data(), sizeB);

    auto it = pipelines_.find("matmul_fp16");
    if (it == pipelines_.end()) {
        std::cerr << "[VulkanExecutor] MatMul pipeline not found\n";
        return false;
    }

    VkDescriptorSet descriptorSet;
    VkDescriptorSetAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    allocInfo.descriptorPool = descriptorPool_;
    allocInfo.descriptorSetCount = 1;
    allocInfo.pSetLayouts = &it->second.descriptorSetLayout;

    if (vkAllocateDescriptorSets(device_, &allocInfo, &descriptorSet) != VK_SUCCESS) {
        std::cerr << "[VulkanExecutor] Failed to allocate descriptor set\n";
        return false;
    }

    VkDescriptorBufferInfo bufferInfoA = {};
    bufferInfoA.buffer = bufferA.buffer;
    bufferInfoA.range = sizeA;

    VkDescriptorBufferInfo bufferInfoB = {};
    bufferInfoB.buffer = bufferB.buffer;
    bufferInfoB.range = sizeB;

    VkDescriptorBufferInfo bufferInfoC = {};
    bufferInfoC.buffer = bufferC.buffer;
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

    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);

    struct PushConstants {
        uint32_t M, N, K;
        uint32_t lda, ldb, ldc;
    } pc = {M, N, K, K, N, N};

    VkCommandBuffer commandBuffer = BeginCommandBuffer();

    vkCmdBindPipeline(commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, it->second.pipeline);
    vkCmdBindDescriptorSets(commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, it->second.layout, 0, 1, &descriptorSet, 0, nullptr);
    vkCmdPushConstants(commandBuffer, it->second.layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);

    uint32_t groupsX = (M + 15) / 16;
    uint32_t groupsY = (N + 15) / 16;
    vkCmdDispatch(commandBuffer, groupsX, groupsY, 1);

    EndCommandBuffer(commandBuffer);

    std::vector<uint16_t> C_fp16(M * N);
    DownloadBuffer(bufferC, C_fp16.data(), sizeC);

    C.resize(M * N);
    for (size_t i = 0; i < C.size(); i++) {
        C[i] = FP16ToFloat(C_fp16[i]);
    }

    DestroyBuffer(bufferA);
    DestroyBuffer(bufferB);
    DestroyBuffer(bufferC);
    vkFreeDescriptorSets(device_, descriptorPool_, 1, &descriptorSet);

    std::cout << "[VulkanExecutor] MatMul complete\n";
    return true;
}

bool VulkanExecutor::LoadShaders() {
    std::cout << "[VulkanExecutor] Loading shaders...\n";

    if (!CreateComputePipeline("matmul_fp16", MATMUL_FP16_SPV, MATMUL_FP16_SPV_SIZE * sizeof(uint32_t))) {
        std::cerr << "[VulkanExecutor] Failed to load matmul_fp16\n";
        return false;
    }
    std::cout << "[VulkanExecutor] Loaded matmul_fp16\n";

    return true;
}

bool VulkanExecutor::CreateComputePipeline(const std::string& name, const uint32_t* code, size_t codeSize) {
    VkShaderModuleCreateInfo shaderInfo = {};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = codeSize;
    shaderInfo.pCode = code;

    VkShaderModule shaderModule;
    if (vkCreateShaderModule(device_, &shaderInfo, nullptr, &shaderModule) != VK_SUCCESS) {
        std::cerr << "[VulkanExecutor] Failed to create shader module for " << name << "\n";
        return false;
    }

    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }

    VkDescriptorSetLayoutCreateInfo layoutInfo = {};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = 3;
    layoutInfo.pBindings = bindings;

    VkDescriptorSetLayout descriptorSetLayout;
    if (vkCreateDescriptorSetLayout(device_, &layoutInfo, nullptr, &descriptorSetLayout) != VK_SUCCESS) {
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        return false;
    }

    VkPushConstantRange pushConstantRange = {};
    pushConstantRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pushConstantRange.offset = 0;
    pushConstantRange.size = 128;

    VkPipelineLayoutCreateInfo pipelineLayoutInfo = {};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &descriptorSetLayout;
    pipelineLayoutInfo.pushConstantRangeCount = 1;
    pipelineLayoutInfo.pPushConstantRanges = &pushConstantRange;

    VkPipelineLayout pipelineLayout;
    if (vkCreatePipelineLayout(device_, &pipelineLayoutInfo, nullptr, &pipelineLayout) != VK_SUCCESS) {
        vkDestroyDescriptorSetLayout(device_, descriptorSetLayout, nullptr);
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        return false;
    }

    VkComputePipelineCreateInfo pipelineInfo = {};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipelineInfo.stage.module = shaderModule;
    pipelineInfo.stage.pName = "main";
    pipelineInfo.layout = pipelineLayout;

    VkPipeline pipeline;
    if (vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline) != VK_SUCCESS) {
        vkDestroyPipelineLayout(device_, pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(device_, descriptorSetLayout, nullptr);
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        return false;
    }

    PipelineInfo info;
    info.pipeline = pipeline;
    info.layout = pipelineLayout;
    info.descriptorSetLayout = descriptorSetLayout;
    pipelines_[name] = info;

    vkDestroyShaderModule(device_, shaderModule, nullptr);
    return true;
}

bool VulkanExecutor::CreateBuffer(VkDeviceSize size, VkBufferUsageFlags usage, VulkanBuffer& buffer) {
    VkBufferCreateInfo bufferInfo = {};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = size;
    bufferInfo.usage = usage | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    if (vkCreateBuffer(device_, &bufferInfo, nullptr, &buffer.buffer) != VK_SUCCESS) {
        return false;
    }

    VkMemoryRequirements memRequirements;
    vkGetBufferMemoryRequirements(device_, buffer.buffer, &memRequirements);

    VkMemoryAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memRequirements.size;
    allocInfo.memoryTypeIndex = FindMemoryType(memRequirements.memoryTypeBits,
                                                VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                                VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);

    if (vkAllocateMemory(device_, &allocInfo, nullptr, &buffer.memory) != VK_SUCCESS) {
        vkDestroyBuffer(device_, buffer.buffer, nullptr);
        return false;
    }

    vkBindBufferMemory(device_, buffer.buffer, buffer.memory, 0);
    buffer.size = size;
    vkMapMemory(device_, buffer.memory, 0, size, 0, &buffer.mapped);
    return true;
}

void VulkanExecutor::DestroyBuffer(VulkanBuffer& buffer) {
    if (buffer.mapped) vkUnmapMemory(device_, buffer.memory);
    if (buffer.memory) vkFreeMemory(device_, buffer.memory, nullptr);
    if (buffer.buffer) vkDestroyBuffer(device_, buffer.buffer, nullptr);
}

void VulkanExecutor::UploadBuffer(VulkanBuffer& buffer, const void* data, VkDeviceSize size) {
    if (buffer.mapped && size <= buffer.size) {
        std::memcpy(buffer.mapped, data, size);
    }
}

void VulkanExecutor::DownloadBuffer(VulkanBuffer& buffer, void* data, VkDeviceSize size) {
    if (buffer.mapped && size <= buffer.size) {
        std::memcpy(data, buffer.mapped, size);
    }
}

uint32_t VulkanExecutor::FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties) {
    VkPhysicalDeviceMemoryProperties memProperties;
    vkGetPhysicalDeviceMemoryProperties(physicalDevice_, &memProperties);
    for (uint32_t i = 0; i < memProperties.memoryTypeCount; i++) {
        if ((typeFilter & (1 << i)) &&
            (memProperties.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }
    return 0;
}

VkCommandBuffer VulkanExecutor::BeginCommandBuffer() {
    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandPool = commandPool_;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer commandBuffer;
    vkAllocateCommandBuffers(device_, &allocInfo, &commandBuffer);

    VkCommandBufferBeginInfo beginInfo = {};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    vkBeginCommandBuffer(commandBuffer, &beginInfo);
    return commandBuffer;
}

void VulkanExecutor::EndCommandBuffer(VkCommandBuffer commandBuffer) {
    vkEndCommandBuffer(commandBuffer);

    VkSubmitInfo submitInfo = {};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &commandBuffer;

    vkQueueSubmit(queue_, 1, &submitInfo, VK_NULL_HANDLE);
    vkQueueWaitIdle(queue_);

    vkFreeCommandBuffers(device_, commandPool_, 1, &commandBuffer);
}

} // namespace Inference
} // namespace RawrXD
