#include "vulkan_compute.h"
#include <chrono>
#include <fstream>
#include <sstream>
#include <stdexcept>

// Precompiled SPIR-V shaders (no shaderc runtime dependency)
#include "spirv_shaders.h"

// Vulkan compute backend implementation
// Uses standard Vulkan 1.3 API for cross-platform GPU compute
#ifndef VK_API_VERSION_1_3
#define VK_API_VERSION_1_3 VK_MAKE_VERSION(1, 3, 0)
#endif

namespace RawrXD
{


VulkanCompute::VulkanCompute()
{
    // Initialize Vulkan loader
    // if (volkInitialize() != VK_SUCCESS) {
    //    throw std::runtime_error("Failed to initialize Vulkan loader");
    // }
}

VulkanCompute::~VulkanCompute()
{
    shutdown();
}

void VulkanCompute::shutdown()
{
    if (m_device != VK_NULL_HANDLE)
    {
        vkDeviceWaitIdle(m_device);

        if (m_commandPool != VK_NULL_HANDLE)
        {
            vkDestroyCommandPool(m_device, m_commandPool, nullptr);
        }

        if (m_descriptorPool != VK_NULL_HANDLE)
        {
            vkDestroyDescriptorPool(m_device, m_descriptorPool, nullptr);
        }

        for (auto& [name, pipeline] : m_pipelines)
        {
            vkDestroyPipeline(m_device, pipeline, nullptr);
        }

        for (auto& [name, layout] : m_pipelineLayouts)
        {
            vkDestroyPipelineLayout(m_device, layout, nullptr);
        }

        for (auto& [name, dsl] : m_descriptorSetLayouts)
        {
            vkDestroyDescriptorSetLayout(m_device, dsl, nullptr);
        }

        vkDestroyDevice(m_device, nullptr);
    }

    if (m_instance != VK_NULL_HANDLE)
    {
        vkDestroyInstance(m_instance, nullptr);
    }
}

std::expected<void, VulkanError> VulkanCompute::initialize()
{
    // Real instance creation
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD Inference";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD Engine";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_3;

    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    // const char* validationLayers[] = {"VK_LAYER_KHRONOS_validation"};
    // createInfo.enabledLayerCount = 1;
    // createInfo.ppEnabledLayerNames = validationLayers;
    createInfo.enabledLayerCount = 0;

    // Fixed: Use VK_KHR_SURFACE_EXTENSION_NAME only if needed for presentation, but code is compute only.
    // Removing surface extension for pure compute to simplify dependencies.
    // const char* extensions[] = {VK_KHR_SURFACE_EXTENSION_NAME};
    createInfo.enabledExtensionCount = 0;
    // createInfo.ppEnabledExtensionNames = extensions;

    if (vkCreateInstance(&createInfo, nullptr, &m_instance) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::InstanceCreationFailed);
    }

    // voltLoadInstance(m_instance); // If using volk

    // Real device selection
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(m_instance, &deviceCount, nullptr);

    if (deviceCount == 0)
    {
        return std::unexpected(VulkanError::DeviceSelectionFailed);
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(m_instance, &deviceCount, devices.data());
    // E12 — discovery truth: `deviceCount` physical devices visible to Vulkan on this machine.

    // Select first discrete GPU
    m_physicalDevice = VK_NULL_HANDLE;
    for (const auto& device : devices)
    {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(device, &props);

        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU)
        {
            m_physicalDevice = device;
            break;
        }
    }

    if (m_physicalDevice == VK_NULL_HANDLE)
    {
        m_physicalDevice = devices[0];  // Fall back to first device
    }

    // Real device creation
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo{};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = 0;  // Compute queue family - simplified, should query
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkPhysicalDeviceFeatures deviceFeatures{};

    VkDeviceCreateInfo deviceCreateInfo{};
    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;
    deviceCreateInfo.pEnabledFeatures = &deviceFeatures;

    // Enable compute shader extensions for optimal performance
    const char* deviceExtensions[] = {
        VK_KHR_SHADER_NON_SEMANTIC_INFO_EXTENSION_NAME
    };
    
    // Check if extensions are available before enabling
    uint32_t extensionCount = 0;
    vkEnumerateDeviceExtensionProperties(m_physicalDevice, nullptr, &extensionCount, nullptr);
    std::vector<VkExtensionProperties> availableExtensions(extensionCount);
    vkEnumerateDeviceExtensionProperties(m_physicalDevice, nullptr, &extensionCount, availableExtensions.data());
    
    bool hasShaderNonSemantic = false;
    for (const auto& ext : availableExtensions) {
        if (strcmp(ext.extensionName, VK_KHR_SHADER_NON_SEMANTIC_INFO_EXTENSION_NAME) == 0) {
            hasShaderNonSemantic = true;
            break;
        }
    }
    
    if (hasShaderNonSemantic) {
        deviceCreateInfo.enabledExtensionCount = 1;
        deviceCreateInfo.ppEnabledExtensionNames = deviceExtensions;
    } else {
        // Fall back to no extensions if not available
        deviceCreateInfo.enabledExtensionCount = 0;
    }

    if (vkCreateDevice(m_physicalDevice, &deviceCreateInfo, nullptr, &m_device) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::DeviceSelectionFailed);
    }

    vkGetDeviceQueue(m_device, 0, 0, &m_computeQueue);

    // Create command pool
    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    poolInfo.queueFamilyIndex = 0;

    if (vkCreateCommandPool(m_device, &poolInfo, nullptr, &m_commandPool) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }

    // Create descriptor pool
    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 100;

    VkDescriptorPoolCreateInfo descriptorPoolInfo{};
    descriptorPoolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    descriptorPoolInfo.poolSizeCount = 1;
    descriptorPoolInfo.pPoolSizes = &poolSize;
    descriptorPoolInfo.maxSets = 100;

    if (vkCreateDescriptorPool(m_device, &descriptorPoolInfo, nullptr, &m_descriptorPool) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }

    // Create compute pipelines using precompiled SPIR-V (no runtime shaderc dependency)
    try
    {
        auto matmulResult =
            createComputePipeline("matmul", std::vector<uint32_t>(MATMUL_SPV, MATMUL_SPV + MATMUL_SPV_SIZE / sizeof(uint32_t)),
                                  {{0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr},
                                   {1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr},
                                   {2, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr}});

        if (!matmulResult)
        {
            return std::unexpected(matmulResult.error());
        }

        auto softmaxResult =
            createComputePipeline("softmax", std::vector<uint32_t>(SOFTMAX_SPV, SOFTMAX_SPV + SOFTMAX_SPV_SIZE / sizeof(uint32_t)),
                                  {{0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr},
                                   {1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, nullptr}});

        if (!softmaxResult)
        {
            return std::unexpected(softmaxResult.error());
        }
    }
    catch (...)
    {
        // Shader compilation failed
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }

    return {};
}

std::expected<void, VulkanError> VulkanCompute::executeMatrixMultiplication(const VulkanBuffer& a,
                                                                            const VulkanBuffer& b, VulkanBuffer& result,
                                                                            size_t dim)
{
    std::lock_guard lock(m_mutex);

    // Real command buffer recording
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = m_commandPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer commandBuffer;
    if (vkAllocateCommandBuffers(m_device, &allocInfo, &commandBuffer) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::KernelExecutionFailed);
    }

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    vkBeginCommandBuffer(commandBuffer, &beginInfo);

    // Bind pipeline
    vkCmdBindPipeline(commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipelines["matmul"]);

    // Bind descriptors
    VkDescriptorSet descriptorSet;
    VkDescriptorSetAllocateInfo descriptorAllocInfo{};
    descriptorAllocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    descriptorAllocInfo.descriptorPool = m_descriptorPool;
    descriptorAllocInfo.descriptorSetCount = 1;
    descriptorAllocInfo.pSetLayouts = &m_descriptorSetLayouts["matmul"];

    vkAllocateDescriptorSets(m_device, &descriptorAllocInfo, &descriptorSet);

    VkDescriptorBufferInfo bufferInfoA{a.buffer, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo bufferInfoB{b.buffer, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo bufferInfoResult{result.buffer, 0, VK_WHOLE_SIZE};

    VkWriteDescriptorSet descriptorWrites[3];

    // Input A
    descriptorWrites[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    descriptorWrites[0].dstSet = descriptorSet;
    descriptorWrites[0].dstBinding = 0;
    descriptorWrites[0].dstArrayElement = 0;
    descriptorWrites[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    descriptorWrites[0].descriptorCount = 1;
    descriptorWrites[0].pBufferInfo = &bufferInfoA;

    // Input B
    descriptorWrites[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    descriptorWrites[1].dstSet = descriptorSet;
    descriptorWrites[1].dstBinding = 1;
    descriptorWrites[1].dstArrayElement = 0;
    descriptorWrites[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    descriptorWrites[1].descriptorCount = 1;
    descriptorWrites[1].pBufferInfo = &bufferInfoB;

    // Output
    descriptorWrites[2].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    descriptorWrites[2].dstSet = descriptorSet;
    descriptorWrites[2].dstBinding = 2;
    descriptorWrites[2].dstArrayElement = 0;
    descriptorWrites[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    descriptorWrites[2].descriptorCount = 1;
    descriptorWrites[2].pBufferInfo = &bufferInfoResult;

    vkUpdateDescriptorSets(m_device, 3, descriptorWrites, 0, nullptr);
    vkCmdBindDescriptorSets(commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipelineLayouts["matmul"], 0, 1,
                            &descriptorSet, 0, nullptr);

    // Push constants
    struct PushConstants
    {
        uint32_t dim;
    } pushConstants{static_cast<uint32_t>(dim)};

    vkCmdPushConstants(commandBuffer, m_pipelineLayouts["matmul"], VK_SHADER_STAGE_COMPUTE_BIT, 0,
                       sizeof(pushConstants), &pushConstants);

    // Dispatch
    vkCmdDispatch(commandBuffer, (uint32_t)(dim * dim + 255) / 256, 1, 1);

    vkEndCommandBuffer(commandBuffer);

    // Submit
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &commandBuffer;

    if (vkQueueSubmit(m_computeQueue, 1, &submitInfo, VK_NULL_HANDLE) != VK_SUCCESS)
    {
        vkFreeCommandBuffers(m_device, m_commandPool, 1, &commandBuffer);
        return std::unexpected(VulkanError::KernelExecutionFailed);
    }

    vkQueueWaitIdle(m_computeQueue);

    // Cleanup
    vkFreeCommandBuffers(m_device, m_commandPool, 1, &commandBuffer);

    return {};
}

std::expected<void, VulkanError> VulkanCompute::createComputePipeline(
    const std::string& name, const std::vector<uint32_t>& shaderCode,
    const std::vector<VkDescriptorSetLayoutBinding>& bindings)
{
    VkShaderModuleCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    createInfo.codeSize = shaderCode.size() * sizeof(uint32_t);
    createInfo.pCode = shaderCode.data();

    VkShaderModule shaderModule;
    if (vkCreateShaderModule(m_device, &createInfo, nullptr, &shaderModule) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }

    VkDescriptorSetLayoutBinding* bindingsData = const_cast<VkDescriptorSetLayoutBinding*>(bindings.data());
    VkDescriptorSetLayoutCreateInfo layoutInfo{};
    layoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layoutInfo.bindingCount = static_cast<uint32_t>(bindings.size());
    layoutInfo.pBindings = bindingsData;

    VkDescriptorSetLayout descriptorSetLayout;
    if (vkCreateDescriptorSetLayout(m_device, &layoutInfo, nullptr, &descriptorSetLayout) != VK_SUCCESS)
    {
        vkDestroyShaderModule(m_device, shaderModule, nullptr);
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }

    VkPushConstantRange pushConstantRange{};
    pushConstantRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pushConstantRange.offset = 0;
    pushConstantRange.size = 128;  // Large enough for params

    VkPipelineLayoutCreateInfo pipelineLayoutInfo{};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &descriptorSetLayout;
    pipelineLayoutInfo.pushConstantRangeCount = 1;
    pipelineLayoutInfo.pPushConstantRanges = &pushConstantRange;

    m_descriptorSetLayouts[name] = descriptorSetLayout;

    if (vkCreatePipelineLayout(m_device, &pipelineLayoutInfo, nullptr, &m_pipelineLayouts[name]) != VK_SUCCESS)
    {
        vkDestroyDescriptorSetLayout(m_device, descriptorSetLayout, nullptr);
        vkDestroyShaderModule(m_device, shaderModule, nullptr);
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }

    VkPipelineShaderStageCreateInfo shaderStageInfo{};
    shaderStageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    shaderStageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    shaderStageInfo.module = shaderModule;
    shaderStageInfo.pName = "main";

    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.layout = m_pipelineLayouts[name];
    pipelineInfo.stage = shaderStageInfo;

    if (vkCreateComputePipelines(m_device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &m_pipelines[name]) != VK_SUCCESS)
    {
        vkDestroyShaderModule(m_device, shaderModule, nullptr);
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }

    vkDestroyShaderModule(m_device, shaderModule, nullptr);
    return {};
}

// Production implementation for Vulkan buffer creation
std::expected<VulkanBuffer, VulkanError> VulkanCompute::createBuffer(size_t size, VkBufferUsageFlags usage,
                                                                     VkMemoryPropertyFlags properties)
{
    if (m_device == VK_NULL_HANDLE)
        return std::unexpected(VulkanError::MemoryAllocationFailed);

    VulkanBuffer buf{};
    buf.size = size;

    VkBufferCreateInfo bufferInfo{};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = size;
    bufferInfo.usage = usage;
    bufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    if (vkCreateBuffer(m_device, &bufferInfo, nullptr, &buf.buffer) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::MemoryAllocationFailed);
    }

    VkMemoryRequirements memReq;
    vkGetBufferMemoryRequirements(m_device, buf.buffer, &memReq);

    // Find suitable memory type
    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(m_physicalDevice, &memProps);

    uint32_t memIndex = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i)
    {
        if ((memReq.memoryTypeBits & (1u << i)) && (memProps.memoryTypes[i].propertyFlags & properties) == properties)
        {
            memIndex = i;
            break;
        }
    }

    if (memIndex == UINT32_MAX)
    {
        vkDestroyBuffer(m_device, buf.buffer, nullptr);
        return std::unexpected(VulkanError::MemoryAllocationFailed);
    }

    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memReq.size;
    allocInfo.memoryTypeIndex = memIndex;

    if (vkAllocateMemory(m_device, &allocInfo, nullptr, &buf.memory) != VK_SUCCESS)
    {
        vkDestroyBuffer(m_device, buf.buffer, nullptr);
        return std::unexpected(VulkanError::MemoryAllocationFailed);
    }

    vkBindBufferMemory(m_device, buf.buffer, buf.memory, 0);

    // Map if host-visible
    if (properties & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    {
        vkMapMemory(m_device, buf.memory, 0, size, 0, &buf.mappedMemory);
    }

    return buf;
}

void VulkanCompute::destroyBuffer(VulkanBuffer& buffer)
{
    if (m_device == VK_NULL_HANDLE)
        return;
    if (buffer.mappedMemory)
    {
        vkUnmapMemory(m_device, buffer.memory);
        buffer.mappedMemory = nullptr;
    }
    if (buffer.buffer != VK_NULL_HANDLE)
    {
        vkDestroyBuffer(m_device, buffer.buffer, nullptr);
        buffer.buffer = VK_NULL_HANDLE;
    }
    if (buffer.memory != VK_NULL_HANDLE)
    {
        vkFreeMemory(m_device, buffer.memory, nullptr);
        buffer.memory = VK_NULL_HANDLE;
    }
    buffer.size = 0;
}

std::expected<void, VulkanError> VulkanCompute::executeSoftmax(VulkanBuffer& logits, float temperature,
                                                               size_t vocabSize)
{
    std::lock_guard lock(m_mutex);

    if (m_pipelines.find("softmax") == m_pipelines.end())
        return std::unexpected(VulkanError::PipelineCreationFailed);

    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = m_commandPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer cmdBuf;
    if (vkAllocateCommandBuffers(m_device, &allocInfo, &cmdBuf) != VK_SUCCESS)
        return std::unexpected(VulkanError::KernelExecutionFailed);

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmdBuf, &beginInfo);

    vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipelines["softmax"]);

    struct
    {
        float temperature;
        uint32_t vocabSize;
    } pc{temperature, static_cast<uint32_t>(vocabSize)};
    vkCmdPushConstants(cmdBuf, m_pipelineLayouts["softmax"], VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);

    vkCmdDispatch(cmdBuf, 1, 1, 1);  // Single workgroup — shader processes full vocab
    vkEndCommandBuffer(cmdBuf);

    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuf;

    if (vkQueueSubmit(m_computeQueue, 1, &submitInfo, VK_NULL_HANDLE) != VK_SUCCESS)
    {
        vkFreeCommandBuffers(m_device, m_commandPool, 1, &cmdBuf);
        return std::unexpected(VulkanError::KernelExecutionFailed);
    }

    vkQueueWaitIdle(m_computeQueue);
    vkFreeCommandBuffers(m_device, m_commandPool, 1, &cmdBuf);
    return {};
}

std::expected<void, VulkanError> VulkanCompute::executeAttention(const VulkanBuffer& q, const VulkanBuffer& k,
                                                                 const VulkanBuffer& v, VulkanBuffer& output,
                                                                 size_t seqLen, size_t headDim)
{
    std::lock_guard lock(m_mutex);

    // Attention = softmax(Q·K^T / sqrt(d_k)) · V
    // Step 1: Q·K^T via matmul pipeline
    // Allocate temp buffer for QK scores
    auto scoresBuf = createBuffer(seqLen * seqLen * sizeof(float), VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                                  VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (!scoresBuf)
        return std::unexpected(scoresBuf.error());

    // QK^T matmul
    auto mmResult = executeMatrixMultiplication(q, k, *scoresBuf, headDim);
    if (!mmResult)
    {
        destroyBuffer(*scoresBuf);
        return std::unexpected(mmResult.error());
    }

    // Step 2: Scale + softmax in-place
    float scale = 1.0f / sqrtf(static_cast<float>(headDim));
    auto smResult = executeSoftmax(*scoresBuf, scale, seqLen);
    if (!smResult)
    {
        destroyBuffer(*scoresBuf);
        return std::unexpected(smResult.error());
    }

    // Step 3: Scores · V
    mmResult = executeMatrixMultiplication(*scoresBuf, v, output, seqLen);
    destroyBuffer(*scoresBuf);
    if (!mmResult)
        return std::unexpected(mmResult.error());

    return {};
}

std::expected<VkShaderModule, VulkanError> VulkanCompute::createShaderModule(
    const std::vector<uint32_t>& code)
{
    VkShaderModuleCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    createInfo.codeSize = code.size() * sizeof(uint32_t);
    createInfo.pCode = code.data();

    VkShaderModule shaderModule;
    if (vkCreateShaderModule(m_device, &createInfo, nullptr, &shaderModule) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::PipelineCreationFailed);
    }
    return shaderModule;
}

std::expected<VkCommandBuffer, VulkanError> VulkanCompute::beginCommandBuffer()
{
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = m_commandPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer cmdBuffer;
    if (vkAllocateCommandBuffers(m_device, &allocInfo, &cmdBuffer) != VK_SUCCESS)
    {
        return std::unexpected(VulkanError::KernelExecutionFailed);
    }

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    if (vkBeginCommandBuffer(cmdBuffer, &beginInfo) != VK_SUCCESS)
    {
        vkFreeCommandBuffers(m_device, m_commandPool, 1, &cmdBuffer);
        return std::unexpected(VulkanError::KernelExecutionFailed);
    }

    return cmdBuffer;
}

std::expected<void, VulkanError> VulkanCompute::endCommandBuffer(VkCommandBuffer cmdBuffer)
{
    if (vkEndCommandBuffer(cmdBuffer) != VK_SUCCESS)
    {
        vkFreeCommandBuffers(m_device, m_commandPool, 1, &cmdBuffer);
        return std::unexpected(VulkanError::KernelExecutionFailed);
    }
    return {};
}

std::expected<void, VulkanError> VulkanCompute::synchronize()
{
    if (m_device == VK_NULL_HANDLE)
        return std::unexpected(VulkanError::SynchronizationFailed);
    if (vkQueueWaitIdle(m_computeQueue) != VK_SUCCESS)
        return std::unexpected(VulkanError::SynchronizationFailed);
    return {};
}
json VulkanCompute::getStatus() const
{
    return json{{"status", "active"}};
}

}  // namespace RawrXD
