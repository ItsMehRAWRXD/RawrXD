// ============================================================================
// VulkanGemmDispatcher.cpp
// Pre-compiled SPIR-V GEMM dispatcher — no runtime shader compilation.
// ============================================================================
#include "VulkanGemmDispatcher.hpp"
#include <cstdio>
#include <fstream>

namespace RawrXD {

VulkanGemmDispatcher::VulkanGemmDispatcher() = default;
VulkanGemmDispatcher::~VulkanGemmDispatcher() { Shutdown(); }

bool VulkanGemmDispatcher::LoadSpirv(const std::string& path, std::vector<uint32_t>& outCode) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        printf("[VulkanGemmDispatcher] Failed to open SPIR-V: %s\n", path.c_str());
        return false;
    }
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    outCode.resize(size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(outCode.data()), size);
    printf("[VulkanGemmDispatcher] Loaded SPIR-V: %s (%zu bytes)\n", path.c_str(), size);
    return true;
}

bool VulkanGemmDispatcher::CreatePipeline(const std::vector<uint32_t>& code) {
    VkShaderModuleCreateInfo shaderInfo{};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = code.size() * sizeof(uint32_t);
    shaderInfo.pCode = code.data();

    VkShaderModule shaderModule = VK_NULL_HANDLE;
    if (vkCreateShaderModule(m_device, &shaderInfo, nullptr, &shaderModule) != VK_SUCCESS) {
        printf("[VulkanGemmDispatcher] vkCreateShaderModule failed\n");
        return false;
    }

    // Descriptor set layout: 3 storage buffers (weight, input, output)
    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }

    VkDescriptorSetLayoutCreateInfo dslInfo{};
    dslInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dslInfo.bindingCount = 3;
    dslInfo.pBindings = bindings;
    if (vkCreateDescriptorSetLayout(m_device, &dslInfo, nullptr, &m_dsLayout) != VK_SUCCESS) {
        printf("[VulkanGemmDispatcher] vkCreateDescriptorSetLayout failed\n");
        vkDestroyShaderModule(m_device, shaderModule, nullptr);
        return false;
    }

    // Push constants: M, N, K
    VkPushConstantRange pcRange{};
    pcRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pcRange.offset = 0;
    pcRange.size = sizeof(uint32_t) * 3;

    VkPipelineLayoutCreateInfo plInfo{};
    plInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    plInfo.setLayoutCount = 1;
    plInfo.pSetLayouts = &m_dsLayout;
    plInfo.pushConstantRangeCount = 1;
    plInfo.pPushConstantRanges = &pcRange;
    if (vkCreatePipelineLayout(m_device, &plInfo, nullptr, &m_pipelineLayout) != VK_SUCCESS) {
        printf("[VulkanGemmDispatcher] vkCreatePipelineLayout failed\n");
        vkDestroyDescriptorSetLayout(m_device, m_dsLayout, nullptr);
        vkDestroyShaderModule(m_device, shaderModule, nullptr);
        return false;
    }

    VkPipelineShaderStageCreateInfo stageInfo{};
    stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stageInfo.module = shaderModule;
    stageInfo.pName = "main";

    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.layout = m_pipelineLayout;
    pipelineInfo.stage = stageInfo;

    VkResult result = vkCreateComputePipelines(m_device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &m_pipeline);
    vkDestroyShaderModule(m_device, shaderModule, nullptr); // safe after pipeline creation

    if (result != VK_SUCCESS) {
        printf("[VulkanGemmDispatcher] vkCreateComputePipelines failed (VkResult=%d)\n", static_cast<int>(result));
        vkDestroyPipelineLayout(m_device, m_pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(m_device, m_dsLayout, nullptr);
        return false;
    }

    // Descriptor pool
    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 3;

    VkDescriptorPoolCreateInfo dpInfo{};
    dpInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpInfo.maxSets = 1;
    dpInfo.poolSizeCount = 1;
    dpInfo.pPoolSizes = &poolSize;
    if (vkCreateDescriptorPool(m_device, &dpInfo, nullptr, &m_descPool) != VK_SUCCESS) {
        vkDestroyPipeline(m_device, m_pipeline, nullptr);
        vkDestroyPipelineLayout(m_device, m_pipelineLayout, nullptr);
        vkDestroyDescriptorSetLayout(m_device, m_dsLayout, nullptr);
        return false;
    }

    printf("[VulkanGemmDispatcher] Pipeline created successfully\n");
    return true;
}

bool VulkanGemmDispatcher::Initialize(VkDevice device, VkQueue queue, VkCommandPool commandPool,
                                      const std::string& spirvPath) {
    if (m_initialized) Shutdown();

    m_device = device;
    m_queue = queue;
    m_cmdPool = commandPool;

    std::vector<uint32_t> spirvCode;
    if (!LoadSpirv(spirvPath, spirvCode)) {
        return false;
    }

    if (!CreatePipeline(spirvCode)) {
        return false;
    }

    m_initialized = true;
    printf("[VulkanGemmDispatcher] Initialized (device=%p, queue=%p, pool=%p)\n",
           (void*)m_device, (void*)m_queue, (void*)m_cmdPool);
    return true;
}

void VulkanGemmDispatcher::Shutdown() {
    if (!m_initialized) return;

    if (m_descPool) vkDestroyDescriptorPool(m_device, m_descPool, nullptr);
    if (m_pipeline) vkDestroyPipeline(m_device, m_pipeline, nullptr);
    if (m_pipelineLayout) vkDestroyPipelineLayout(m_device, m_pipelineLayout, nullptr);
    if (m_dsLayout) vkDestroyDescriptorSetLayout(m_device, m_dsLayout, nullptr);

    m_descPool = VK_NULL_HANDLE;
    m_pipeline = VK_NULL_HANDLE;
    m_pipelineLayout = VK_NULL_HANDLE;
    m_dsLayout = VK_NULL_HANDLE;
    m_device = VK_NULL_HANDLE;
    m_queue = VK_NULL_HANDLE;
    m_cmdPool = VK_NULL_HANDLE;
    m_initialized = false;
}

bool VulkanGemmDispatcher::DispatchGemm(VkBuffer weightBuffer, VkBuffer inputBuffer, VkBuffer outputBuffer,
                                          uint32_t M, uint32_t N, uint32_t K) {
    if (!m_initialized) {
        printf("[VulkanGemmDispatcher] Not initialized\n");
        return false;
    }

    // Allocate command buffer
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = m_cmdPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    VkCommandBuffer cmdBuf = VK_NULL_HANDLE;
    if (vkAllocateCommandBuffers(m_device, &allocInfo, &cmdBuf) != VK_SUCCESS) {
        printf("[VulkanGemmDispatcher] vkAllocateCommandBuffers failed\n");
        return false;
    }

    // Allocate descriptor set
    VkDescriptorSetAllocateInfo dsAllocInfo{};
    dsAllocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dsAllocInfo.descriptorPool = m_descPool;
    dsAllocInfo.descriptorSetCount = 1;
    dsAllocInfo.pSetLayouts = &m_dsLayout;

    VkDescriptorSet ds = VK_NULL_HANDLE;
    if (vkAllocateDescriptorSets(m_device, &dsAllocInfo, &ds) != VK_SUCCESS) {
        vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);
        return false;
    }

    // Write descriptors
    VkDescriptorBufferInfo dbiWeight{weightBuffer, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo dbiInput{inputBuffer, 0, VK_WHOLE_SIZE};
    VkDescriptorBufferInfo dbiOutput{outputBuffer, 0, VK_WHOLE_SIZE};

    VkWriteDescriptorSet writes[3] = {};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiWeight;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiInput;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiOutput;
    vkUpdateDescriptorSets(m_device, 3, writes, 0, nullptr);

    // Record command buffer
    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmdBuf, &beginInfo);

    vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipeline);
    vkCmdBindDescriptorSets(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipelineLayout, 0, 1, &ds, 0, nullptr);

    uint32_t pushConsts[3] = {M, N, K};
    vkCmdPushConstants(cmdBuf, m_pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pushConsts), pushConsts);

    // Dispatch: local_size = 8×8×1 in shader
    vkCmdDispatch(cmdBuf, (M + 7) / 8, (N + 7) / 8, 1);

    // Barrier: ensure shader writes complete before any subsequent read
    VkBufferMemoryBarrier barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_TRANSFER_READ_BIT;
    barrier.buffer = outputBuffer;
    barrier.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(cmdBuf, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,
                         0, 0, nullptr, 1, &barrier, 0, nullptr);

    vkEndCommandBuffer(cmdBuf);

    // Submit and wait
    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(m_device, &fenceInfo, nullptr, &fence);

    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmdBuf;

    VkResult result = vkQueueSubmit(m_queue, 1, &submitInfo, fence);
    if (result != VK_SUCCESS) {
        printf("[VulkanGemmDispatcher] vkQueueSubmit failed (VkResult=%d)\n", static_cast<int>(result));
        vkDestroyFence(m_device, fence, nullptr);
        vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);
        return false;
    }

    vkWaitForFences(m_device, 1, &fence, VK_TRUE, 10000000000ULL);

    // Cleanup
    vkDestroyFence(m_device, fence, nullptr);
    vkFreeCommandBuffers(m_device, m_cmdPool, 1, &cmdBuf);

    return true;
}

} // namespace RawrXD
