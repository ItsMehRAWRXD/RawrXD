// ============================================================================
// flash_attention_vulkan_fp8.cpp — Vulkan FP8 flash attention dispatch
// ============================================================================
// Real Vulkan compute path for flash_attention_fp8_e4m3.comp.
//
// Buffers are packed uint32 arrays holding little-endian E4M3 bytes:
//   Q/K/V : [headOrKvHead][seqLen][headDim] packed 4-per-uint
//   O     : [head][seqLenM][headDim] float32
//
// Dispatch grid: x = seqLenM (one workgroup per query row), y = numHeads, z = 1.

#include "flash_attention_vulkan_fp8.h"

#include <cstring>
#include <mutex>
#include <unordered_map>

#ifndef RAWRXD_FA8_SPIRV_PATH
#define RAWRXD_FA8_SPIRV_PATH "flash_attention_fp8_e4m3.spv"
#endif

namespace RawrXD
{
namespace
{

constexpr uint32_t kBindingCount = 4;
constexpr uint32_t kMaxHeadDim = 128u;
constexpr uint32_t kLocalSizeX = 64u;

struct Fa8Pipeline
{
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkPipelineLayout pipelineLayout = VK_NULL_HANDLE;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    VkShaderModule shaderModule = VK_NULL_HANDLE;
    VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
    VkDescriptorSet descriptorSet = VK_NULL_HANDLE;
};

std::mutex g_mutex;
std::unordered_map<VkDevice, Fa8Pipeline> g_pipelines;

bool LoadSpirv(std::vector<uint32_t>& words, std::string& error)
{
    FILE* f = std::fopen(RAWRXD_FA8_SPIRV_PATH, "rb");
    if (!f)
    {
        error = std::string("cannot open ") + RAWRXD_FA8_SPIRV_PATH;
        return false;
    }
    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (size <= 0 || (size % 4) != 0)
    {
        std::fclose(f);
        error = "SPIR-V size is not a positive multiple of 4";
        return false;
    }
    words.resize(static_cast<size_t>(size) / 4u);
    const size_t got = std::fread(words.data(), 1, static_cast<size_t>(size), f);
    std::fclose(f);
    if (got != static_cast<size_t>(size))
    {
        error = "short read on SPIR-V";
        return false;
    }
    if (words[0] != 0x07230203u)
    {
        error = "SPIR-V magic mismatch";
        return false;
    }
    return true;
}

Fa8Pipeline* FindPipeline(VkDevice device)
{
    auto it = g_pipelines.find(device);
    return (it == g_pipelines.end()) ? nullptr : &it->second;
}

}  // namespace

bool ValidateFlashAttentionFP8Push(const FlashAttentionFP8PushConstants& c, std::string& error)
{
    if (c.seqLenM == 0 || c.seqLenN == 0 || c.headDim == 0 || c.numHeads == 0 || c.numKVHeads == 0)
    {
        error = "seqLenM/seqLenN/headDim/numHeads/numKVHeams must all be non-zero";
        return false;
    }
    if (c.headDim > kMaxHeadDim)
    {
        error = "headDim exceeds the shader's 128-element shared accumulator";
        return false;
    }
    if (c.numKVHeads > c.numHeads)
    {
        error = "numKVHeads cannot exceed numHeads";
        return false;
    }
    if (c.qScale == 0.0f || c.kScale == 0.0f || c.vScale == 0.0f)
    {
        error = "qScale/kScale/vScale must be non-zero";
        return false;
    }
    return true;
}

bool CreateFlashAttentionFP8Pipeline(VkDevice device, std::string& error)
{
    if (device == VK_NULL_HANDLE)
    {
        error = "null VkDevice";
        return false;
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_pipelines.count(device))
    {
        return true;  // idempotent
    }

    std::vector<uint32_t> spirv;
    if (!LoadSpirv(spirv, error))
    {
        return false;
    }

    Fa8Pipeline p;

    VkDescriptorSetLayoutBinding bindings[kBindingCount]{};
    for (uint32_t i = 0; i < kBindingCount; ++i)
    {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo setLayoutInfo{};
    setLayoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    setLayoutInfo.bindingCount = kBindingCount;
    setLayoutInfo.pBindings = bindings;
    if (vkCreateDescriptorSetLayout(device, &setLayoutInfo, nullptr, &p.setLayout) != VK_SUCCESS)
    {
        error = "vkCreateDescriptorSetLayout failed";
        return false;
    }

    VkPushConstantRange pushRange{};
    pushRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pushRange.offset = 0;
    pushRange.size = sizeof(FlashAttentionFP8PushConstants);
    VkPipelineLayoutCreateInfo layoutInfo{};
    layoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    layoutInfo.setLayoutCount = 1;
    layoutInfo.pSetLayouts = &p.setLayout;
    layoutInfo.pushConstantRangeCount = 1;
    layoutInfo.pPushConstantRanges = &pushRange;
    if (vkCreatePipelineLayout(device, &layoutInfo, nullptr, &p.pipelineLayout) != VK_SUCCESS)
    {
        error = "vkCreatePipelineLayout failed";
        return false;
    }

    VkShaderModuleCreateInfo moduleInfo{};
    moduleInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    moduleInfo.codeSize = spirv.size() * sizeof(uint32_t);
    moduleInfo.pCode = spirv.data();
    if (vkCreateShaderModule(device, &moduleInfo, nullptr, &p.shaderModule) != VK_SUCCESS)
    {
        error = "vkCreateShaderModule failed";
        return false;
    }

    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipelineInfo.stage.module = p.shaderModule;
    pipelineInfo.stage.pName = "main";
    pipelineInfo.layout = p.pipelineLayout;
    if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &p.pipeline) !=
        VK_SUCCESS)
    {
        error = "vkCreateComputePipelines failed";
        return false;
    }

    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = kBindingCount;
    VkDescriptorPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.maxSets = 1;
    poolInfo.poolSizeCount = 1;
    poolInfo.pPoolSizes = &poolSize;
    if (vkCreateDescriptorPool(device, &poolInfo, nullptr, &p.descriptorPool) != VK_SUCCESS)
    {
        error = "vkCreateDescriptorPool failed";
        return false;
    }

    VkDescriptorSetAllocateInfo setAlloc{};
    setAlloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    setAlloc.descriptorPool = p.descriptorPool;
    setAlloc.descriptorSetCount = 1;
    setAlloc.pSetLayouts = &p.setLayout;
    if (vkAllocateDescriptorSets(device, &setAlloc, &p.descriptorSet) != VK_SUCCESS)
    {
        error = "vkAllocateDescriptorSets failed";
        return false;
    }

    g_pipelines.emplace(device, p);
    return true;
}

bool BindFlashAttentionFP8Buffers(VkDevice device,
                                  VkDescriptorPool descriptorPool,
                                  VkBuffer qBuffer,
                                  VkBuffer kBuffer,
                                  VkBuffer vBuffer,
                                  VkBuffer oBuffer)
{
    (void)descriptorPool;  // the pipeline owns a dedicated pool
    if (device == VK_NULL_HANDLE)
    {
        return false;
    }
    const VkBuffer buffers[kBindingCount] = {qBuffer, kBuffer, vBuffer, oBuffer};

    std::lock_guard<std::mutex> lock(g_mutex);
    Fa8Pipeline* p = FindPipeline(device);
    if (!p)
    {
        return false;
    }

    VkDescriptorBufferInfo infos[kBindingCount]{};
    VkWriteDescriptorSet writes[kBindingCount]{};
    for (uint32_t i = 0; i < kBindingCount; ++i)
    {
        if (buffers[i] == VK_NULL_HANDLE)
        {
            return false;
        }
        infos[i].buffer = buffers[i];
        infos[i].offset = 0;
        infos[i].range = VK_WHOLE_SIZE;
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = p->descriptorSet;
        writes[i].dstBinding = i;
        writes[i].dstArrayElement = 0;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &infos[i];
    }
    vkUpdateDescriptorSets(device, kBindingCount, writes, 0, nullptr);
    return true;
}

bool DispatchFlashAttentionVulkanFP8(VkDevice device,
                                     VkQueue queue,
                                     VkCommandPool commandPool,
                                     VkBuffer qBuffer,
                                     VkBuffer kBuffer,
                                     VkBuffer vBuffer,
                                     VkBuffer oBuffer,
                                     const FlashAttentionFP8PushConstants& constants)
{
    std::string error;
    if (!ValidateFlashAttentionFP8Push(constants, error))
    {
        return false;
    }
    if (!CreateFlashAttentionFP8Pipeline(device, error))
    {
        return false;
    }
    if (!BindFlashAttentionFP8Buffers(device, VK_NULL_HANDLE, qBuffer, kBuffer, vBuffer, oBuffer))
    {
        return false;
    }

    Fa8Pipeline* p = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        p = FindPipeline(device);
    }
    if (!p || queue == VK_NULL_HANDLE || commandPool == VK_NULL_HANDLE)
    {
        return false;
    }

    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = commandPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    if (vkAllocateCommandBuffers(device, &allocInfo, &cmd) != VK_SUCCESS)
    {
        return false;
    }

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &beginInfo);

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, p->pipeline);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, p->pipelineLayout, 0, 1,
                            &p->descriptorSet, 0, nullptr);
    vkCmdPushConstants(cmd, p->pipelineLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0,
                       sizeof(FlashAttentionFP8PushConstants), &constants);

    // Make prior writes to Q/K/V/O visible to the compute stage.
    VkBufferMemoryBarrier preBarriers[kBindingCount]{};
    VkBuffer preBuffers[kBindingCount] = {qBuffer, kBuffer, vBuffer, oBuffer};
    for (uint32_t i = 0; i < kBindingCount; ++i)
    {
        preBarriers[i].sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        preBarriers[i].srcAccessMask = VK_ACCESS_HOST_WRITE_BIT;
        preBarriers[i].dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT;
        preBarriers[i].srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        preBarriers[i].dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        preBarriers[i].buffer = preBuffers[i];
        preBarriers[i].offset = 0;
        preBarriers[i].size = VK_WHOLE_SIZE;
    }
    vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_HOST_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0,
                         0, nullptr, kBindingCount, preBarriers, 0, nullptr);

    vkCmdDispatch(cmd, constants.seqLenM, constants.numHeads, 1);

    // O becomes host-readable after the dispatch.
    VkBufferMemoryBarrier postBarrier{};
    postBarrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    postBarrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    postBarrier.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    postBarrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    postBarrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    postBarrier.buffer = oBuffer;
    postBarrier.offset = 0;
    postBarrier.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0,
                         0, nullptr, 1, &postBarrier, 0, nullptr);

    vkEndCommandBuffer(cmd);

    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &cmd;

    bool ok = false;
    if (vkQueueSubmit(queue, 1, &submitInfo, VK_NULL_HANDLE) == VK_SUCCESS)
    {
        ok = (vkQueueWaitIdle(queue) == VK_SUCCESS);
    }

    vkFreeCommandBuffers(device, commandPool, 1, &cmd);
    return ok;
}

void DestroyFlashAttentionFP8Pipeline(VkDevice device)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_pipelines.find(device);
    if (it == g_pipelines.end())
    {
        return;
    }
    Fa8Pipeline& p = it->second;
    if (p.descriptorPool)
    {
        vkDestroyDescriptorPool(device, p.descriptorPool, nullptr);
    }
    if (p.pipeline)
    {
        vkDestroyPipeline(device, p.pipeline, nullptr);
    }
    if (p.pipelineLayout)
    {
        vkDestroyPipelineLayout(device, p.pipelineLayout, nullptr);
    }
    if (p.setLayout)
    {
        vkDestroyDescriptorSetLayout(device, p.setLayout, nullptr);
    }
    if (p.shaderModule)
    {
        vkDestroyShaderModule(device, p.shaderModule, nullptr);
    }
    g_pipelines.erase(it);
}

}  // namespace RawrXD