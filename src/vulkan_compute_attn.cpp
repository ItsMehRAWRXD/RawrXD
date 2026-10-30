// DEEP2_VULKAN_SUBMIT_OPT_001: QuantDot-stack GQA AttnDecode (single CB).
// Linked with vulkan_compute.cpp; uses private members declared in the header.
#include "../include/vulkan_compute.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_MSC_VER) || defined(__x86_64__)
#include <immintrin.h>
#endif

namespace {
struct AttnPush {
    uint32_t headDim = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t seqLen = 0;
    uint32_t kvDim = 0;
    uint32_t pad0 = 0;
    float scale = 1.0f;
    float pad1 = 0.0f;
};
static_assert(sizeof(AttnPush) == 32, "AttnPush must match quant_attn_decode.comp");

VkResult WaitAttnFence(VkDevice device, VkFence fence) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    for (;;) {
        const VkResult status = vkGetFenceStatus(device, fence);
        if (status == VK_SUCCESS) return VK_SUCCESS;
        if (status != VK_NOT_READY) return status;
        if (std::chrono::steady_clock::now() >= deadline) return VK_TIMEOUT;
#if defined(_MSC_VER) || defined(__x86_64__)
        _mm_pause();
#else
        std::this_thread::yield();
#endif
    }
}

bool GrowDevBuf(VkDevice device, const VkPhysicalDeviceMemoryProperties& mem_props,
                VkBuffer& buf, VkDeviceMemory& mem, size_t& cap, size_t need) {
    if (buf && cap >= need) return true;
    if (buf) {
        vkDestroyBuffer(device, buf, nullptr);
        vkFreeMemory(device, mem, nullptr);
        buf = nullptr; mem = nullptr; cap = 0;
    }
    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = need ? need : 1u;
    bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT |
               VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device, &bi, nullptr, &buf) != VK_SUCCESS) return false;
    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(device, buf, &mr);
    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = mr.size;
    ai.memoryTypeIndex = UINT32_MAX;
    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        const auto& mt = mem_props.memoryTypes[i];
        if ((mr.memoryTypeBits & (1u << i)) &&
            (mt.propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            ai.memoryTypeIndex = i;
            break;
        }
    }
    if (ai.memoryTypeIndex == UINT32_MAX) return false;
    if (vkAllocateMemory(device, &ai, nullptr, &mem) != VK_SUCCESS) return false;
    if (vkBindBufferMemory(device, buf, mem, 0) != VK_SUCCESS) return false;
    cap = need;
    return true;
}
}  // namespace

bool VulkanCompute::EnsureAttnDecodePipeline() {
    if (shaders_.count("attn_decode") && shaders_["attn_decode"].pipeline &&
        shaders_["attn_decode"].layout && attn_set_layout_) {
        return true;
    }
    std::vector<uint32_t> code;
    std::vector<std::string> candidates = {
        "F:\\rawrxd\\tools\\shaders\\quant_attn_decode.spv",
        "tools/shaders/quant_attn_decode.spv",
    };
    if (const char* ov = std::getenv("RAWRXD_ATTN_DECODE_SHADER"); ov && *ov)
        candidates.insert(candidates.begin(), ov);
    std::string selected;
    for (const auto& c : candidates) {
        if (LoadSPIRVCode(c, code) && !code.empty()) { selected = c; break; }
        code.clear();
    }
    if (selected.empty()) {
        std::cerr << "[ATTN_DECODE] SPIR-V missing (quant_attn_decode.spv)\n";
        return false;
    }

    ComputeShader cs;
    cs.name = "attn_decode";
    cs.spirv_code = code;
    VkShaderModuleCreateInfo sm{};
    sm.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm.codeSize = code.size() * sizeof(uint32_t);
    sm.pCode = code.data();
    if (vkCreateShaderModule(device_, &sm, nullptr, &cs.module) != VK_SUCCESS)
        return false;

    VkDescriptorSetLayoutBinding binds[4] = {};
    for (uint32_t i = 0; i < 4; ++i) {
        binds[i].binding = i;
        binds[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        binds[i].descriptorCount = 1;
        binds[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dsl{};
    dsl.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dsl.bindingCount = 4;
    dsl.pBindings = binds;
    if (vkCreateDescriptorSetLayout(device_, &dsl, nullptr, &attn_set_layout_) != VK_SUCCESS)
        return false;

    VkPushConstantRange pcr{};
    pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pcr.offset = 0;
    pcr.size = sizeof(AttnPush);
    VkPipelineLayoutCreateInfo pl{};
    pl.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl.setLayoutCount = 1;
    pl.pSetLayouts = &attn_set_layout_;
    pl.pushConstantRangeCount = 1;
    pl.pPushConstantRanges = &pcr;
    if (vkCreatePipelineLayout(device_, &pl, nullptr, &cs.layout) != VK_SUCCESS)
        return false;

    VkPipelineShaderStageCreateInfo stage{};
    stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage.module = cs.module;
    stage.pName = "main";
    VkComputePipelineCreateInfo cp{};
    cp.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp.stage = stage;
    cp.layout = cs.layout;
    if (vkCreateComputePipelines(device_, nullptr, 1, &cp, nullptr, &cs.pipeline) != VK_SUCCESS)
        return false;

    shaders_["attn_decode"] = cs;
    return true;
}

bool VulkanCompute::ExecuteAttnDecodeGqa(
    const float* q, size_t q_floats,
    const float* k_cache, size_t k_floats,
    const float* v_cache, size_t v_floats,
    float* out, size_t out_floats,
    uint32_t head_dim, uint32_t heads, uint32_t kv_heads,
    uint32_t seq_len, float scale) {
    if (!device_ || !compute_queue_ || !q || !k_cache || !v_cache || !out)
        return false;
    if (!head_dim || !heads || !kv_heads || !seq_len) return false;
    if ((heads % kv_heads) != 0u) return false;
    // Shader shared score scratch is 256 floats (sealed decode=32 fits).
    if (seq_len > 256u || head_dim > 256u) return false;
    const uint32_t kv_dim = kv_heads * head_dim;
    const size_t need_q = size_t(heads) * head_dim;
    const size_t need_kv = size_t(seq_len) * kv_dim;
    if (q_floats < need_q || k_floats < need_kv || v_floats < need_kv ||
        out_floats < need_q) {
        return false;
    }
    if (!EnsureAttnDecodePipeline()) return false;
    if (!EnsureQuantFastPath()) return false;
    auto sh = shaders_.find("attn_decode");
    if (sh == shaders_.end() || !sh->second.pipeline || !attn_set_layout_)
        return false;

    const size_t q_bytes = need_q * sizeof(float);
    const size_t kv_bytes = need_kv * sizeof(float);
    const size_t o_bytes = need_q * sizeof(float);

    if (!GrowDevBuf(device_, device_info_.memory_props, attn_q_dev_, attn_q_mem_,
                    attn_q_cap_, q_bytes)) return false;
    if (!GrowDevBuf(device_, device_info_.memory_props, attn_k_dev_, attn_k_mem_,
                    attn_k_cap_, kv_bytes)) return false;
    if (!GrowDevBuf(device_, device_info_.memory_props, attn_v_dev_, attn_v_mem_,
                    attn_v_cap_, kv_bytes)) return false;
    if (!GrowDevBuf(device_, device_info_.memory_props, attn_o_dev_, attn_o_mem_,
                    attn_o_cap_, o_bytes)) return false;

    if (!EnsureHostVisible(q_bytes, attn_stage_q_, attn_stage_q_mem_,
                           attn_stage_q_sz_, attn_stage_q_map_)) return false;
    if (!EnsureHostVisible(kv_bytes, attn_stage_k_, attn_stage_k_mem_,
                           attn_stage_k_sz_, attn_stage_k_map_)) return false;
    if (!EnsureHostVisible(kv_bytes, attn_stage_v_, attn_stage_v_mem_,
                           attn_stage_v_sz_, attn_stage_v_map_)) return false;
    if (!EnsureHostVisible(o_bytes, attn_stage_o_, attn_stage_o_mem_,
                           attn_stage_o_sz_, attn_stage_o_map_)) return false;

    std::memcpy(attn_stage_q_map_, q, q_bytes);
    std::memcpy(attn_stage_k_map_, k_cache, kv_bytes);
    std::memcpy(attn_stage_v_map_, v_cache, kv_bytes);
    gpu_counters_.upload_bytes += q_bytes + 2 * kv_bytes;

    if (!attn_desc_pool_) {
        VkDescriptorPoolSize ps{};
        ps.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        ps.descriptorCount = 32;
        VkDescriptorPoolCreateInfo dpi{};
        dpi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        dpi.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
        dpi.maxSets = 8;
        dpi.poolSizeCount = 1;
        dpi.pPoolSizes = &ps;
        if (vkCreateDescriptorPool(device_, &dpi, nullptr, &attn_desc_pool_) != VK_SUCCESS)
            return false;
    }
    VkDescriptorSetAllocateInfo dai{};
    dai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dai.descriptorPool = attn_desc_pool_;
    dai.descriptorSetCount = 1;
    dai.pSetLayouts = &attn_set_layout_;
    VkDescriptorSet ds = nullptr;
    if (vkAllocateDescriptorSets(device_, &dai, &ds) != VK_SUCCESS) return false;

    VkBuffer bufs[4] = { attn_q_dev_, attn_k_dev_, attn_v_dev_, attn_o_dev_ };
    size_t sizes[4] = { q_bytes, kv_bytes, kv_bytes, o_bytes };
    VkDescriptorBufferInfo bis[4]{};
    VkWriteDescriptorSet wrs[4]{};
    for (int i = 0; i < 4; ++i) {
        bis[i].buffer = bufs[i];
        bis[i].range = sizes[i];
        wrs[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        wrs[i].dstSet = ds;
        wrs[i].dstBinding = (uint32_t)i;
        wrs[i].descriptorCount = 1;
        wrs[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        wrs[i].pBufferInfo = &bis[i];
    }
    vkUpdateDescriptorSets(device_, 4, wrs, 0, nullptr);

    if (vkResetFences(device_, 1, &quant_fence_) != VK_SUCCESS ||
        vkResetCommandBuffer(quant_cmd_, 0) != VK_SUCCESS) {
        vkFreeDescriptorSets(device_, attn_desc_pool_, 1, &ds);
        return false;
    }
    VkCommandBufferBeginInfo cbi{};
    cbi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    cbi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(quant_cmd_, &cbi) != VK_SUCCESS) {
        vkFreeDescriptorSets(device_, attn_desc_pool_, 1, &ds);
        return false;
    }

    auto copy_up = [&](VkBuffer host, VkBuffer dev, size_t bytes) {
        VkBufferCopy r{}; r.size = bytes;
        vkCmdCopyBuffer(quant_cmd_, host, dev, 1, &r);
    };
    copy_up(attn_stage_q_, attn_q_dev_, q_bytes);
    copy_up(attn_stage_k_, attn_k_dev_, kv_bytes);
    copy_up(attn_stage_v_, attn_v_dev_, kv_bytes);

    VkMemoryBarrier mb{};
    mb.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    mb.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    mb.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0,
                         1, &mb, 0, nullptr, 0, nullptr);

    AttnPush push{};
    push.headDim = head_dim;
    push.heads = heads;
    push.kvHeads = kv_heads;
    push.seqLen = seq_len;
    push.kvDim = kv_dim;
    push.scale = scale;

    vkCmdBindPipeline(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE, sh->second.pipeline);
    vkCmdBindDescriptorSets(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE,
                            sh->second.layout, 0, 1, &ds, 0, nullptr);
    vkCmdPushConstants(quant_cmd_, sh->second.layout, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(AttnPush), &push);
    // One workgroup per head (scores once in shared; lanes share weights).
    vkCmdDispatch(quant_cmd_, heads, 1, 1);

    mb.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    mb.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
                         1, &mb, 0, nullptr, 0, nullptr);
    VkBufferCopy down{}; down.size = o_bytes;
    vkCmdCopyBuffer(quant_cmd_, attn_o_dev_, attn_stage_o_, 1, &down);

    if (vkEndCommandBuffer(quant_cmd_) != VK_SUCCESS) {
        vkFreeDescriptorSets(device_, attn_desc_pool_, 1, &ds);
        return false;
    }
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &quant_cmd_;
    if (vkQueueSubmit(compute_queue_, 1, &si, quant_fence_) != VK_SUCCESS) {
        vkFreeDescriptorSets(device_, attn_desc_pool_, 1, &ds);
        return false;
    }
    ++gpu_counters_.submits;
    if (quant_fuse_active_) ++quant_fuse_submits_;
    if (std::getenv("DEEP2_SUBMIT_TRACE")) {
        std::fprintf(stderr,
            "SUBMIT_TRACE kind=AttnDecodeGqa seq=%u heads=%u dependency=HOST_READBACK "
            "necessary=1 fuse=%d\n",
            seq_len, heads, quant_fuse_active_ ? 1 : 0);
        std::fflush(stderr);
    }
    if (WaitAttnFence(device_, quant_fence_) != VK_SUCCESS) {
        vkFreeDescriptorSets(device_, attn_desc_pool_, 1, &ds);
        return false;
    }
    ++gpu_counters_.waits;
    ++quant_epoch_;
    NoteSubmissionComplete();
    std::memcpy(out, attn_stage_o_map_, o_bytes);
    gpu_counters_.download_bytes += o_bytes;
    vkFreeDescriptorSets(device_, attn_desc_pool_, 1, &ds);
    return true;
}
