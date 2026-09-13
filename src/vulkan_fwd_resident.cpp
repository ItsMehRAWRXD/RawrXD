// vulkan_fwd_resident.cpp — device-resident transformer ops (STREAMER_GPU_FORWARD_OPS_001)
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace CPUInference {
namespace {

bool OpenSpv(const char* name, std::vector<uint32_t>& code) {
    const char* cands[] = {
        name,
        "bin/",
        "src/backend/",
        "G:/~dev/rawrxd/src/backend/",
        "G:/~dev/rawrxd/build-ninja/bin/",
    };
    char path[512];
    for (const char* base : cands) {
        if (std::strchr(base, '/') || std::strchr(base, '\\')) {
            std::snprintf(path, sizeof(path), "%s%s", base, name);
        } else if (base[0] && base[std::strlen(base)-1] == '/') {
            std::snprintf(path, sizeof(path), "%s%s", base, name);
        } else if (!base[0] || std::strcmp(base, name) == 0) {
            std::snprintf(path, sizeof(path), "%s", name);
        } else {
            std::snprintf(path, sizeof(path), "%s%s", base, name);
        }
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open() && std::strcmp(base, name) != 0) {
            std::snprintf(path, sizeof(path), "%s%s", base, name);
            f.open(path, std::ios::binary | std::ios::ate);
        }
        if (!f.is_open()) continue;
        size_t sz = (size_t)f.tellg();
        f.seekg(0);
        code.resize(sz / 4);
        f.read(reinterpret_cast<char*>(code.data()), (std::streamsize)sz);
        return !code.empty();
    }
    // explicit full paths
    const char* abs[] = {
        "G:\\~dev\\rawrxd\\src\\backend\\rmsnorm.spv",
        "G:\\~dev\\rawrxd\\src\\backend\\residual_add.spv",
        "G:\\~dev\\rawrxd\\src\\backend\\rope.spv",
        "G:\\~dev\\rawrxd\\src\\backend\\attn_decode.spv",
        "G:\\~dev\\rawrxd\\src\\backend\\swiglu.spv",
    };
    (void)abs;
    std::string p = std::string("G:\\~dev\\rawrxd\\src\\backend\\") + name;
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    size_t sz = (size_t)f.tellg();
    f.seekg(0);
    code.resize(sz / 4);
    f.read(reinterpret_cast<char*>(code.data()), (std::streamsize)sz);
    return !code.empty();
}

void DestroyBuf(VkDevice dev, VulkanCompute::DeviceBuf& b) {
    if (!dev) return;
    if (b.buffer) vkDestroyBuffer(dev, b.buffer, nullptr);
    if (b.memory) vkFreeMemory(dev, b.memory, nullptr);
    b = {};
}

} // namespace

bool VulkanCompute::LoadComputePipeline(
    const char* spvName, uint32_t nBind, uint32_t pcBytes,
    VkPipeline& pipe, VkPipelineLayout& layout,
    VkDescriptorSetLayout& dsLayout, VkDescriptorPool& pool, VkDescriptorSet& ds)
{
    if (pipe) return true;
    std::vector<uint32_t> spirv;
    if (!OpenSpv(spvName, spirv)) return false;
    VkShaderModuleCreateInfo smi{};
    smi.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    smi.codeSize = spirv.size() * 4;
    smi.pCode = spirv.data();
    VkShaderModule mod = nullptr;
    if (vkCreateShaderModule(device_, &smi, nullptr, &mod) != VK_SUCCESS) return false;

    std::vector<VkDescriptorSetLayoutBinding> binds(nBind);
    for (uint32_t i = 0; i < nBind; ++i) {
        binds[i] = {};
        binds[i].binding = i;
        binds[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        binds[i].descriptorCount = 1;
        binds[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dli{};
    dli.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dli.bindingCount = nBind;
    dli.pBindings = binds.data();
    if (vkCreateDescriptorSetLayout(device_, &dli, nullptr, &dsLayout) != VK_SUCCESS) {
        vkDestroyShaderModule(device_, mod, nullptr);
        return false;
    }
    VkPushConstantRange pcr{};
    pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pcr.offset = 0;
    pcr.size = pcBytes;
    VkPipelineLayoutCreateInfo pli{};
    pli.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pli.setLayoutCount = 1;
    pli.pSetLayouts = &dsLayout;
    pli.pushConstantRangeCount = pcBytes ? 1u : 0u;
    pli.pPushConstantRanges = pcBytes ? &pcr : nullptr;
    if (vkCreatePipelineLayout(device_, &pli, nullptr, &layout) != VK_SUCCESS) {
        vkDestroyShaderModule(device_, mod, nullptr);
        return false;
    }
    VkComputePipelineCreateInfo cpi{};
    cpi.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cpi.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cpi.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cpi.stage.module = mod;
    cpi.stage.pName = "main";
    cpi.layout = layout;
    if (vkCreateComputePipelines(device_, nullptr, 1, &cpi, nullptr, &pipe) != VK_SUCCESS) {
        vkDestroyShaderModule(device_, mod, nullptr);
        return false;
    }
    vkDestroyShaderModule(device_, mod, nullptr);

    /* 16 sets: fused MoE stick may record ≤16 SwiGLU/saxpy in one CB. */
    VkDescriptorPoolSize ps{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, nBind * 16};
    VkDescriptorPoolCreateInfo dpi{};
    dpi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpi.maxSets = 16;
    dpi.poolSizeCount = 1;
    dpi.pPoolSizes = &ps;
    if (vkCreateDescriptorPool(device_, &dpi, nullptr, &pool) != VK_SUCCESS) return false;
    VkDescriptorSetAllocateInfo dai{};
    dai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dai.descriptorPool = pool;
    dai.descriptorSetCount = 1;
    dai.pSetLayouts = &dsLayout;
    return vkAllocateDescriptorSets(device_, &dai, &ds) == VK_SUCCESS;
}

bool VulkanCompute::SubmitOne(VkCommandBuffer cmd) {
    last_d2h_vk_ = 0;
    last_d2h_phase_ = "submit";
    VkFence fence = nullptr;
    VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    if (vkCreateFence(device_, &fi, nullptr, &fence) != VK_SUCCESS) {
        last_d2h_phase_ = "fence_create";
        return false;
    }
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    const VkResult sr = vkQueueSubmit(compute_queue_, 1, &si, fence);
    last_d2h_vk_ = (int)sr;
    if (sr != VK_SUCCESS) {
        last_d2h_phase_ = (sr == VK_ERROR_DEVICE_LOST) ? "device_lost" : "submit";
        vkDestroyFence(device_, fence, nullptr);
        vkFreeCommandBuffers(device_, command_pool_, 1, &cmd);
        return false;
    }
    const VkResult wr =
        vkWaitForFences(device_, 1, &fence, VK_TRUE, 30ull * 1000000000ull);
    last_d2h_vk_ = (int)wr;
    vkDestroyFence(device_, fence, nullptr);
    vkFreeCommandBuffers(device_, command_pool_, 1, &cmd);
    if (wr != VK_SUCCESS) {
        last_d2h_phase_ =
            (wr == VK_ERROR_DEVICE_LOST) ? "device_lost" : "fence";
        return false;
    }
    last_d2h_phase_ = "ok";
    ++op_submits_;
    return true;
}

bool VulkanCompute::DownloadDeviceLocal(VkBuffer src, void* dst, size_t size) {
    /* Persistent gemv_out staging — avoid HOST_VISIBLE alloc after MoE pin fill. */
    last_d2h_phase_ = "staging";
    last_d2h_vk_ = 0;
    if (!src || !dst || !size) return false;
    if (!EnsureHostIo(size, size) || !gemv_out_buf_) {
        last_d2h_phase_ = "staging";
        return false;
    }
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    if (vkAllocateCommandBuffers(device_, &cai, &cmd) != VK_SUCCESS || !cmd) {
        last_d2h_phase_ = "cmd_alloc";
        return false;
    }
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    VkBufferCopy copy{};
    copy.size = size;
    vkCmdCopyBuffer(cmd, src, gemv_out_buf_, 1, &copy);
    vkEndCommandBuffer(cmd);
    if (!SubmitOne(cmd)) return false;
    void* mapped = nullptr;
    if (vkMapMemory(device_, gemv_out_mem_, 0, size, 0, &mapped) != VK_SUCCESS ||
        !mapped) {
        last_d2h_phase_ = "map";
        return false;
    }
    std::memcpy(dst, mapped, size);
    vkUnmapMemory(device_, gemv_out_mem_);
    last_d2h_phase_ = "ok";
    return true;
}

bool VulkanCompute::CopyDeviceToDevice(VkBuffer src, VkBuffer dst, size_t size) {
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    VkBufferCopy copy{};
    copy.size = size;
    vkCmdCopyBuffer(cmd, src, dst, 1, &copy);
    vkEndCommandBuffer(cmd);
    return SubmitOne(cmd);
}

void VulkanCompute::ReleaseForwardArena() {
    if (!device_) return;
    DestroyBuf(device_, fwd_hidden_);
    DestroyBuf(device_, fwd_residual_);
    DestroyBuf(device_, fwd_normed_);
    DestroyBuf(device_, fwd_q_);
    DestroyBuf(device_, fwd_k_);
    DestroyBuf(device_, fwd_v_);
    DestroyBuf(device_, fwd_attn_);
    DestroyBuf(device_, fwd_gate_);
    DestroyBuf(device_, fwd_up_);
    DestroyBuf(device_, fwd_down_);
    DestroyBuf(device_, fwd_ffn_act_);
    DestroyBuf(device_, fwd_attn_w_);
    DestroyBuf(device_, fwd_ffn_w_);
    DestroyBuf(device_, fwd_k_cache_);
    DestroyBuf(device_, fwd_v_cache_);
    fwd_arena_ready_ = false;
}

bool VulkanCompute::EnsureForwardArena(uint32_t hidden, uint32_t inter, uint32_t nHeads,
                                       uint32_t nKv, uint32_t headDim, uint32_t maxSeq,
                                       uint32_t nLayers) {
    if (!device_ || !EnsureGemvPipeline()) return false;
    const uint32_t kvDim = nKv * headDim;
    if (nLayers == 0) nLayers = 1;
    if (fwd_arena_ready_ && fwd_hidden_n_ == hidden && fwd_inter_n_ == inter &&
        fwd_kv_dim_ == kvDim && fwd_max_seq_ == maxSeq && fwd_n_layers_ == nLayers)
        return true;
    ReleaseForwardArena();
    auto mk = [&](DeviceBuf& b, size_t bytes) -> bool {
        return CreateDeviceLocalBuffer(bytes, b.buffer, b.memory) && ((b.bytes = bytes), true);
    };
    const size_t hb = (size_t)hidden * 4;
    const size_t ib = (size_t)inter * 4;
    const size_t qb = (size_t)nHeads * headDim * 4;
    const size_t kb = (size_t)kvDim * 4;
    const size_t cb = (size_t)nLayers * maxSeq * kvDim * 4;
    if (!mk(fwd_hidden_, hb) || !mk(fwd_residual_, hb) || !mk(fwd_normed_, hb) ||
        !mk(fwd_q_, qb) || !mk(fwd_k_, kb) || !mk(fwd_v_, kb) || !mk(fwd_attn_, qb) ||
        !mk(fwd_gate_, ib) || !mk(fwd_up_, ib) || !mk(fwd_down_, hb) || !mk(fwd_ffn_act_, ib) ||
        !mk(fwd_attn_w_, hb) || !mk(fwd_ffn_w_, hb) ||
        !mk(fwd_k_cache_, cb) || !mk(fwd_v_cache_, cb))
        return false;
    if (!LoadComputePipeline("rmsnorm.spv", 3, 8, rms_pipe_, rms_layout_, rms_dsl_, rms_pool_, rms_ds_))
        return false;
    if (!LoadComputePipeline("residual_add.spv", 3, 4, add_pipe_, add_layout_, add_dsl_, add_pool_, add_ds_))
        return false;
    if (!LoadComputePipeline("rope.spv", 2, 20, rope_pipe_, rope_layout_, rope_dsl_, rope_pool_, rope_ds_))
        return false;
    if (!LoadComputePipeline("attn_decode.spv", 4, 20, attn_pipe_, attn_layout_, attn_dsl_, attn_pool_, attn_ds_))
        return false;
    if (!LoadComputePipeline("swiglu.spv", 3, 4, swiglu_pipe_, swiglu_layout_, swiglu_dsl_, swiglu_pool_, swiglu_ds_))
        return false;
    /* scaled_add.spv: PC = {uint n; float scale} = 8 bytes, 2 storage bufs. */
    if (!LoadComputePipeline("scaled_add.spv", 2, 8, saxpy_pipe_, saxpy_layout_,
                             saxpy_dsl_, saxpy_pool_, saxpy_ds_))
        return false;
    if (!EnsureFusedAuxDs())
        return false;
    {
        VkDescriptorSetAllocateInfo dai{};
        dai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        dai.descriptorPool = rms_pool_;
        dai.descriptorSetCount = 1;
        dai.pSetLayouts = &rms_dsl_;
        if (vkAllocateDescriptorSets(device_, &dai, &rms_ds2_) != VK_SUCCESS) return false;
        dai.descriptorPool = add_pool_;
        dai.pSetLayouts = &add_dsl_;
        if (vkAllocateDescriptorSets(device_, &dai, &add_ds2_) != VK_SUCCESS) return false;
    }
    fwd_hidden_n_ = hidden;
    fwd_inter_n_ = inter;
    fwd_kv_dim_ = kvDim;
    fwd_max_seq_ = maxSeq;
    fwd_n_layers_ = nLayers;
    fwd_arena_ready_ = true;
    return true;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaHidden() { return fwd_hidden_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaResidual() { return fwd_residual_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaNormed() { return fwd_normed_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaQ() { return fwd_q_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaK() { return fwd_k_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaV() { return fwd_v_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaAttn() { return fwd_attn_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaGate() { return fwd_gate_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaUp() { return fwd_up_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaDown() { return fwd_down_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaFFNAct() { return fwd_ffn_act_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaAttnW() { return fwd_attn_w_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaFfnW() { return fwd_ffn_w_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaKCache() { return fwd_k_cache_; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaVCache() { return fwd_v_cache_; }

bool VulkanCompute::UploadHidden(const float* host, uint32_t n) {
    if (!fwd_arena_ready_ || !host) return false;
    return UploadToDeviceLocal(host, (size_t)n * 4, fwd_hidden_.buffer);
}
bool VulkanCompute::DownloadHidden(float* host, uint32_t n) {
    if (!fwd_arena_ready_ || !host) return false;
    return DownloadDeviceLocal(fwd_hidden_.buffer, host, (size_t)n * 4);
}
bool VulkanCompute::UploadNormWeight(DeviceBuf& dst, const float* w, uint32_t n) {
    if (!w || !dst.buffer) return false;
    return UploadToDeviceLocal(w, (size_t)n * 4, dst.buffer);
}
bool VulkanCompute::CopyArenaHiddenTo(VulkanCompute& dst, uint32_t n) {
    std::vector<float> tmp(n);
    if (!DownloadHidden(tmp.data(), n)) return false;
    return dst.UploadHidden(tmp.data(), n);
}

bool VulkanCompute::DispatchGemvDevice(const float* weights, uint64_t cacheKey,
                                       DeviceBuf& in, DeviceBuf& out,
                                       uint32_t rows, uint32_t cols) {
    if (!EnsureGemvPipeline() || !weights || !in.buffer || !out.buffer) return false;
    ++gemv_attempts_;
    const size_t weightBytes = (size_t)rows * cols * sizeof(float);
    VkBuffer weightBuf = nullptr;
    if (WantWeightStream()) {
        if (!ww_active_ || weightBytes > ww_slot_bytes_) {
            size_t budget = ww_budget_bytes_ ? ww_budget_bytes_ : (size_t)512 << 20;
            const char* b = std::getenv("DEEP2_WEIGHT_BUDGET_MIB");
            if (b && *b) budget = (size_t)std::atoi(b) << 20;
            uint32_t nSlots = 8;
            const char* ns = std::getenv("DEEP2_WEIGHT_SLOTS");
            if (ns && *ns) nSlots = (uint32_t)std::atoi(ns);
            if (!EnsureWeightWindow(weightBytes, nSlots, budget)) return false;
        }
        if (!StreamWeightToSlot(weights, weightBytes, weightBuf)) return false;
    } else {
        if (cacheKey == 0)
            cacheKey = (uint64_t)(uintptr_t)weights ^ ((uint64_t)rows << 32) ^ (uint64_t)cols;
        auto it = gemv_weight_cache_.find(cacheKey);
        if (it != gemv_weight_cache_.end() && it->second.rows == rows && it->second.cols == cols) {
            weightBuf = it->second.buffer;
            ++gemv_weight_hits_;
        } else {
            GemvResidentWeight rw{};
            ++ww_hotpath_create_buf_;
            if (!CreateDeviceLocalBuffer(weightBytes, rw.buffer, rw.memory)) return false;
            if (!UploadToDeviceLocal(weights, weightBytes, rw.buffer)) {
                ++ww_hotpath_destroy_buf_;
                vkDestroyBuffer(device_, rw.buffer, nullptr);
                vkFreeMemory(device_, rw.memory, nullptr);
                return false;
            }
            rw.bytes = weightBytes; rw.rows = rows; rw.cols = cols;
            if (it != gemv_weight_cache_.end()) {
                ++ww_hotpath_destroy_buf_;
                if (it->second.buffer) vkDestroyBuffer(device_, it->second.buffer, nullptr);
                if (it->second.memory) vkFreeMemory(device_, it->second.memory, nullptr);
                gemv_resident_bytes_ -= it->second.bytes;
            }
            gemv_weight_cache_[cacheKey] = rw;
            gemv_resident_bytes_ += weightBytes;
            ++gemv_weight_uploads_;
            weightBuf = rw.buffer;
        }
    }
    VkDescriptorSet ds = fused_cmd_ ? NextGemvDs() : gemv_ds_;
    VkDescriptorBufferInfo dbiW{weightBuf, 0, weightBytes};
    VkDescriptorBufferInfo dbiI{in.buffer, 0, (VkDeviceSize)cols * 4};
    VkDescriptorBufferInfo dbiO{out.buffer, 0, (VkDeviceSize)rows * 4};
    VkWriteDescriptorSet writes[3]{};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiW;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiI;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiO;
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);
    uint32_t pc[2] = {rows, cols};
    if (!RecordCompute(gemv_pipeline_, gemv_pipeline_layout_, ds, pc, sizeof(pc),
                       (rows + 255u) / 256u))
        return false;
    ++gemv_success_;
    return true;
}

static void Bind3(VkDevice dev, VkDescriptorSet ds, VulkanCompute::DeviceBuf& a,
                  VulkanCompute::DeviceBuf& b, VulkanCompute::DeviceBuf& c) {
    VkDescriptorBufferInfo i0{a.buffer, 0, a.bytes};
    VkDescriptorBufferInfo i1{b.buffer, 0, b.bytes};
    VkDescriptorBufferInfo i2{c.buffer, 0, c.bytes};
    VkWriteDescriptorSet w[3]{};
    for (int i = 0; i < 3; ++i) {
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w[i].dstSet = ds;
        w[i].dstBinding = (uint32_t)i;
        w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    w[0].pBufferInfo = &i0; w[1].pBufferInfo = &i1; w[2].pBufferInfo = &i2;
    vkUpdateDescriptorSets(dev, 3, w, 0, nullptr);
}

bool VulkanCompute::DispatchRmsNorm(DeviceBuf& in, DeviceBuf& w, DeviceBuf& out,
                                    uint32_t n, float eps) {
    if (!rms_pipe_ || !rms_ds_) return false;
    VkDescriptorSet ds = (fused_cmd_ && ((rms_use_++) & 1u) && rms_ds2_) ? rms_ds2_ : rms_ds_;
    Bind3(device_, ds, in, w, out);
    struct { uint32_t n; float eps; } pc{n, eps};
    return RecordCompute(rms_pipe_, rms_layout_, ds, &pc, sizeof(pc), 1);
}

bool VulkanCompute::DispatchResidualAdd(DeviceBuf& a, DeviceBuf& b, DeviceBuf& out, uint32_t n) {
    if (!add_pipe_ || !add_ds_) return false;
    VkDescriptorSet ds = (fused_cmd_ && ((add_use_++) & 1u) && add_ds2_) ? add_ds2_ : add_ds_;
    Bind3(device_, ds, a, b, out);
    uint32_t pc = n;
    return RecordCompute(add_pipe_, add_layout_, ds, &pc, 4, (n + 255u) / 256u);
}

bool VulkanCompute::DispatchScaledAdd(DeviceBuf& accum, DeviceBuf& src, float scale,
                                      uint32_t n) {
    if (!saxpy_pipe_ || !saxpy_ds_ || !accum.buffer || !src.buffer || !n)
        return false;
    VkDescriptorSet ds = fused_cmd_ ? NextSaxpyDs() : saxpy_ds_;
    VkDescriptorBufferInfo i0{accum.buffer, 0, accum.bytes};
    VkDescriptorBufferInfo i1{src.buffer, 0, src.bytes};
    VkWriteDescriptorSet w[2]{};
    for (int i = 0; i < 2; ++i) {
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w[i].dstSet = ds;
        w[i].dstBinding = (uint32_t)i;
        w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    w[0].pBufferInfo = &i0;
    w[1].pBufferInfo = &i1;
    vkUpdateDescriptorSets(device_, 2, w, 0, nullptr);
    struct {
        uint32_t n;
        float scale;
    } pc{n, scale};
    return RecordCompute(saxpy_pipe_, saxpy_layout_, ds, &pc, sizeof(pc),
                         (n + 255u) / 256u);
}

bool VulkanCompute::DispatchRope(DeviceBuf& q, DeviceBuf& k, uint32_t headDim, uint32_t nHeads,
                                 uint32_t nKv, uint32_t pos, float theta) {
    if (!rope_pipe_) return false;
    VkDescriptorBufferInfo i0{q.buffer, 0, q.bytes};
    VkDescriptorBufferInfo i1{k.buffer, 0, k.bytes};
    VkWriteDescriptorSet w[2]{};
    for (int i = 0; i < 2; ++i) {
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w[i].dstSet = rope_ds_;
        w[i].dstBinding = (uint32_t)i;
        w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    w[0].pBufferInfo = &i0; w[1].pBufferInfo = &i1;
    vkUpdateDescriptorSets(device_, 2, w, 0, nullptr);
    struct { uint32_t hd, nh, nk, pos; float th; } pc{headDim, nHeads, nKv, pos, theta};
    return RecordCompute(rope_pipe_, rope_layout_, rope_ds_, &pc, sizeof(pc),
                         (nHeads + 63u) / 64u);
}

bool VulkanCompute::DispatchAttnDecode(DeviceBuf& q, DeviceBuf& kCache, DeviceBuf& vCache,
                                       DeviceBuf& out, uint32_t headDim, uint32_t nHeads,
                                       uint32_t nKv, uint32_t seq, float scale,
                                       uint32_t layer) {
    if (!attn_pipe_ || seq == 0 || layer >= fwd_n_layers_) return false;
    const VkDeviceSize layerBytes = (VkDeviceSize)fwd_max_seq_ * fwd_kv_dim_ * 4;
    const VkDeviceSize layerOff = (VkDeviceSize)layer * layerBytes;
    VkDescriptorBufferInfo infos[4] = {
        {q.buffer, 0, q.bytes},
        {kCache.buffer, layerOff, layerBytes},
        {vCache.buffer, layerOff, layerBytes},
        {out.buffer, 0, out.bytes}};
    VkWriteDescriptorSet w[4]{};
    for (int i = 0; i < 4; ++i) {
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w[i].dstSet = attn_ds_;
        w[i].dstBinding = (uint32_t)i;
        w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        w[i].pBufferInfo = &infos[i];
    }
    vkUpdateDescriptorSets(device_, 4, w, 0, nullptr);
    struct { uint32_t hd, nh, nk, seq; float scale; } pc{headDim, nHeads, nKv, seq, scale};
    return RecordCompute(attn_pipe_, attn_layout_, attn_ds_, &pc, sizeof(pc),
                         (nHeads + 63u) / 64u);
}

bool VulkanCompute::DispatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out, uint32_t n) {
    if (!swiglu_pipe_) return false;
    VkDescriptorSet ds = fused_cmd_ ? NextSwigluDs() : swiglu_ds_;
    Bind3(device_, ds, gate, up, out);
    uint32_t pc = n;
    return RecordCompute(swiglu_pipe_, swiglu_layout_, ds, &pc, 4, (n + 255u) / 256u);
}

bool VulkanCompute::AppendKV(DeviceBuf& kTok, DeviceBuf& vTok, uint32_t kvDim, uint32_t pos,
                             uint32_t layer) {
    if (!fwd_arena_ready_ || pos >= fwd_max_seq_ || layer >= fwd_n_layers_ ||
        !kTok.buffer || !vTok.buffer)
        return false;
    const VkDeviceSize bytes = (VkDeviceSize)kvDim * 4;
    const VkDeviceSize off = (VkDeviceSize)((size_t)layer * fwd_max_seq_ + pos) * bytes;
    return RecordCopy(kTok.buffer, fwd_k_cache_.buffer, 0, off, bytes) &&
           RecordCopy(vTok.buffer, fwd_v_cache_.buffer, 0, off, bytes);
}

} // namespace CPUInference
#endif // RAWR_VULKAN_AVAILABLE
