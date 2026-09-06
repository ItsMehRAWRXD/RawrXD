// vulkan_fwd_resident.cpp — device-resident transformer ops (STREAMER_GPU_FORWARD_OPS_001)
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>

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

    VkDescriptorPoolSize ps{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, nBind};
    VkDescriptorPoolCreateInfo dpi{};
    dpi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpi.maxSets = 1;
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
    VkFence fence = nullptr;
    VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    vkCreateFence(device_, &fi, nullptr, &fence);
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    bool ok = vkQueueSubmit(compute_queue_, 1, &si, fence) == VK_SUCCESS;
    if (ok) vkWaitForFences(device_, 1, &fence, VK_TRUE, 30ull * 1000000000ull);
    vkDestroyFence(device_, fence, nullptr);
    vkFreeCommandBuffers(device_, command_pool_, 1, &cmd);
    return ok;
}

bool VulkanCompute::DownloadDeviceLocal(VkBuffer src, void* dst, size_t size) {
    VkBuffer staging = nullptr;
    VkDeviceMemory stagingMem = nullptr;
    if (!CreateHostVisibleBuffer(size, staging, stagingMem)) return false;
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
    vkCmdCopyBuffer(cmd, src, staging, 1, &copy);
    vkEndCommandBuffer(cmd);
    if (!SubmitOne(cmd)) {
        vkDestroyBuffer(device_, staging, nullptr);
        vkFreeMemory(device_, stagingMem, nullptr);
        return false;
    }
    void* mapped = nullptr;
    vkMapMemory(device_, stagingMem, 0, size, 0, &mapped);
    std::memcpy(dst, mapped, size);
    vkUnmapMemory(device_, stagingMem);
    vkDestroyBuffer(device_, staging, nullptr);
    vkFreeMemory(device_, stagingMem, nullptr);
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
    if (cacheKey == 0)
        cacheKey = (uint64_t)(uintptr_t)weights ^ ((uint64_t)rows << 32) ^ (uint64_t)cols;
    GemvResidentWeight* resident = nullptr;
    auto it = gemv_weight_cache_.find(cacheKey);
    if (it != gemv_weight_cache_.end() && it->second.rows == rows && it->second.cols == cols) {
        resident = &it->second;
        ++gemv_weight_hits_;
    } else {
        GemvResidentWeight rw{};
        if (!CreateDeviceLocalBuffer(weightBytes, rw.buffer, rw.memory)) return false;
        if (!UploadToDeviceLocal(weights, weightBytes, rw.buffer)) {
            vkDestroyBuffer(device_, rw.buffer, nullptr);
            vkFreeMemory(device_, rw.memory, nullptr);
            return false;
        }
        rw.bytes = weightBytes; rw.rows = rows; rw.cols = cols;
        if (it != gemv_weight_cache_.end()) {
            if (it->second.buffer) vkDestroyBuffer(device_, it->second.buffer, nullptr);
            if (it->second.memory) vkFreeMemory(device_, it->second.memory, nullptr);
            gemv_resident_bytes_ -= it->second.bytes;
        }
        gemv_weight_cache_[cacheKey] = rw;
        gemv_resident_bytes_ += weightBytes;
        ++gemv_weight_uploads_;
        resident = &gemv_weight_cache_[cacheKey];
    }
    VkDescriptorBufferInfo dbiW{resident->buffer, 0, weightBytes};
    VkDescriptorBufferInfo dbiI{in.buffer, 0, (VkDeviceSize)cols * 4};
    VkDescriptorBufferInfo dbiO{out.buffer, 0, (VkDeviceSize)rows * 4};
    VkWriteDescriptorSet writes[3]{};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = gemv_ds_;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiW;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiI;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiO;
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);

    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo begin{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &begin);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, gemv_pipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, gemv_pipeline_layout_,
                            0, 1, &gemv_ds_, 0, nullptr);
    uint32_t pc[2] = {rows, cols};
    vkCmdPushConstants(cmd, gemv_pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), pc);
    vkCmdDispatch(cmd, (rows + 255u) / 256u, 1, 1);
    vkEndCommandBuffer(cmd);
    if (!SubmitOne(cmd)) return false;
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
    if (!rms_pipe_) return false;
    Bind3(device_, rms_ds_, in, w, out);
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, rms_pipe_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, rms_layout_, 0, 1, &rms_ds_, 0, nullptr);
    struct { uint32_t n; float eps; } pc{n, eps};
    vkCmdPushConstants(cmd, rms_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);
    vkCmdDispatch(cmd, 1, 1, 1);
    vkEndCommandBuffer(cmd);
    return SubmitOne(cmd);
}

bool VulkanCompute::DispatchResidualAdd(DeviceBuf& a, DeviceBuf& b, DeviceBuf& out, uint32_t n) {
    if (!add_pipe_) return false;
    Bind3(device_, add_ds_, a, b, out);
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, add_pipe_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, add_layout_, 0, 1, &add_ds_, 0, nullptr);
    uint32_t pc = n;
    vkCmdPushConstants(cmd, add_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, 4, &pc);
    vkCmdDispatch(cmd, (n + 255u) / 256u, 1, 1);
    vkEndCommandBuffer(cmd);
    return SubmitOne(cmd);
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
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, rope_pipe_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, rope_layout_, 0, 1, &rope_ds_, 0, nullptr);
    struct { uint32_t hd, nh, nk, pos; float th; } pc{headDim, nHeads, nKv, pos, theta};
    vkCmdPushConstants(cmd, rope_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);
    vkCmdDispatch(cmd, nHeads, 1, 1);
    vkEndCommandBuffer(cmd);
    return SubmitOne(cmd);
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
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, attn_pipe_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, attn_layout_, 0, 1, &attn_ds_, 0, nullptr);
    struct { uint32_t hd, nh, nk, seq; float scale; } pc{headDim, nHeads, nKv, seq, scale};
    vkCmdPushConstants(cmd, attn_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);
    vkCmdDispatch(cmd, nHeads, 1, 1);
    vkEndCommandBuffer(cmd);
    return SubmitOne(cmd);
}

bool VulkanCompute::DispatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out, uint32_t n) {
    if (!swiglu_pipe_) return false;
    Bind3(device_, swiglu_ds_, gate, up, out);
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = command_pool_;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = nullptr;
    vkAllocateCommandBuffers(device_, &cai, &cmd);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &bi);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, swiglu_pipe_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, swiglu_layout_, 0, 1, &swiglu_ds_, 0, nullptr);
    uint32_t pc = n;
    vkCmdPushConstants(cmd, swiglu_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, 4, &pc);
    vkCmdDispatch(cmd, (n + 255u) / 256u, 1, 1);
    vkEndCommandBuffer(cmd);
    return SubmitOne(cmd);
}

bool VulkanCompute::AppendKV(DeviceBuf& kTok, DeviceBuf& vTok, uint32_t kvDim, uint32_t pos,
                             uint32_t layer) {
    if (!fwd_arena_ready_ || pos >= fwd_max_seq_ || layer >= fwd_n_layers_ ||
        !kTok.buffer || !vTok.buffer)
        return false;
    const size_t bytes = (size_t)kvDim * 4;
    const size_t off = ((size_t)layer * fwd_max_seq_ + pos) * bytes;
    auto copyAt = [&](VkBuffer src, VkBuffer dst) -> bool {
        VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        cai.commandPool = command_pool_;
        cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cai.commandBufferCount = 1;
        VkCommandBuffer cmd = nullptr;
        vkAllocateCommandBuffers(device_, &cai, &cmd);
        VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(cmd, &bi);
        VkBufferCopy c{};
        c.srcOffset = 0;
        c.dstOffset = off;
        c.size = bytes;
        vkCmdCopyBuffer(cmd, src, dst, 1, &c);
        vkEndCommandBuffer(cmd);
        return SubmitOne(cmd);
    };
    return copyAt(kTok.buffer, fwd_k_cache_.buffer) &&
           copyAt(vTok.buffer, fwd_v_cache_.buffer);
}

} // namespace CPUInference
#endif // RAWR_VULKAN_AVAILABLE
