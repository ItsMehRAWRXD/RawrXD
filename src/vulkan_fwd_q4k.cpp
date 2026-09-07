// vulkan_fwd_q4k.cpp — packed Q4_K GEMV consumer of the weight-slot ring
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <vector>

namespace CPUInference {
namespace {
bool LoadQ4kSpv(std::vector<uint32_t>& code) {
    const char* paths[] = {
        "G:/~dev/rawrxd/src/backend/gemv_q4k.spv",
        "G:\\~dev\\rawrxd\\src\\backend\\gemv_q4k.spv",
        "G:/~dev/rawrxd/build-ninja/bin/gemv_q4k.spv",
        "gemv_q4k.spv", "bin/gemv_q4k.spv",
    };
    for (const char* p : paths) {
        std::ifstream f(p, std::ios::binary | std::ios::ate);
        if (!f.is_open()) continue;
        size_t n = (size_t)f.tellg(); f.seekg(0);
        code.resize(n / 4);
        f.read(reinterpret_cast<char*>(code.data()), (std::streamsize)n);
        if (!code.empty()) {
            printf("[VulkanCompute] Q4K_SPV=%s bytes=%zu\n", p, n);
            return true;
        }
    }
    return false;
}
} // namespace

bool VulkanCompute::EnsureQ4kPipeline() {
    if (q4k_pipe_) return true;
    if (!EnsureGemvPipeline()) return false;
    std::vector<uint32_t> spirv;
    if (!LoadQ4kSpv(spirv)) return false;
    VkShaderModuleCreateInfo si{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    si.codeSize = spirv.size() * 4; si.pCode = spirv.data();
    VkShaderModule mod = nullptr;
    if (vkCreateShaderModule(device_, &si, nullptr, &mod) != VK_SUCCESS) return false;
    VkPipelineShaderStageCreateInfo st{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO};
    st.stage = VK_SHADER_STAGE_COMPUTE_BIT; st.module = mod; st.pName = "main";
    VkComputePipelineCreateInfo pi{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    pi.layout = gemv_pipeline_layout_; pi.stage = st;
    VkResult r = vkCreateComputePipelines(device_, nullptr, 1, &pi, nullptr, &q4k_pipe_);
    vkDestroyShaderModule(device_, mod, nullptr);
    return r == VK_SUCCESS && q4k_pipe_;
}

bool VulkanCompute::BindGemvStorage(VkBuffer wbuf, size_t wbytes, VkBuffer inb, size_t inBytes,
                                    VkBuffer outb, size_t outBytes, VkPipeline pipe,
                                    uint32_t rows, uint32_t cols, uint32_t groups) {
    // SSBO uint loads need 4-byte range (Q6_K blocks are 210B; pad last d read).
    const VkDeviceSize wRange = (VkDeviceSize)((wbytes + 3u) & ~size_t(3));
    VkDescriptorSet ds = fused_cmd_ ? NextGemvDs() : gemv_ds_;
    VkDescriptorBufferInfo dbiW{wbuf, 0, wRange};
    VkDescriptorBufferInfo dbiI{inb, 0, inBytes};
    VkDescriptorBufferInfo dbiO{outb, 0, outBytes};
    VkWriteDescriptorSet w[3]{};
    for (int i = 0; i < 3; ++i) {
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w[i].dstSet = ds;
        w[i].dstBinding = (uint32_t)i;
        w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    w[0].pBufferInfo = &dbiW; w[1].pBufferInfo = &dbiI; w[2].pBufferInfo = &dbiO;
    vkUpdateDescriptorSets(device_, 3, w, 0, nullptr);
    uint32_t pc[2] = {rows, cols};
    return RecordCompute(pipe, gemv_pipeline_layout_, ds, pc, sizeof(pc), groups);
}

bool VulkanCompute::DispatchGemvPacked(const void* packed, size_t bytes,
                                       DeviceBuf& in, DeviceBuf& out,
                                       uint32_t rows, uint32_t cols) {
    if (!EnsureQ4kPipeline() || !packed || !in.buffer || !out.buffer || bytes == 0)
        return false;
    ++gemv_attempts_;
    VkBuffer wbuf = nullptr;
    if (!ww_active_ || bytes > ww_slot_bytes_) {
        size_t budget = ww_budget_bytes_ ? ww_budget_bytes_ : ((size_t)512 << 20);
        uint32_t nSlots = ww_slot_count_ ? ww_slot_count_ : 8;
        size_t slotB = bytes > ww_slot_bytes_ ? bytes
                       : (ww_slot_bytes_ ? ww_slot_bytes_ : bytes);
        if (!EnsureWeightWindow(slotB, nSlots, budget)) return false;
    }
    if (!StreamWeightToSlot(packed, bytes, wbuf)) return false;
    if (!BindGemvStorage(wbuf, bytes, in.buffer, (size_t)cols * 4, out.buffer,
                         (size_t)rows * 4, q4k_pipe_, rows, cols, (rows + 63u) / 64u))
        return false;
    ++q4k_packed_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
