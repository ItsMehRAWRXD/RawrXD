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
uint64_t Fnv64Spv(const uint32_t* w, size_t nWords) {
    uint64_t h = 14695981039346656037ull;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(w);
    const size_t n = nWords * 4u;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}
bool LoadQ4kSpv(std::vector<uint32_t>& code) {
    /* C740 loads disk SPV (no embed). Order: env override, then absolute
     * src/backend, then cwd/bin copies. Bytes alone ≠ SHA — print FNV64 of
     * loaded image so a candidate cannot silently look like pin 4548BCF1. */
    const char* envPath = std::getenv("RAWRXD_Q4K_SPV");
    const char* paths[8];
    int nPath = 0;
    if (envPath && envPath[0]) paths[nPath++] = envPath;
    paths[nPath++] = "G:/~dev/rawrxd/src/backend/gemv_q4k.spv";
    paths[nPath++] = "G:\\~dev\\rawrxd\\src\\backend\\gemv_q4k.spv";
    paths[nPath++] = "G:/~dev/rawrxd/build_ninja/bin/gemv_q4k.spv";
    paths[nPath++] = "G:/~dev/rawrxd/build-ninja/bin/gemv_q4k.spv";
    paths[nPath++] = "gemv_q4k.spv";
    paths[nPath++] = "bin/gemv_q4k.spv";
    for (int i = 0; i < nPath; ++i) {
        const char* p = paths[i];
        std::ifstream f(p, std::ios::binary | std::ios::ate);
        if (!f.is_open()) continue;
        size_t n = (size_t)f.tellg();
        f.seekg(0);
        if (n < 4 || (n % 4) != 0) continue;
        code.resize(n / 4);
        f.read(reinterpret_cast<char*>(code.data()), (std::streamsize)n);
        if (!code.empty()) {
            const uint64_t fnv = Fnv64Spv(code.data(), code.size());
            printf("[VulkanCompute] Q4K_SPV=%s bytes=%zu fnv64=%016llX\n", p, n,
                   (unsigned long long)fnv);
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
    const uint32_t avx = gemv_avx_wq_next_ ? 1u : 0u;
    gemv_avx_wq_next_ = false;
    uint32_t pc[4] = {rows, cols, avx, 0u};
    return RecordCompute(pipe, gemv_pipeline_layout_, ds, pc, sizeof(pc), groups);
}

bool VulkanCompute::BindGemvStoragePc(VkBuffer wbuf, size_t wbytes, VkBuffer inb,
                                       size_t inBytes, VkBuffer outb, size_t outBytes,
                                       VkPipeline pipe, const uint32_t* pc, uint32_t pcN,
                                       uint32_t groups) {
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
    const uint32_t bytes = pcN * (uint32_t)sizeof(uint32_t);
    return RecordCompute(pipe, gemv_pipeline_layout_, ds, pc, bytes, groups);
}

bool VulkanCompute::DispatchGemvPacked(const void* packed, size_t bytes,
                                       DeviceBuf& in, DeviceBuf& out,
                                       uint32_t rows, uint32_t cols,
                                       uint64_t pinKey) {
    if (!EnsureQ4kPipeline() || !packed || !in.buffer || !out.buffer || bytes == 0)
        return false;
    ++gemv_attempts_;
    VkBuffer wbuf = nullptr;
    // pinKey!=0 → MLA resident pins; pinKey==0 keeps stream-slot path (GpuForward).
    if (pinKey && WantWeightPin()) {
        if (!EnsurePinnedPackedWeight(packed, bytes, rows, cols, wbuf, pinKey))
            return false;
    } else {
        if (!ww_active_ || bytes > ww_slot_bytes_) {
            size_t budget = ww_budget_bytes_ ? ww_budget_bytes_
                                            : ((size_t)512 << 20);
            uint32_t nSlots = ww_slot_count_ ? ww_slot_count_ : 8;
            size_t slotB = bytes > ww_slot_bytes_ ? bytes
                           : (ww_slot_bytes_ ? ww_slot_bytes_ : bytes);
            if (!EnsureWeightWindow(slotB, nSlots, budget)) return false;
        }
        if (!StreamWeightToSlot(packed, bytes, wbuf)) return false;
    }
    if (!BindGemvStorage(wbuf, bytes, in.buffer, (size_t)cols * 4, out.buffer,
                         (size_t)rows * 4, q4k_pipe_, rows, cols,
                         (rows + 63u) / 64u))
        return false;
    ++q4k_packed_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
