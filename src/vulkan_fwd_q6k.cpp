// vulkan_fwd_q6k.cpp — packed Q6_K GEMV into bounded weight slots
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <fstream>
#include <vector>

namespace CPUInference {
namespace {
bool LoadQ6kSpv(std::vector<uint32_t>& code) {
    const char* paths[] = {
        "gemv_q6k.spv", "bin/gemv_q6k.spv",
        "G:/~dev/rawrxd/src/backend/gemv_q6k.spv",
        "G:\\~dev\\rawrxd\\src\\backend\\gemv_q6k.spv",
        "G:/~dev/rawrxd/build-ninja/bin/gemv_q6k.spv",
    };
    for (const char* p : paths) {
        std::ifstream f(p, std::ios::binary | std::ios::ate);
        if (!f.is_open()) continue;
        size_t n = (size_t)f.tellg(); f.seekg(0);
        code.resize(n / 4);
        f.read(reinterpret_cast<char*>(code.data()), (std::streamsize)n);
        if (!code.empty()) return true;
    }
    return false;
}
} // namespace

bool VulkanCompute::EnsureQ6kPipeline() {
    if (q6k_pipe_) return true;
    if (!EnsureGemvPipeline()) return false;
    std::vector<uint32_t> spirv;
    if (!LoadQ6kSpv(spirv)) return false;
    VkShaderModuleCreateInfo si{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    si.codeSize = spirv.size() * 4; si.pCode = spirv.data();
    VkShaderModule mod = nullptr;
    if (vkCreateShaderModule(device_, &si, nullptr, &mod) != VK_SUCCESS) return false;
    VkPipelineShaderStageCreateInfo st{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO};
    st.stage = VK_SHADER_STAGE_COMPUTE_BIT; st.module = mod; st.pName = "main";
    VkComputePipelineCreateInfo pi{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    pi.layout = gemv_pipeline_layout_; pi.stage = st;
    VkResult r = vkCreateComputePipelines(device_, nullptr, 1, &pi, nullptr, &q6k_pipe_);
    vkDestroyShaderModule(device_, mod, nullptr);
    return r == VK_SUCCESS && q6k_pipe_;
}

bool VulkanCompute::DispatchGemvQ6kPacked(const void* packed, size_t bytes,
                                          DeviceBuf& in, DeviceBuf& out,
                                          uint32_t rows, uint32_t cols) {
    if (!EnsureQ6kPipeline() || !packed || !in.buffer || !out.buffer || bytes == 0)
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
                         (size_t)rows * 4, q6k_pipe_, rows, cols, (rows + 63u) / 64u))
        return false;
    ++q6k_packed_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
