// vulkan_fwd_quant_pipe.cpp — shared SPIR-V GEMV pipeline loader
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <fstream>
#include <cstring>
#include <cstdio>
#include <vector>

namespace CPUInference {

bool VulkanCompute::CreateGemvPipe(const char* spvName, VkPipeline& pipe) {
    if (pipe) return true;
    if (!EnsureGemvPipeline() || !spvName) return false;
    std::vector<uint32_t> spirv;
    const char* bases[] = {
        "", "bin/", "src/backend/",
        "G:/~dev/rawrxd/src/backend/",
        "G:/~dev/rawrxd/build-ninja/bin/",
    };
    char path[512];
    for (const char* b : bases) {
        std::snprintf(path, sizeof(path), "%s%s", b, spvName);
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) continue;
        size_t n = (size_t)f.tellg(); f.seekg(0);
        spirv.resize(n / 4);
        f.read(reinterpret_cast<char*>(spirv.data()), (std::streamsize)n);
        if (!spirv.empty()) break;
    }
    if (spirv.empty()) return false;
    VkShaderModuleCreateInfo si{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    si.codeSize = spirv.size() * 4; si.pCode = spirv.data();
    VkShaderModule mod = nullptr;
    if (vkCreateShaderModule(device_, &si, nullptr, &mod) != VK_SUCCESS) return false;
    VkPipelineShaderStageCreateInfo st{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO};
    st.stage = VK_SHADER_STAGE_COMPUTE_BIT; st.module = mod; st.pName = "main";
    VkComputePipelineCreateInfo pi{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    pi.layout = gemv_pipeline_layout_; pi.stage = st;
    VkResult r = vkCreateComputePipelines(device_, nullptr, 1, &pi, nullptr, &pipe);
    vkDestroyShaderModule(device_, mod, nullptr);
    return r == VK_SUCCESS && pipe;
}

bool VulkanCompute::EnsureQ5kPipeline() { return CreateGemvPipe("gemv_q5k.spv", q5k_pipe_); }
bool VulkanCompute::EnsureQ3kPipeline() { return CreateGemvPipe("gemv_q3k.spv", q3k_pipe_); }
bool VulkanCompute::EnsureQ2kPipeline() { return CreateGemvPipe("gemv_q2k.spv", q2k_pipe_); }
bool VulkanCompute::EnsureQ8Pipeline() { return CreateGemvPipe("gemv_q8.spv", q8_pipe_); }

bool VulkanCompute::SelectPackedPipe(int ggmlType, VkPipeline& pipe, uint64_t*& ops) {
    pipe = nullptr; ops = nullptr;
    if (ggmlType == 12) { if (!EnsureQ4kPipeline()) return false; pipe = q4k_pipe_; ops = &q4k_packed_ops_; }
    else if (ggmlType == 14) { if (!EnsureQ6kPipeline()) return false; pipe = q6k_pipe_; ops = &q6k_packed_ops_; }
    else if (ggmlType == 13) { if (!EnsureQ5kPipeline()) return false; pipe = q5k_pipe_; ops = &q5k_packed_ops_; }
    else if (ggmlType == 11) { if (!EnsureQ3kPipeline()) return false; pipe = q3k_pipe_; ops = &q3k_packed_ops_; }
    else if (ggmlType == 10) { if (!EnsureQ2kPipeline()) return false; pipe = q2k_pipe_; ops = &q2k_packed_ops_; }
    else if (ggmlType == 8) { if (!EnsureQ8Pipeline()) return false; pipe = q8_pipe_; ops = &q8_packed_ops_; }
    return pipe != nullptr;
}

} // namespace CPUInference
#endif
