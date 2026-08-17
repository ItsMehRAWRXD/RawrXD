// ============================================================================
// VulkanGemmDispatcher.hpp
// Lightweight Vulkan compute GEMM dispatcher using pre-compiled SPIR-V.
// Reuses an external VkDevice/VkQueue/VkCommandPool (from RawrXDInference).
// No runtime shader compilation — loads gemm_compute.spv at init.
// ============================================================================
#pragma once

#include <vulkan/vulkan.h>
#include <cstdint>
#include <vector>
#include <string>

namespace RawrXD {

class VulkanGemmDispatcher {
public:
    VulkanGemmDispatcher();
    ~VulkanGemmDispatcher();

    // Non-copyable
    VulkanGemmDispatcher(const VulkanGemmDispatcher&) = delete;
    VulkanGemmDispatcher& operator=(const VulkanGemmDispatcher&) = delete;

    // Initialize with existing Vulkan handles (from RawrXDInference)
    bool Initialize(VkDevice device, VkQueue queue, VkCommandPool commandPool,
                    const std::string& spirvPath);

    void Shutdown();

    // Dispatch GEMM: output[M×N] = weight[M×K] @ input[K×N] (column-major for input)
    // For transformer GEMV: input is [K] vector, output is [M] vector
    // weight buffer must be GPU-resident, input/output must be GPU buffers
    bool DispatchGemm(VkBuffer weightBuffer, VkBuffer inputBuffer, VkBuffer outputBuffer,
                        uint32_t M, uint32_t N, uint32_t K);

    bool IsInitialized() const { return m_initialized; }

private:
    bool LoadSpirv(const std::string& path, std::vector<uint32_t>& outCode);
    bool CreatePipeline(const std::vector<uint32_t>& code);

    VkDevice m_device = VK_NULL_HANDLE;
    VkQueue m_queue = VK_NULL_HANDLE;
    VkCommandPool m_cmdPool = VK_NULL_HANDLE;
    VkPipeline m_pipeline = VK_NULL_HANDLE;
    VkPipelineLayout m_pipelineLayout = VK_NULL_HANDLE;
    VkDescriptorSetLayout m_dsLayout = VK_NULL_HANDLE;
    VkDescriptorPool m_descPool = VK_NULL_HANDLE;
    bool m_initialized = false;
};

} // namespace RawrXD
