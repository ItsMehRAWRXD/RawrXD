// ============================================================================
// Vulkan Executor Extended Header
// ============================================================================
// Extends VulkanExecutor with additional kernels (RMSNorm, Softmax, VerifyCandidates)
// ============================================================================

#pragma once

#include "vulkan_executor.hpp"

namespace RawrXD {
namespace Inference {

// Extended Vulkan Executor with additional kernels
class VulkanExecutorExtended : public VulkanExecutor {
public:
    bool InitializeExtended();
    
    // Execute RMS Normalization
    bool ExecuteRMSNorm(const std::vector<float>& input, std::vector<float>& output, 
                        uint32_t size, float eps = 1e-6f);
    
    // Execute Softmax
    bool ExecuteSoftmax(const std::vector<float>& input, std::vector<float>& output,
                        uint32_t rows, uint32_t cols);
    
    // Execute Medusa Candidate Verification
    bool ExecuteVerifyCandidates(const std::vector<float>& logits,
                                 const std::vector<uint32_t>& candidates,
                                 std::vector<bool>& acceptance_mask,
                                 uint32_t num_heads, uint32_t tokens_per_head, uint32_t vocab_size);
    
    // Accessors for external integration
    VkDevice GetDevice() const { return device_; }
    VkPhysicalDevice GetPhysicalDevice() const { return physicalDevice_; }
    VkDescriptorPool GetDescriptorPool() const { return descriptorPool_; }
    VkQueue GetComputeQueue() const { return queue_; }
    
    // Pipeline access for fused kernels
    auto GetPipeline(const std::string& name) -> decltype(pipelines_.find(name)) {
        return pipelines_.find(name);
    }
    auto GetPipelinesEnd() -> decltype(pipelines_.end()) {
        return pipelines_.end();
    }
    
    // Expose protected methods for fused kernels
    using VulkanExecutor::CreateBuffer;
    using VulkanExecutor::DestroyBuffer;
    using VulkanExecutor::UploadBuffer;
    using VulkanExecutor::DownloadBuffer;
    using VulkanExecutor::BeginCommandBuffer;
    using VulkanExecutor::EndCommandBuffer;
};

} // namespace Inference
} // namespace RawrXD
