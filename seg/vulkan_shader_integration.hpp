// ============================================================================
// Vulkan Shader Integration - Wire SPIR-V to RX 7800 XT
// ============================================================================
// Connects pre-compiled SPIR-V shaders to VulkanBackend
// Target: 500 tok/s on RX 7800 XT
// ============================================================================

#pragma once

#include <vulkan/vulkan.h>
#include <vector>
#include <string>
#include <memory>

namespace transformer {

// ============================================================================
// SPIR-V Shader Loader
// ============================================================================
class SPIRVLoader {
public:
    static std::vector<uint32_t> LoadFile(const std::string& path);
    static bool Validate(const std::vector<uint32_t>& code);
};

// ============================================================================
// Shader Pipeline Configuration
// ============================================================================
struct ShaderPipelineConfig {
    // Workgroup sizes optimized for RDNA3
    struct WorkgroupSize {
        uint32_t x = 256;  // Wave64 * 4
        uint32_t y = 1;
        uint32_t z = 1;
    };
    
    WorkgroupSize rmsnorm_workgroup{256, 1, 1};
    WorkgroupSize matmul_workgroup{16, 16, 1};  // Tile size
    WorkgroupSize softmax_workgroup{256, 1, 1};
    WorkgroupSize flash_attn_workgroup{64, 1, 1};  // Per head
    
    // RDNA3-specific optimizations
    bool use_wave64 = true;           // RDNA3 prefers wave64
    bool use_scalar_cache = true;     // Scalar cache for uniforms
    bool use_gds = false;             // Global data share for reductions
    uint32_t lds_size = 65536;        // 64KB LDS per workgroup
};

// ============================================================================
// Vulkan Shader Pipeline
// ============================================================================
class VulkanShaderPipeline {
public:
    VulkanShaderPipeline(VkDevice device, VkPipelineLayout layout);
    ~VulkanShaderPipeline();
    
    bool Initialize(const std::vector<uint32_t>& spirv_code,
                   const ShaderPipelineConfig& config,
                   VkShaderStageFlagBits stage);
    
    void Bind(VkCommandBuffer cmd_buffer);
    void Dispatch(VkCommandBuffer cmd_buffer, uint32_t x, uint32_t y, uint32_t z);
    
    VkPipeline GetPipeline() const { return pipeline_; }
    VkPipelineLayout GetLayout() const { return layout_; }
    
private:
    VkDevice device_;
    VkPipelineLayout layout_;
    VkPipeline pipeline_ = VK_NULL_HANDLE;
    VkShaderModule module_ = VK_NULL_HANDLE;
    VkPipelineCache cache_ = VK_NULL_HANDLE;
    
    VkShaderModule CreateShaderModule(const std::vector<uint32_t>& code);
};

// ============================================================================
// RDNA3-Optimized Shader Manager
// ============================================================================
class RDNA3ShaderManager {
public:
    RDNA3ShaderManager();
    ~RDNA3ShaderManager();
    
    bool Initialize(VkDevice device, VkPipelineLayout layout);
    void Cleanup();
    
    // Load all RawrXD shaders
    bool LoadRawrXDShaders(const std::string& shader_dir);
    
    // Get pipelines
    VkPipeline GetRMSNormPipeline() const { return rmsnorm_pipeline_ ? rmsnorm_pipeline_->GetPipeline() : VK_NULL_HANDLE; }
    VkPipeline GetMatMulPipeline() const { return matmul_pipeline_ ? matmul_pipeline_->GetPipeline() : VK_NULL_HANDLE; }
    VkPipeline GetSoftmaxPipeline() const { return softmax_pipeline_ ? softmax_pipeline_->GetPipeline() : VK_NULL_HANDLE; }
    VkPipeline GetFlashAttentionPipeline() const { return flash_attn_pipeline_ ? flash_attn_pipeline_->GetPipeline() : VK_NULL_HANDLE; }
    VkPipeline GetQ4KGEMMPipeline() const { return q4k_gemm_pipeline_ ? q4k_gemm_pipeline_->GetPipeline() : VK_NULL_HANDLE; }
    
    // Check if all shaders loaded
    bool IsComplete() const;
    
    // Get status
    std::string GetStatus() const;
    
private:
    VkDevice device_ = VK_NULL_HANDLE;
    VkPipelineLayout layout_ = VK_NULL_HANDLE;
    
    std::unique_ptr<VulkanShaderPipeline> rmsnorm_pipeline_;
    std::unique_ptr<VulkanShaderPipeline> matmul_pipeline_;
    std::unique_ptr<VulkanShaderPipeline> softmax_pipeline_;
    std::unique_ptr<VulkanShaderPipeline> flash_attn_pipeline_;
    std::unique_ptr<VulkanShaderPipeline> q4k_gemm_pipeline_;
    
    ShaderPipelineConfig config_;
    
    bool LoadPipeline(std::unique_ptr<VulkanShaderPipeline>& pipeline,
                     const std::string& path,
                     VkShaderStageFlagBits stage);
};

// ============================================================================
// GPU Transformer Dispatcher
// ============================================================================
class GPUTransformerDispatcher {
public:
    GPUTransformerDispatcher();
    ~GPUTransformerDispatcher();
    
    bool Initialize(VkDevice device, VkQueue queue, uint32_t queue_family,
                   VkCommandPool pool, VkDescriptorPool descriptor_pool);
    
    // Execute transformer operations on GPU
    void RMSNorm(VkBuffer input, VkBuffer output, VkBuffer weights,
                uint32_t size, float epsilon, VkCommandBuffer cmd);
    
    void MatMul(VkBuffer a, VkBuffer b, VkBuffer c,
               uint32_t m, uint32_t k, uint32_t n,
               VkCommandBuffer cmd);
    
    void FlashAttention(VkBuffer q, VkBuffer k, VkBuffer v, VkBuffer output,
                       uint32_t seq_len, uint32_t num_heads, uint32_t head_dim,
                       VkCommandBuffer cmd);
    
    void Q4KGEMM(VkBuffer a, VkBuffer b, VkBuffer c,
                uint32_t m, uint32_t n, uint32_t k,
                VkCommandBuffer cmd);
    
    // Set shader manager
    void SetShaderManager(RDNA3ShaderManager* manager) { shader_manager_ = manager; }
    
private:
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue queue_ = VK_NULL_HANDLE;
    uint32_t queue_family_ = 0;
    VkCommandPool pool_ = VK_NULL_HANDLE;
    VkDescriptorPool descriptor_pool_ = VK_NULL_HANDLE;
    
    RDNA3ShaderManager* shader_manager_ = nullptr;
    
    // Descriptor set layouts
    VkDescriptorSetLayout rmsnorm_layout_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout matmul_layout_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout flash_attn_layout_ = VK_NULL_HANDLE;
    
    void CreateDescriptorLayouts();
    VkDescriptorSet AllocateDescriptorSet(VkDescriptorSetLayout layout);
};

// ============================================================================
// Performance Metrics
// ============================================================================
struct GPUPerformanceMetrics {
    double rmsnorm_time_ms = 0.0;
    double matmul_time_ms = 0.0;
    double flash_attn_time_ms = 0.0;
    double total_layer_time_ms = 0.0;
    double tokens_per_sec = 0.0;
    double gpu_utilization = 0.0;
    double memory_bandwidth_gbps = 0.0;
    
    void Print() const;
};

} // namespace transformer
