// ============================================================================
// Transformer Vulkan Backend using RawrXD's Production Engine
// ============================================================================
// Direct integration with RawrXD's vulkan_compute.h for maximum performance
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>

// Include RawrXD's production Vulkan compute
#include "../rawrxd/src/vulkan_compute.h"

namespace RawrXD {
namespace GPU {

// Transformer layer using RawrXD's VulkanCompute
class TransformerVulkanRawrXD {
public:
    TransformerVulkanRawrXD(uint32_t hidden_size, uint32_t num_heads,
                            uint32_t num_kv_heads, uint32_t intermediate_size);
    ~TransformerVulkanRawrXD();

    // Initialize Vulkan compute
    bool Initialize();
    bool IsInitialized() const { return vulkan_ != nullptr && vulkan_->GetDeviceInfo().supports_compute; }

    // Load weights to GPU
    bool LoadWeights(const float* q_w, const float* k_w, const float* v_w, const float* o_w,
                     const float* ffn_g, const float* ffn_u, const float* ffn_d);

    // Forward pass on GPU
    bool Forward(const float* input, float* output, uint32_t seq_len);

    // Get performance stats
    float GetLastKernelTime() const { return last_kernel_time_ms_; }
    std::string GetDeviceName() const;
    bool IsAMD() const;
    bool IsUsingTensorCores() const;

    // Static factory - tries to create Vulkan backend
    static std::unique_ptr<TransformerVulkanRawrXD> TryCreate(uint32_t hidden_size, uint32_t num_heads,
                                                               uint32_t num_kv_heads, uint32_t intermediate_size);

private:
    std::unique_ptr<VulkanCompute> vulkan_;

    // Model dimensions
    uint32_t hidden_size_;
    uint32_t num_heads_;
    uint32_t num_kv_heads_;
    uint32_t intermediate_size_;
    uint32_t head_dim_;

    // GPU buffers for weights (indices into VulkanCompute buffer pool)
    uint32_t q_weight_idx_ = UINT32_MAX;
    uint32_t k_weight_idx_ = UINT32_MAX;
    uint32_t v_weight_idx_ = UINT32_MAX;
    uint32_t o_weight_idx_ = UINT32_MAX;
    uint32_t ffn_gate_idx_ = UINT32_MAX;
    uint32_t ffn_up_idx_ = UINT32_MAX;
    uint32_t ffn_down_idx_ = UINT32_MAX;

    // GPU buffers for activations
    uint32_t input_idx_ = UINT32_MAX;
    uint32_t hidden_idx_ = UINT32_MAX;
    uint32_t q_proj_idx_ = UINT32_MAX;
    uint32_t k_proj_idx_ = UINT32_MAX;
    uint32_t v_proj_idx_ = UINT32_MAX;
    uint32_t attn_out_idx_ = UINT32_MAX;
    uint32_t ffn_gate_buf_idx_ = UINT32_MAX;
    uint32_t ffn_up_buf_idx_ = UINT32_MAX;
    uint32_t ffn_act_idx_ = UINT32_MAX;
    uint32_t output_idx_ = UINT32_MAX;

    // Shader/pipeline names
    std::string matmul_shader_ = "matmul_f32";
    std::string rmsnorm_shader_ = "rms_norm_f32";
    std::string silu_shader_ = "silu_f32";
    std::string softmax_shader_ = "softmax_f32";
    std::string attention_shader_ = "flash_attention_v2";

    // Performance tracking
    float last_kernel_time_ms_ = 0.0f;

    // Helper methods
    bool AllocateActivationBuffers();
    void FreeAllBuffers();
    bool UploadWeights(const float* weights, uint32_t& buffer_idx, size_t size);
    bool DownloadOutput(float* output);
};

} // namespace GPU
} // namespace RawrXD
