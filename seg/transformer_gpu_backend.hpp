// ============================================================================
// Transformer GPU Backend Interface
// ============================================================================
// Unified interface for CUDA/HIP/Vulkan GPU acceleration
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>

namespace RawrXD {
namespace GPU {

// GPU backend type
enum class GPUBackend {
    NONE,
    CUDA,      // NVIDIA
    HIP,       // AMD
    VULKAN,    // Cross-platform (RDNA3 7800XT)
    OPENCL     // Fallback
};

// GPU buffer handle
struct GPUBuffer {
    void* handle = nullptr;
    void* memory = nullptr;
    size_t size = 0;
};

// GPU compute kernel
struct GPUKernel {
    void* shaderModule = nullptr;
    void* pipeline = nullptr;
    void* layout = nullptr;
};

// Transformer GPU backend interface
class TransformerGPUBackend {
public:
    virtual ~TransformerGPUBackend() = default;
    
    // Initialize GPU
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    
    // Get backend type
    virtual GPUBackend GetBackendType() const = 0;
    virtual const char* GetBackendName() const = 0;
    
    // Memory management
    virtual GPUBuffer AllocateBuffer(size_t size) = 0;
    virtual void FreeBuffer(GPUBuffer& buffer) = 0;
    virtual void CopyToGPU(GPUBuffer& dst, const void* src, size_t size) = 0;
    virtual void CopyFromGPU(void* dst, const GPUBuffer& src, size_t size) = 0;
    
    // Compute operations
    virtual void MatMul(const GPUBuffer& A, const GPUBuffer& B, GPUBuffer& C,
                        uint32_t M, uint32_t N, uint32_t K) = 0;
    virtual void RMSNorm(const GPUBuffer& input, const GPUBuffer& weight,
                         GPUBuffer& output, uint32_t size, float eps) = 0;
    virtual void Softmax(const GPUBuffer& input, GPUBuffer& output,
                         uint32_t rows, uint32_t cols) = 0;
    virtual void SiLU(const GPUBuffer& input, GPUBuffer& output, uint32_t size) = 0;
    virtual void Attention(const GPUBuffer& Q, const GPUBuffer& K, const GPUBuffer& V,
                            GPUBuffer& output, uint32_t num_heads, uint32_t seq_len,
                            uint32_t head_dim) = 0;
    
    // Synchronization
    virtual void Synchronize() = 0;
    
    // Factory method
    static std::unique_ptr<TransformerGPUBackend> Create(GPUBackend preferred = GPUBackend::VULKAN);
};

// GPU-accelerated transformer layer
class TransformerGPULayer {
public:
    TransformerGPULayer(uint32_t hidden_size, uint32_t num_heads, 
                        uint32_t num_kv_heads, uint32_t intermediate_size);
    ~TransformerGPULayer();
    
    // Initialize with backend
    bool Initialize(GPUBackend preferred = GPUBackend::VULKAN);
    
    // Load weights to GPU
    bool LoadWeights(const float* q_w, const float* k_w, const float* v_w, const float* o_w,
                     const float* ffn_g, const float* ffn_u, const float* ffn_d);
    
    // Forward pass on GPU
    bool Forward(const float* input, float* output, uint32_t seq_len);
    
    // Get performance stats
    float GetLastKernelTime() const { return last_kernel_time_ms_; }
    GPUBackend GetActiveBackend() const;
    
private:
    std::unique_ptr<TransformerGPUBackend> backend_;
    
    // Model dimensions
    uint32_t hidden_size_;
    uint32_t num_heads_;
    uint32_t num_kv_heads_;
    uint32_t intermediate_size_;
    
    // GPU buffers for weights
    GPUBuffer q_weight_;
    GPUBuffer k_weight_;
    GPUBuffer v_weight_;
    GPUBuffer o_weight_;
    GPUBuffer ffn_gate_;
    GPUBuffer ffn_up_;
    GPUBuffer ffn_down_;
    
    // GPU buffers for activations
    GPUBuffer input_buf_;
    GPUBuffer hidden_buf_;
    GPUBuffer q_proj_buf_;
    GPUBuffer k_proj_buf_;
    GPUBuffer v_proj_buf_;
    GPUBuffer attn_out_buf_;
    GPUBuffer ffn_gate_buf_;
    GPUBuffer ffn_up_buf_;
    GPUBuffer ffn_down_buf_;
    GPUBuffer output_buf_;
    
    // Performance tracking
    float last_kernel_time_ms_ = 0.0f;
};

} // namespace GPU
} // namespace RawrXD
