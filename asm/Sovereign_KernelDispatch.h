// ============================================================================
// Sovereign_KernelDispatch.h - Unified Kernel Dispatch Interface
// ============================================================================
// Bridges all Sovereign MASM kernels with C++ runtime
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ----------------------------------------------------------------------------
// Kernel Function Signatures
// ----------------------------------------------------------------------------

// Normalization
typedef int (*pfn_rms_norm_f32)(float* input, float* output, float* weight,
                                 size_t n_elements, float epsilon);
typedef int (*pfn_rms_norm_f32_inplace)(float* buffer, float* weight,
                                         size_t n_elements, float epsilon);
typedef int (*pfn_layer_norm_f32)(float* input, float* output,
                                    float* gamma, float* beta,
                                    size_t n_elements, float epsilon);

// Position Embeddings
typedef int (*pfn_rope_precompute)(size_t head_dim, size_t max_seq_len,
                                    float theta, float* cache);
typedef int (*pfn_rope_apply_f32)(float* tensor, float* freq_cache,
                                    size_t seq_len, size_t head_dim, 
                                    size_t num_heads);
typedef int (*pfn_rope_apply_llama_f32)(float* q, float* k, int* positions,
                                        size_t seq_len, size_t head_dim, 
                                        float theta);

// Residual Connections
typedef int (*pfn_residual_add_f32)(float* input, float* residual, 
                                    float* output, size_t n_elements);
typedef int (*pfn_residual_add_f32_inplace)(float* buffer, float* residual,
                                             size_t n_elements);
typedef int (*pfn_residual_add_f32_scaled)(float* input, float* residual,
                                           float* output, size_t n_elements,
                                           float scale_factor);

// Quantization
typedef size_t (*pfn_q4k_dequant_block)(const void* src, float* dst,
                                         size_t block_size, const void* scales);
typedef int (*pfn_q4k_dequant_tensor)(const void* tensor_data, float* output,
                                      size_t num_elements, const void* tensor_info);

// ----------------------------------------------------------------------------
// Kernel Dispatch Table
// ----------------------------------------------------------------------------

typedef struct {
    // Normalization
    pfn_rms_norm_f32              rms_norm_f32;
    pfn_rms_norm_f32_inplace      rms_norm_f32_inplace;
    pfn_layer_norm_f32            layer_norm_f32;
    
    // Position Embeddings
    pfn_rope_precompute           rope_precompute_cache;
    pfn_rope_apply_f32            rope_apply_f32;
    pfn_rope_apply_llama_f32      rope_apply_llama_f32;
    
    // Residual Connections
    pfn_residual_add_f32          residual_add_f32;
    pfn_residual_add_f32_inplace  residual_add_f32_inplace;
    pfn_residual_add_f32_scaled   residual_add_f32_scaled;
    
    // Quantization
    pfn_q4k_dequant_block         q4k_dequant_block;
    pfn_q4k_dequant_tensor        q4k_dequant_tensor;
    
} Sovereign_KernelTable;

// ----------------------------------------------------------------------------
// C API Functions
// ----------------------------------------------------------------------------

// Initialize kernel table with function pointers
int Sovereign_InitKernelTable(Sovereign_KernelTable* table);

// Validate all kernel pointers are loaded
int Sovereign_ValidateKernelTable(const Sovereign_KernelTable* table);

// Get version info
const char* Sovereign_GetKernelVersion();

#ifdef __cplusplus
}

// ----------------------------------------------------------------------------
// C++ Wrapper
// ----------------------------------------------------------------------------

namespace Sovereign {

class KernelDispatch {
public:
    KernelDispatch();
    ~KernelDispatch();
    
    // Initialize - loads all kernel function pointers
    bool Initialize();
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Get raw table
    const Sovereign_KernelTable& GetTable() const { return table_; }
    
    // Get version string
    const char* GetVersion();
    
    // Convenience wrappers
    bool RMSNorm(float* input, float* output, float* weight, 
                 size_t n, float epsilon = 1e-6f);
    bool RMSNormInPlace(float* buffer, float* weight, 
                         size_t n, float epsilon = 1e-6f);
    
    bool LayerNorm(float* input, float* output, float* gamma, float* beta,
                   size_t n, float epsilon = 1e-6f);
    
    bool RoPEPrecompute(size_t head_dim, size_t max_seq_len, 
                        float theta, float* cache);
    bool RoPEApply(float* tensor, float* freq_cache,
                   size_t seq_len, size_t head_dim, size_t num_heads);
    
    bool ResidualAdd(float* input, float* residual, float* output, size_t n);
    bool ResidualAddInPlace(float* buffer, float* residual, size_t n);
    bool ResidualAddScaled(float* input, float* residual, float* output,
                          size_t n, float scale);
    
    bool Q4KDequantBlock(const void* src, float* dst, 
                         size_t block_size, const void* scales);
    bool Q4KDequantTensor(const void* tensor_data, float* output,
                          size_t num_elements, const void* tensor_info);

private:
    Sovereign_KernelTable table_;
    bool initialized_;
};

} // namespace Sovereign

#endif // __cplusplus
