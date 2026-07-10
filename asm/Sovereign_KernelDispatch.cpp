// ============================================================================
// Sovereign_KernelDispatch.cpp - Kernel Dispatch Implementation
// ============================================================================

#include "Sovereign_KernelDispatch.h"
#include <cstring>
#include <stdexcept>

// ----------------------------------------------------------------------------
// C API Implementation
// ----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

// External declarations from MASM kernels
extern "C" {
    // RMSNorm
    int rms_norm_f32(float* input, float* output, float* weight,
                     size_t n_elements, float epsilon);
    int rms_norm_f32_inplace(float* buffer, float* weight,
                             size_t n_elements, float epsilon);
    int layer_norm_f32(float* input, float* output, float* gamma, float* beta,
                       size_t n_elements, float epsilon);
    
    // RoPE
    int rope_precompute_cache(size_t head_dim, size_t max_seq_len,
                              float theta, float* cache);
    int rope_apply_f32(float* tensor, float* freq_cache,
                       size_t seq_len, size_t head_dim, size_t num_heads);
    int rope_apply_llama_f32(float* q, float* k, int* positions,
                             size_t seq_len, size_t head_dim, float theta);
    
    // Residual Add
    int residual_add_f32(float* input, float* residual, float* output,
                         size_t n_elements);
    int residual_add_f32_inplace(float* buffer, float* residual,
                                  size_t n_elements);
    int residual_add_f32_scaled(float* input, float* residual, float* output,
                                 size_t n_elements, float scale_factor);
    
    // Q4K Dequant (using available symbols from Sovereign_Q4K_Dequant.asm)
    int Sovereign_Q4K_Dequant_Block_AVX2(const void* src, float* dst,
                                           size_t block_size, const void* scales);
    int Sovereign_Q4K_Dequant_Tensor_AVX2(const void* tensor_data, float* output,
                                          size_t num_elements, const void* tensor_info);
}

int Sovereign_InitKernelTable(Sovereign_KernelTable* table) {
    if (!table) return -1;
    
    // Clear table
    memset(table, 0, sizeof(Sovereign_KernelTable));
    
    // Load normalization kernels
    table->rms_norm_f32 = rms_norm_f32;
    table->rms_norm_f32_inplace = rms_norm_f32_inplace;
    table->layer_norm_f32 = layer_norm_f32;
    
    // Load RoPE kernels
    table->rope_precompute_cache = rope_precompute_cache;
    table->rope_apply_f32 = rope_apply_f32;
    table->rope_apply_llama_f32 = rope_apply_llama_f32;
    
    // Load residual kernels
    table->residual_add_f32 = residual_add_f32;
    table->residual_add_f32_inplace = residual_add_f32_inplace;
    table->residual_add_f32_scaled = residual_add_f32_scaled;
    
    // Load quantization kernels
    table->q4k_dequant_block = (pfn_q4k_dequant_block)Sovereign_Q4K_Dequant_Block_AVX2;
    table->q4k_dequant_tensor = (pfn_q4k_dequant_tensor)Sovereign_Q4K_Dequant_Tensor_AVX2;
    
    return 0;
}

int Sovereign_ValidateKernelTable(const Sovereign_KernelTable* table) {
    if (!table) return -1;
    
    // Check critical kernels
    if (!table->rms_norm_f32) return -2;
    if (!table->rope_apply_f32) return -3;
    if (!table->residual_add_f32) return -4;
    
    return 0;
}

const char* Sovereign_GetKernelVersion() {
    return "Sovereign Kernel Suite v1.0.0 (AVX2)";
}

#ifdef __cplusplus
}

// ----------------------------------------------------------------------------
// C++ Wrapper Implementation
// ----------------------------------------------------------------------------

namespace Sovereign {

KernelDispatch::KernelDispatch() : initialized_(false) {
    memset(&table_, 0, sizeof(table_));
}

KernelDispatch::~KernelDispatch() {
    // Cleanup if needed
}

bool KernelDispatch::Initialize() {
    if (initialized_) return true;
    
    int result = Sovereign_InitKernelTable(&table_);
    if (result != 0) return false;
    
    result = Sovereign_ValidateKernelTable(&table_);
    if (result != 0) return false;
    
    initialized_ = true;
    return true;
}

bool KernelDispatch::RMSNorm(float* input, float* output, float* weight,
                              size_t n, float epsilon) {
    if (!initialized_ || !table_.rms_norm_f32) return false;
    return table_.rms_norm_f32(input, output, weight, n, epsilon) == 0;
}

bool KernelDispatch::RMSNormInPlace(float* buffer, float* weight,
                                     size_t n, float epsilon) {
    if (!initialized_ || !table_.rms_norm_f32_inplace) return false;
    return table_.rms_norm_f32_inplace(buffer, weight, n, epsilon) == 0;
}

bool KernelDispatch::LayerNorm(float* input, float* output, float* gamma, 
                                float* beta, size_t n, float epsilon) {
    if (!initialized_ || !table_.layer_norm_f32) return false;
    return table_.layer_norm_f32(input, output, gamma, beta, n, epsilon) == 0;
}

bool KernelDispatch::RoPEPrecompute(size_t head_dim, size_t max_seq_len,
                                     float theta, float* cache) {
    if (!initialized_ || !table_.rope_precompute_cache) return false;
    return table_.rope_precompute_cache(head_dim, max_seq_len, theta, cache) == 0;
}

bool KernelDispatch::RoPEApply(float* tensor, float* freq_cache,
                                size_t seq_len, size_t head_dim, size_t num_heads) {
    if (!initialized_ || !table_.rope_apply_f32) return false;
    return table_.rope_apply_f32(tensor, freq_cache, seq_len, head_dim, num_heads) == 0;
}

bool KernelDispatch::ResidualAdd(float* input, float* residual, 
                                  float* output, size_t n) {
    if (!initialized_ || !table_.residual_add_f32) return false;
    return table_.residual_add_f32(input, residual, output, n) == 0;
}

bool KernelDispatch::ResidualAddInPlace(float* buffer, float* residual, size_t n) {
    if (!initialized_ || !table_.residual_add_f32_inplace) return false;
    return table_.residual_add_f32_inplace(buffer, residual, n) == 0;
}

bool KernelDispatch::ResidualAddScaled(float* input, float* residual, float* output,
                                        size_t n, float scale) {
    if (!initialized_ || !table_.residual_add_f32_scaled) return false;
    return table_.residual_add_f32_scaled(input, residual, output, n, scale) == 0;
}

bool KernelDispatch::Q4KDequantBlock(const void* src, float* dst,
                                      size_t block_size, const void* scales) {
    if (!initialized_ || !table_.q4k_dequant_block) return false;
    size_t result = table_.q4k_dequant_block(src, dst, block_size, scales);
    return result > 0;
}

bool KernelDispatch::Q4KDequantTensor(const void* tensor_data, float* output,
                                      size_t num_elements, const void* tensor_info) {
    if (!initialized_ || !table_.q4k_dequant_tensor) return false;
    return table_.q4k_dequant_tensor(tensor_data, output, num_elements, tensor_info) == 0;
}

const char* KernelDispatch::GetVersion() {
    return Sovereign_GetKernelVersion();
}

} // namespace Sovereign

#endif // __cplusplus
