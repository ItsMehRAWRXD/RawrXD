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
    
    // Resurrected Kernels (Phase 7A)
    int flash_attention_v2_f32(float* Q, float* K, float* V, float* output,
                                size_t seq_len, size_t head_dim);
    size_t fast_token_scan(const char* buffer, size_t length,
                           const void* token_table, int* output);
    int svd_compress_f32(float* input, size_t rank, float* output, size_t original_dim);
    size_t token_merge_avx512(int* token_ids, size_t count,
                              const void* merge_rules, size_t* output_count);
    int q4_0_q8_0_matmul(const void* A, const void* B, float* C,
                         size_t m, size_t n, size_t k);
    
    // Phase 7B Intrinsics Optimized Kernels
    int Sovereign_Q4Q8_MatMul_Intrinsics(const void* A, const void* B, float* C,
                                         size_t m, size_t n, size_t k);
    int Sovereign_FlashAttentionV2_Intrinsics(float* Q, float* K, float* V, float* output,
                                               size_t seq_len, size_t head_dim);
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
    
    // Load resurrected kernels (Phase 7A)
    table->flash_attention_v2_f32 = flash_attention_v2_f32;
    table->fast_token_scan = fast_token_scan;
    table->svd_compress_f32 = svd_compress_f32;
    table->token_merge_avx512 = token_merge_avx512;
    table->q4_0_q8_0_matmul = q4_0_q8_0_matmul;
    
    // Load Phase 7B Intrinsics Optimized Kernels
    table->q4q8_matmul_intrinsics = Sovereign_Q4Q8_MatMul_Intrinsics;
    table->flash_attention_v2_intrinsics = Sovereign_FlashAttentionV2_Intrinsics;
    
    return 0;
}

int Sovereign_ValidateKernelTable(const Sovereign_KernelTable* table) {
    if (!table) return -1;
    
    // Check critical kernels
    if (!table->rms_norm_f32) return -2;
    if (!table->rope_apply_f32) return -3;
    if (!table->residual_add_f32) return -4;
    if (!table->q4_0_q8_0_matmul) return -5;  // Critical: Q4/Q8 MatMul
    
    return 0;
}

const char* Sovereign_GetKernelVersion() {
    return "Sovereign Kernel Suite v1.2.0 (AVX2 + Phase 7A Resurrected + Phase 7B Intrinsics)";
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

// ----------------------------------------------------------------------------
// Resurrected Kernels (Phase 7A)
// ----------------------------------------------------------------------------

bool KernelDispatch::FlashAttentionV2(float* Q, float* K, float* V, float* output,
                                       size_t seq_len, size_t head_dim) {
    if (!initialized_ || !table_.flash_attention_v2_f32) return false;
    return table_.flash_attention_v2_f32(Q, K, V, output, seq_len, head_dim) == 0;
}

size_t KernelDispatch::FastTokenScan(const char* buffer, size_t length,
                                       const void* token_table, int* output) {
    if (!initialized_ || !table_.fast_token_scan) return 0;
    return table_.fast_token_scan(buffer, length, token_table, output);
}

bool KernelDispatch::SVDCompress(float* input, size_t rank, float* output,
                                  size_t original_dim) {
    if (!initialized_ || !table_.svd_compress_f32) return false;
    return table_.svd_compress_f32(input, rank, output, original_dim) == 0;
}

size_t KernelDispatch::TokenMergeAVX512(int* token_ids, size_t count,
                                          const void* merge_rules, size_t* output_count) {
    if (!initialized_ || !table_.token_merge_avx512) return 0;
    return table_.token_merge_avx512(token_ids, count, merge_rules, output_count);
}

bool KernelDispatch::Q4Q8MatMul(const void* A, const void* B, float* C,
                                size_t m, size_t n, size_t k) {
    if (!initialized_ || !table_.q4_0_q8_0_matmul) return false;
    return table_.q4_0_q8_0_matmul(A, B, C, m, n, k) == 0;
}

// ----------------------------------------------------------------------------
// Phase 7B Intrinsics Optimized Kernels
// ----------------------------------------------------------------------------

bool KernelDispatch::Q4Q8MatMulIntrinsics(const void* A, const void* B, float* C,
                                             size_t m, size_t n, size_t k) {
    if (!initialized_ || !table_.q4q8_matmul_intrinsics) return false;
    return table_->q4q8_matmul_intrinsics(A, B, C, m, n, k) == 0;
}

bool KernelDispatch::FlashAttentionV2Intrinsics(float* Q, float* K, float* V, float* output,
                                                  size_t seq_len, size_t head_dim) {
    if (!initialized_ || !table_.flash_attention_v2_intrinsics) return false;
    return table_->flash_attention_v2_intrinsics(Q, K, V, output, seq_len, head_dim) == 0;
}

const char* KernelDispatch::GetVersion() {
    return Sovereign_GetKernelVersion();
}

} // namespace Sovereign

#endif // __cplusplus
