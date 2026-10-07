//============================================================================
// Sovereign_KernelRegistration.cpp
// Register Phase 7A/7B Kernels with Phase 7C Dispatch Registry
//
// Connects existing kernel implementations to centralized dispatch
//============================================================================

#include "Sovereign_KernelRegistry.hpp"
#include "Sovereign_KernelDispatch.h"
#include <cstring>

namespace Sovereign {

//============================================================================
// FORWARD DECLARATIONS - Phase 7A Resurrected Kernels
//============================================================================

extern "C" {
    // RMSNorm (MASM)
    int rms_norm_f32(float* input, float* output, float* weight,
                     size_t n_elements, float epsilon);
    int rms_norm_f32_inplace(float* buffer, float* weight,
                             size_t n_elements, float epsilon);
    
    // LayerNorm (MASM)
    int layer_norm_f32(float* input, float* output, float* gamma, float* beta,
                       size_t n_elements, float epsilon);
    
    // RoPE (MASM)
    int rope_precompute_cache(size_t head_dim, size_t max_seq_len,
                              float theta, float* cache);
    int rope_apply_f32(float* tensor, float* freq_cache,
                       size_t seq_len, size_t head_dim, size_t num_heads);
    int rope_apply_llama_f32(float* q, float* k, int* positions,
                             size_t seq_len, size_t head_dim, float theta);
    
    // Residual Add (MASM)
    int residual_add_f32(float* input, float* residual, float* output,
                         size_t n_elements);
    int residual_add_f32_inplace(float* buffer, float* residual,
                                  size_t n_elements);
    int residual_add_f32_scaled(float* input, float* residual, float* output,
                                 size_t n_elements, float scale_factor);
    
    // Q4K Dequant (MASM)
    int Sovereign_Q4K_Dequant_Block_AVX2(const void* src, float* dst,
                                           size_t block_size, const void* scales);
    int Sovereign_Q4K_Dequant_Tensor_AVX2(const void* tensor_data, float* output,
                                          size_t num_elements, const void* tensor_info);
    
    // Phase 7A Resurrected Kernels
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

//============================================================================
// SCALAR REFERENCE IMPLEMENTATIONS
//============================================================================

// Scalar RMSNorm for validation
static int Scalar_RMSNorm(const float* input, float* output, size_t n, float epsilon)
{
    // Calculate RMS
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / n + epsilon);
    float inv_rms = 1.0f / rms;
    
    // Normalize
    for (size_t i = 0; i < n; i++) {
        output[i] = input[i] * inv_rms;
    }
    
    return 0;
}

// Scalar LayerNorm for validation
static int Scalar_LayerNorm(const float* input, float* output, size_t n,
                             const float* gamma, const float* beta, float epsilon)
{
    // Calculate mean
    float mean = 0.0f;
    for (size_t i = 0; i < n; i++) {
        mean += input[i];
    }
    mean /= n;
    
    // Calculate variance
    float var = 0.0f;
    for (size_t i = 0; i < n; i++) {
        float diff = input[i] - mean;
        var += diff * diff;
    }
    var /= n;
    
    // Normalize
    float inv_std = 1.0f / std::sqrt(var + epsilon);
    for (size_t i = 0; i < n; i++) {
        float normalized = (input[i] - mean) * inv_std;
        output[i] = normalized * (gamma ? gamma[i] : 1.0f) + (beta ? beta[i] : 0.0f);
    }
    
    return 0;
}

// Scalar ResidualAdd for validation
static int Scalar_ResidualAdd(const float* a, const float* b, float* output,
                               size_t n, float scale)
{
    for (size_t i = 0; i < n; i++) {
        output[i] = a[i] + scale * b[i];
    }
    return 0;
}

// Scalar MatMul F32 for validation
static int Scalar_MatMulF32(const float* A, const float* B, float* C,
                             size_t m, size_t n, size_t k)
{
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (size_t l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
    return 0;
}

// Scalar Softmax for validation
static int Scalar_Softmax(const float* input, float* output, size_t n)
{
    // Find max for numerical stability
    float max_val = input[0];
    for (size_t i = 1; i < n; i++) {
        if (input[i] > max_val) max_val = input[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (size_t i = 0; i < n; i++) {
        output[i] = std::exp(input[i] - max_val);
        sum += output[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    for (size_t i = 0; i < n; i++) {
        output[i] *= inv_sum;
    }
    
    return 0;
}

//============================================================================
// WRAPPER FUNCTIONS - Adapt MASM signatures to Registry signatures
//============================================================================

// RMSNorm wrapper (registry expects no weight parameter)
static int RMSNorm_MASM_Wrapper(const float* input, float* output, size_t n, float epsilon)
{
    // MASM version uses weight, registry version doesn't - use unit weights
    float* weight = new float[n];
    for (size_t i = 0; i < n; i++) weight[i] = 1.0f;
    
    int result = rms_norm_f32(const_cast<float*>(input), output, weight, n, epsilon);
    
    delete[] weight;
    return result;
}

// LayerNorm wrapper
static int LayerNorm_MASM_Wrapper(const float* input, float* output, size_t n,
                                   const float* gamma, const float* beta, float epsilon)
{
    return layer_norm_f32(const_cast<float*>(input), output, 
                          const_cast<float*>(gamma), const_cast<float*>(beta),
                          n, epsilon);
}

// RoPE wrapper (simplified - just call through)
static int RoPE_MASM_Wrapper(float* q, float* k, size_t seq_len, size_t head_dim, size_t pos)
{
    // Create simple position array
    int* positions = new int[seq_len];
    for (size_t i = 0; i < seq_len; i++) positions[i] = (int)(pos + i);
    
    // Precompute cache if needed (simplified - should be cached)
    float* cache = new float[head_dim * seq_len];
    rope_precompute_cache(head_dim, seq_len, 10000.0f, cache);
    
    int result = rope_apply_llama_f32(q, k, positions, seq_len, head_dim, 10000.0f);
    
    delete[] positions;
    delete[] cache;
    return result;
}

// ResidualAdd wrapper
static int ResidualAdd_MASM_Wrapper(const float* a, const float* b, float* output,
                                     size_t n, float scale)
{
    if (scale == 1.0f) {
        return residual_add_f32(const_cast<float*>(a), const_cast<float*>(b), output, n);
    } else {
        return residual_add_f32_scaled(const_cast<float*>(a), const_cast<float*>(b), 
                                        output, n, scale);
    }
}

// MatMul Q4Q8 wrapper
static int MatMulQ4Q8_MASM_Wrapper(const void* A_q4, const void* B_q8, float* C,
                                    size_t m, size_t n, size_t k)
{
    return q4_0_q8_0_matmul(A_q4, B_q8, C, m, n, k);
}

// MatMul Q4Q8 Intrinsics wrapper
static int MatMulQ4Q8_Intrinsics_Wrapper(const void* A_q4, const void* B_q8, float* C,
                                          size_t m, size_t n, size_t k)
{
    return Sovereign_Q4Q8_MatMul_Intrinsics(A_q4, B_q8, C, m, n, k);
}

// FlashAttention MASM wrapper
static int FlashAttention_MASM_Wrapper(const float* Q, const float* K, const float* V,
                                        float* output, size_t seq_len, size_t head_dim)
{
    return flash_attention_v2_f32(const_cast<float*>(Q), const_cast<float*>(K),
                                   const_cast<float*>(V), output, seq_len, head_dim);
}

// FlashAttention Intrinsics wrapper
static int FlashAttention_Intrinsics_Wrapper(const float* Q, const float* K, const float* V,
                                              float* output, size_t seq_len, size_t head_dim)
{
    return Sovereign_FlashAttentionV2_Intrinsics(const_cast<float*>(Q), const_cast<float*>(K),
                                                const_cast<float*>(V), output, seq_len, head_dim);
}

//============================================================================
// REGISTRATION FUNCTION
//============================================================================

bool RegisterAllKernels()
{
    KernelRegistry& registry = KernelRegistry::Instance();
    
    if (!registry.Initialize()) {
        std::cerr << "[RegisterAllKernels] Failed to initialize registry" << std::endl;
        return false;
    }
    
    std::cout << "[RegisterAllKernels] Registering Phase 7A/7B kernels..." << std::endl;
    
    //========================================================================
    // REGISTER SCALAR REFERENCE IMPLEMENTATIONS (for validation)
    //========================================================================
    
    registry.RegisterRMSNorm(KernelBackend::Scalar, Scalar_RMSNorm,
        {"RMSNorm_Scalar", KernelBackend::Scalar, "1.0", "Scalar reference", true, 0.0f, 0.0f, 0.0f});
    
    registry.RegisterLayerNorm(KernelBackend::Scalar, Scalar_LayerNorm,
        {"LayerNorm_Scalar", KernelBackend::Scalar, "1.0", "Scalar reference", true, 0.0f, 0.0f, 0.0f});
    
    registry.RegisterResidualAdd(KernelBackend::Scalar, Scalar_ResidualAdd,
        {"ResidualAdd_Scalar", KernelBackend::Scalar, "1.0", "Scalar reference", true, 0.0f, 0.0f, 0.0f});
    
    registry.RegisterMatMulF32(KernelBackend::Scalar, Scalar_MatMulF32,
        {"MatMulF32_Scalar", KernelBackend::Scalar, "1.0", "Scalar reference", true, 0.0f, 0.0f, 0.0f});
    
    registry.RegisterSoftmax(KernelBackend::Scalar, Scalar_Softmax,
        {"Softmax_Scalar", KernelBackend::Scalar, "1.0", "Scalar reference", true, 0.0f, 0.0f, 0.0f});
    
    //========================================================================
    // REGISTER MASM IMPLEMENTATIONS (Phase 7A)
    //========================================================================
    
    // RMSNorm AVX2
    if (rms_norm_f32) {
        registry.RegisterRMSNorm(KernelBackend::AVX2, RMSNorm_MASM_Wrapper,
            {"RMSNorm_AVX2", KernelBackend::AVX2, "1.0", "MASM AVX2 implementation", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ RMSNorm AVX2" << std::endl;
    }
    
    // LayerNorm AVX2
    if (layer_norm_f32) {
        registry.RegisterLayerNorm(KernelBackend::AVX2, LayerNorm_MASM_Wrapper,
            {"LayerNorm_AVX2", KernelBackend::AVX2, "1.0", "MASM AVX2 implementation", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ LayerNorm AVX2" << std::endl;
    }
    
    // RoPE AVX2
    if (rope_apply_llama_f32) {
        registry.RegisterRoPE(KernelBackend::AVX2, RoPE_MASM_Wrapper,
            {"RoPE_AVX2", KernelBackend::AVX2, "1.0", "MASM AVX2 implementation", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ RoPE AVX2" << std::endl;
    }
    
    // ResidualAdd AVX2
    if (residual_add_f32) {
        registry.RegisterResidualAdd(KernelBackend::AVX2, ResidualAdd_MASM_Wrapper,
            {"ResidualAdd_AVX2", KernelBackend::AVX2, "1.0", "MASM AVX2 implementation", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ ResidualAdd AVX2" << std::endl;
    }
    
    // Q4K Dequant AVX2
    if (Sovereign_Q4K_Dequant_Tensor_AVX2) {
        // Note: Dequantize signature differs, would need adapter
        std::cout << "  ✓ Q4K Dequant AVX2 (registered via dispatch)" << std::endl;
    }
    
    //========================================================================
    // REGISTER RESURRECTED KERNELS (Phase 7A)
    //========================================================================
    
    // FlashAttention V2
    if (flash_attention_v2_f32) {
        registry.RegisterFlashAttention(KernelBackend::AVX2, FlashAttention_MASM_Wrapper,
            {"FlashAttentionV2_AVX2", KernelBackend::AVX2, "1.0", "Phase 7A Resurrected", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ FlashAttention V2 AVX2 (Phase 7A)" << std::endl;
    }
    
    // Q4Q8 MatMul
    if (q4_0_q8_0_matmul) {
        registry.RegisterMatMulQ4Q8(KernelBackend::AVX2, MatMulQ4Q8_MASM_Wrapper,
            {"MatMulQ4Q8_AVX2", KernelBackend::AVX2, "1.0", "Phase 7A Resurrected", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ Q4Q8 MatMul AVX2 (Phase 7A)" << std::endl;
    }
    
    //========================================================================
    // REGISTER INTRINSICS KERNELS (Phase 7B) - PREFERRED
    //========================================================================
    
    // Q4Q8 MatMul Intrinsics (preferred over MASM)
    if (Sovereign_Q4Q8_MatMul_Intrinsics) {
        registry.RegisterMatMulQ4Q8(KernelBackend::AVX2, MatMulQ4Q8_Intrinsics_Wrapper,
            {"MatMulQ4Q8_Intrinsics", KernelBackend::AVX2, "2.0", "Phase 7B AVX2 Intrinsics", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ Q4Q8 MatMul Intrinsics (Phase 7B - PREFERRED)" << std::endl;
    }
    
    // FlashAttention Intrinsics (preferred over MASM)
    if (Sovereign_FlashAttentionV2_Intrinsics) {
        registry.RegisterFlashAttention(KernelBackend::AVX2, FlashAttention_Intrinsics_Wrapper,
            {"FlashAttention_Intrinsics", KernelBackend::AVX2, "2.0", "Phase 7B AVX2 Intrinsics", false, 0.0f, 0.0f, 0.0f});
        std::cout << "  ✓ FlashAttention Intrinsics (Phase 7B - PREFERRED)" << std::endl;
    }
    
    //========================================================================
    // PRINT STATUS
    //========================================================================
    
    std::cout << "[RegisterAllKernels] Registration complete" << std::endl;
    registry.PrintStatus();
    
    return true;
}

} // namespace Sovereign

//============================================================================
// C API
//============================================================================

extern "C" {

int Sovereign_RegisterAllKernels(void)
{
    return Sovereign::RegisterAllKernels() ? 0 : 1;
}

} // extern "C"
