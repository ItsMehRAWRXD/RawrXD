// ============================================================================
// MASM Integration Layer - Links C++ to Assembly Kernels
// Only provides stubs for kernels not yet in assembly
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cmath>

// Assembly functions from .obj files
extern "C" {
    // In silu_avx512.obj
    int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
    
    // In silu_activation_avx512_fixed.obj (FAST_EXP2-based, < 1e-5 error)
    int MASM_Silu_Activation_AVX512_Fixed(float* data, size_t data_size);
    
    // In softmax_avx2.obj  
    int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);
}

// RMSNorm stub (not yet in assembly)
extern "C" int MASM_RMSNorm_Forward_AVX2(float* input, float* output, float* weights, size_t size) {
    if (!input || !output || !weights) return 1;
    if (size == 0) return 2;
    if (size % 8 != 0) return 4;
    
    // Scalar fallback
    float sum_sq = 0.0f;
    for (size_t i = 0; i < size; ++i) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / size + 1e-6f);
    float scale = 1.0f / rms;
    
    for (size_t i = 0; i < size; ++i) {
        output[i] = input[i] * scale * weights[i];
    }
    
    return 0;
}
