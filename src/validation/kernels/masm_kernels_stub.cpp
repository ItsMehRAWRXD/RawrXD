// ============================================================================
// MASM Kernels - Assembly Integration Layer
// Links C++ code to AVX2/AVX-512 assembly kernels
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cmath>

// Assembly function declarations (defined in .obj files from .asm)
// DO NOT provide implementations here - they are in the .obj files
extern "C" {
    // Real AVX-512 implementation (in silu_avx512.obj)
    int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
    
    // Real AVX2 implementation (in softmax_avx2.obj)
    int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);
    
    // Stub for RMSNorm (not yet implemented in assembly) - defined here
    int MASM_RMSNorm_Forward_AVX2(float* input, float* output, float* weights, size_t size);
}

// RMSNorm Forward - Stub implementation (not in assembly yet)
extern "C" int MASM_RMSNorm_Forward_AVX2(float* input, float* output, float* weights, size_t size) {
    // Validate inputs
    if (!input || !output || !weights) return 1;
    if (size == 0) return 2;
    if (size % 8 != 0) return 4; // Must be multiple of 8
    if ((reinterpret_cast<uintptr_t>(input) % 32) != 0) return 3;
    if ((reinterpret_cast<uintptr_t>(output) % 32) != 0) return 3;
    if ((reinterpret_cast<uintptr_t>(weights) % 32) != 0) return 3;
    
    // Stub: Calculate RMS
    float sum_sq = 0.0f;
    for (size_t i = 0; i < size; ++i) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / size + 1e-6f);
    float scale = 1.0f / rms;
    
    // Normalize and apply weights
    for (size_t i = 0; i < size; ++i) {
        output[i] = input[i] * scale * weights[i];
    }
    
    return 0;
}

// Softmax Forward - AVX2 stub
int MASM_Softmax_Forward_AVX2(float* data, size_t data_size) {
    // Validate inputs
    if (!data) return 1;
    if (data_size == 0) return 2;
    if (data_size % 32 != 0) return 4;
    if ((reinterpret_cast<uintptr_t>(data) % 32) != 0) return 3;
    
    size_t size = data_size / sizeof(float);
    
    // Find max
    float max_val = data[0];
    for (size_t i = 1; i < size; ++i) {
        if (data[i] > max_val) max_val = data[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (size_t i = 0; i < size; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum += data[i];
    }
    
    // Normalize
    for (size_t i = 0; i < size; ++i) {
        data[i] /= sum;
    }
    
    return 0;
}

} // extern "C"
