// ============================================================================
// masm_stubs.cpp - Stub implementations for MASM GEMV kernels
// Needed to link test executables that use QuantKernelRegistry without .asm files.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {

// Q4_K MASM kernels
void Sovereign_Q4K_GEMV_AVX2(const void* q4_weights, const float* input,
                              float* output, unsigned int num_blocks, unsigned int rows) {
    // No-op stub
    if (output) std::memset(output, 0, rows * sizeof(float));
}

void Sovereign_Q4K_GEMV_AVX2_V2(const void* q4_weights, const float* input,
                                 float* output, unsigned int num_blocks, unsigned int rows) {
    if (output) std::memset(output, 0, rows * sizeof(float));
}

// Q2_K / Q3_K MASM kernels
void Deep2_Q2_K_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    if (output) std::memset(output, 0, outputDim * sizeof(float));
}

void Deep2_Q3_K_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    if (output) std::memset(output, 0, outputDim * sizeof(float));
}

// Q4_0 / Q4_1 / Q8_0 / Q5_K / Q6_K MASM kernels
void Deep2_Q4_0_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    if (output) std::memset(output, 0, outputDim * sizeof(float));
}

void Deep2_Q4_1_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    if (output) std::memset(output, 0, outputDim * sizeof(float));
}

void Deep2_Q8_0_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    if (output) std::memset(output, 0, outputDim * sizeof(float));
}

void Deep2_Q5_K_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    if (output) std::memset(output, 0, outputDim * sizeof(float));
}

void Deep2_Q6_K_GEMV(const void* blocks, const float* x, float* out, std::size_t nBlocks) {
    if (out) std::memset(out, 0, nBlocks * sizeof(float));
}

// FP16 GEMV
void Deep2_FP16_GEMV(const void* weights, const float* input, float* output,
                     unsigned int rows, unsigned int cols) {
    if (output) std::memset(output, 0, rows * sizeof(float));
}

} // extern "C"
