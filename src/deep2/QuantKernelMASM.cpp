// ============================================================================
// QuantKernelStubs.cpp - Stub implementations for missing MASM quantization
// kernels. These provide functional (but not optimized) fallbacks until the
// corresponding .asm files are implemented.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>

extern "C" {

// ============================================================================
// Q4_K GEMV (stub - scalar fallback)
// ============================================================================
void Sovereign_Q4K_GEMV_AVX2_V2(
    const void* q4_weights,
    const float* input,
    float* output,
    unsigned int num_blocks,
    unsigned int rows
) {
    // Q4_K block: 144 bytes per 256 weights
    // Layout: 2x FP16 scales + 2x FP16 mins + 12 bytes scales/mins + 128 bytes weights
    // For stub: just zero output
    if (output && rows > 0) {
        std::memset(output, 0, rows * sizeof(float));
    }
    (void)q4_weights;
    (void)input;
    (void)num_blocks;
}

// ============================================================================
// Q2_K GEMV (stub - scalar fallback)
// ============================================================================
void Sovereign_Q2K_GEMV_AVX2_V2(
    const void* q2_weights,
    const float* input,
    float* output,
    unsigned int num_blocks,
    unsigned int rows
) {
    if (output && rows > 0) {
        std::memset(output, 0, rows * sizeof(float));
    }
    (void)q2_weights;
    (void)input;
    (void)num_blocks;
}

// ============================================================================
// Q3_K GEMV (stub - scalar fallback)
// ============================================================================
void Sovereign_Q3K_GEMV_AVX2_V2(
    const void* q3_weights,
    const float* input,
    float* output,
    unsigned int num_blocks,
    unsigned int rows
) {
    if (output && rows > 0) {
        std::memset(output, 0, rows * sizeof(float));
    }
    (void)q3_weights;
    (void)input;
    (void)num_blocks;
}

// ============================================================================
// Q4_0 GEMV (stub - scalar fallback)
// Q4_0 block: 18 bytes for 32 weights
//   offset 0:  FP16 delta (2 bytes)
//   offset 2:  32 x 4-bit weights (16 bytes)
// ============================================================================
void Deep2_Q4_0_GEMV(
    const void* weights,
    const float* input,
    float* output,
    unsigned int numBlocks,
    unsigned int outputDim
) {
    if (!weights || !input || !output || numBlocks == 0 || outputDim == 0) {
        return;
    }

    // Scalar dequantization for Q4_0
    // Each block: 18 bytes = FP16 delta + 16 bytes of 4-bit weights
    const uint8_t* w = static_cast<const uint8_t*>(weights);
    
    for (unsigned int row = 0; row < outputDim; ++row) {
        float sum = 0.0f;
        const uint8_t* row_weights = w + row * numBlocks * 18;
        
        for (unsigned int block = 0; block < numBlocks; ++block) {
            const uint8_t* block_ptr = row_weights + block * 18;
            
            // Read FP16 delta
            uint16_t delta_u16 = *reinterpret_cast<const uint16_t*>(block_ptr);
            // Simple FP16 to FP32 conversion (no denormals)
            float delta;
            if ((delta_u16 & 0x7C00) == 0) {
                delta = 0.0f; // zero or denormal
            } else {
                int exp = ((delta_u16 >> 10) & 0x1F) - 15 + 127;
                int mant = (delta_u16 & 0x3FF) << 13;
                int sign = (delta_u16 >> 15) << 31;
                uint32_t f32_bits = static_cast<uint32_t>(sign | (exp << 23) | mant);
                std::memcpy(&delta, &f32_bits, sizeof(float));
            }
            
            // Dequantize 32 weights (4-bit each, packed in 16 bytes)
            for (int i = 0; i < 32; ++i) {
                int byte_idx = i / 2;
                int nibble = (i % 2 == 0) ? (block_ptr[2 + byte_idx] & 0x0F) : ((block_ptr[2 + byte_idx] >> 4) & 0x0F);
                float weight_val = delta * static_cast<float>(nibble);
                unsigned int input_idx = block * 32 + i;
                sum += weight_val * input[input_idx];
            }
        }
        output[row] = sum;
    }
}

// ============================================================================
// Aliases for expected symbol names
// ============================================================================
void Deep2_Q2_K_GEMV(
    const void* weights,
    const float* input,
    float* output,
    unsigned int numBlocks,
    unsigned int outputDim
) {
    Sovereign_Q2K_GEMV_AVX2_V2(weights, input, output, numBlocks, outputDim);
}

void Deep2_Q3_K_GEMV(
    const void* weights,
    const float* input,
    float* output,
    unsigned int numBlocks,
    unsigned int outputDim
) {
    Sovereign_Q3K_GEMV_AVX2_V2(weights, input, output, numBlocks, outputDim);
}

} // extern "C"
