//=============================================================================
// Q4_0 Weight Preprocessor - Implementation
// Converts nibble-interleaved GGUF format to byte-planar for fast AVX-512
//=============================================================================

#include "Q4WeightPreprocess.hpp"
#include <cstring>
#include <cmath>

namespace RawrXD {
namespace Memory {

// FP16 -> FP32 conversion
static float fp16_to_fp32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exponent = (h >> 10) & 0x1F;
    uint32_t mantissa = h & 0x3FF;
    
    if (exponent == 0) {
        return sign ? -0.0f : 0.0f;
    } else if (exponent == 0x1F) {
        return sign ? -INFINITY : INFINITY;
    }
    
    int32_t exp = static_cast<int32_t>(exponent) - 15 + 127;
    uint32_t f32_bits = (sign << 31) | (exp << 23) | (mantissa << 13);
    return *reinterpret_cast<float*>(&f32_bits);
}

void Q4WeightPreprocessor::PreprocessBlock(
    const void* gguf_block,
    PreprocessedQ4Block* output_block,
    uint32_t block_index,
    uint32_t total_blocks,
    uint32_t total_elements
) {
    const uint8_t* input = static_cast<const uint8_t*>(gguf_block);
    
    // Initialize header with metadata
    output_block->init_header(total_blocks, total_elements);
    
    // Convert scale (fp16 -> fp32)
    uint16_t scale_fp16;
    std::memcpy(&scale_fp16, input, 2);
    output_block->scale = fp16_to_fp32(scale_fp16);
    
    // Unpack 32 packed nibbles into 64 bytes
    // Each byte in input[2:33] contains 2 weights
    for (int i = 0; i < 32; i++) {
        uint8_t packed = input[2 + i];
        
        // Low nibble -> weight 2*i
        output_block->weights[i * 2] = static_cast<int8_t>((packed & 0x0F) - 8);
        
        // High nibble -> weight 2*i + 1
        output_block->weights[i * 2 + 1] = static_cast<int8_t>(((packed >> 4) & 0x0F) - 8);
    }
    
    // Zero padding
    std::memset(output_block->padding, 0, sizeof(output_block->padding));
}

std::vector<PreprocessedQ4Block> Q4WeightPreprocessor::PreprocessTensor(
    const void* gguf_tensor_data,
    size_t num_blocks
) {
    std::vector<PreprocessedQ4Block> result;
    result.reserve(num_blocks);
    
    const uint8_t* input = static_cast<const uint8_t*>(gguf_tensor_data);
    
    for (size_t i = 0; i < num_blocks; i++) {
        PreprocessedQ4Block block;
        PreprocessBlock(input + i * 64, &block);
        result.push_back(block);
    }
    
    return result;
}

float Q4WeightPreprocessor::ExtractScale(const PreprocessedQ4Block* block) {
    return fp16_to_fp32(block->scale);
}

bool Q4WeightPreprocessor::ValidateBlock(
    const void* gguf_block,
    const PreprocessedQ4Block* preprocessed_block
) {
    // Validate header
    if (!preprocessed_block->validate()) {
        return false;
    }
    
    const uint8_t* input = static_cast<const uint8_t*>(gguf_block);
    
    // Check scale (compare fp16 input vs fp32 output)
    uint16_t input_scale_fp16;
    std::memcpy(&input_scale_fp16, input, 2);
    float input_scale = fp16_to_fp32(input_scale_fp16);
    
    // Allow small floating point error in scale conversion
    float scale_diff = std::abs(input_scale - preprocessed_block->scale);
    if (scale_diff > 1e-6f) {
        return false;
    }
    
    // Check unpacked weights
    for (int i = 0; i < 32; i++) {
        uint8_t packed = input[2 + i];
        int8_t expected_low = static_cast<int8_t>((packed & 0x0F) - 8);
        int8_t expected_high = static_cast<int8_t>(((packed >> 4) & 0x0F) - 8);
        
        if (preprocessed_block->weights[i * 2] != expected_low) {
            return false;
        }
        if (preprocessed_block->weights[i * 2 + 1] != expected_high) {
            return false;
        }
    }
    
    return true;
}

} // namespace Memory
} // namespace RawrXD

//=============================================================================
// AVX-512 Kernel Implementation (C++ with intrinsics)
// This is the fast path using preprocessed weights
//=============================================================================

#include <immintrin.h>

namespace {

// Dot product of 64 preprocessed weights with 64 activations
// Using AVX-512: process 16 at a time, 4 passes
float q4_preprocessed_dot_avx512_impl(
    const RawrXD::Memory::PreprocessedQ4Block* block,
    const float* activations
) {
    // Load scale
    float scale = RawrXD::Memory::Q4WeightPreprocessor::ExtractScale(block);
    __m512 scale_vec = _mm512_set1_ps(scale);
    
    // Accumulator
    __m512 acc = _mm512_setzero_ps();
    
    // Process 64 weights in 4 chunks of 16
    for (int chunk = 0; chunk < 4; chunk++) {
        int offset = chunk * 16;
        
        // Load 16 weights (int8) and convert to int32
        // Weights are at block->weights[offset:offset+15]
        __m128i weight_bytes = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(block->weights + offset)
        );
        
        // Sign-extend int8 to int32
        __m512i weight_i32 = _mm512_cvtepi8_epi32(weight_bytes);
        
        // Convert int32 to float
        __m512 weight_f32 = _mm512_cvtepi32_ps(weight_i32);
        
        // Scale: weight * scale
        weight_f32 = _mm512_mul_ps(weight_f32, scale_vec);
        
        // Load 16 activations
        __m512 act_vec = _mm512_loadu_ps(activations + offset);
        
        // FMA: acc += weight * activation
        acc = _mm512_fmadd_ps(weight_f32, act_vec, acc);
    }
    
    // Horizontal sum of 16 floats in acc
    // Reduce to single float
    __m256 acc_256 = _mm256_add_ps(
        _mm512_castps512_ps256(acc),
        _mm512_extractf32x8_ps(acc, 1)
    );
    
    __m128 acc_128 = _mm_add_ps(
        _mm256_castps256_ps128(acc_256),
        _mm256_extractf128_ps(acc_256, 1)
    );
    
    acc_128 = _mm_hadd_ps(acc_128, acc_128);
    acc_128 = _mm_hadd_ps(acc_128, acc_128);
    
    return _mm_cvtss_f32(acc_128);
}

} // anonymous namespace

// C interface for ASM linkage
extern "C" {

float q4_preprocessed_dot_avx512(
    const RawrXD::Memory::PreprocessedQ4Block* block,
    const float* activations
) {
    return q4_preprocessed_dot_avx512_impl(block, activations);
}

void q4_preprocessed_gemm_avx512(
    const RawrXD::Memory::PreprocessedQ4Block* blocks,
    const float* activations,
    float* output,
    size_t num_blocks,
    size_t num_outputs
) {
    // For each output element
    for (size_t j = 0; j < num_outputs; j++) {
        float sum = 0.0f;
        
        // Dot product over all blocks
        for (size_t k = 0; k < num_blocks; k++) {
            sum += q4_preprocessed_dot_avx512_impl(&blocks[k], activations + k * 64);
        }
        
        output[j] = sum;
    }
}

} // extern "C"
