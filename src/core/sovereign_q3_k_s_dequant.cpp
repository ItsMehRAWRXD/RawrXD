// =============================================================================
// sovereign_q3_k_s_dequant.cpp
// Q3_K_S Dequantization Kernel
// Converts 3-bit K-quantized weights to float32 for inference
// =============================================================================

#include "sovereign_q3_k_s_dequant.h"
#include <cstdint>
#include <cstring>
#include <windows.h>
#include <intrin.h>

namespace Sovereign {

// =============================================================================
// Q3_K_S Block Structure
// =============================================================================
// Q3_K_S uses 256-element blocks with 3-bit quantization
// Each block contains:
// - 2 bytes: scales (4 scales for 4 groups of 64)
// - 96 bytes: quantized values (256 * 3 bits = 768 bits = 96 bytes)
// Total: 98 bytes per 256 elements = ~3.06 bits per weight

struct Q3_K_S_Block {
    uint8_t scales[2];      // 2 bytes for 4 group scales
    uint8_t quants[96];     // 96 bytes for 256 3-bit weights
};

// =============================================================================
// C++ Reference Dequantization
// =============================================================================

void Dequantize_Q3_K_S_Reference(const uint8_t* src, float* dst, uint32_t n_elements) {
    const uint32_t n_blocks = (n_elements + 255) / 256;
    const Q3_K_S_Block* blocks = reinterpret_cast<const Q3_K_S_Block*>(src);
    
    for (uint32_t b = 0; b < n_blocks; b++) {
        const Q3_K_S_Block* block = &blocks[b];
        
        // Extract 4 scales from 2 bytes
        // Each nibble (4 bits) is a scale index 0-15
        float scales[4];
        scales[0] = static_cast<float>(block->scales[0] & 0x0F);
        scales[1] = static_cast<float>((block->scales[0] >> 4) & 0x0F);
        scales[2] = static_cast<float>(block->scales[1] & 0x0F);
        scales[3] = static_cast<float>((block->scales[1] >> 4) & 0x0F);
        
        // Normalize scales (0-15 -> 0.0-1.0 range, then scale)
        // In K-quants, scales are multiplied by a quantization factor
        for (int i = 0; i < 4; i++) {
            scales[i] = scales[i] / 16.0f;
        }
        
        // Dequantize 256 weights
        for (uint32_t i = 0; i < 256 && (b * 256 + i) < n_elements; i++) {
            uint32_t byte_idx = (i * 3) / 8;
            uint32_t bit_offset = (i * 3) % 8;
            
            uint8_t val = 0;
            if (bit_offset <= 5) {
                // All 3 bits in one byte
                val = (block->quants[byte_idx] >> bit_offset) & 0x07;
            } else {
                // Split across two bytes
                uint8_t low_bits = (block->quants[byte_idx] >> bit_offset) & ((1 << (8 - bit_offset)) - 1);
                uint8_t high_bits = (block->quants[byte_idx + 1] << (8 - bit_offset)) & 0x07;
                val = low_bits | high_bits;
            }
            
            // Map 3-bit value (0-7) to float
            // Center around 0: 0->-3.5, 7->+3.5
            float dequant = static_cast<float>(val) - 3.5f;
            
            // Apply group scale (each group of 64 has its own scale)
            uint32_t group = i / 64;
            dst[b * 256 + i] = dequant * scales[group];
        }
    }
}

// =============================================================================
// AVX2-Optimized Dequantization
// =============================================================================

#ifdef __AVX2__
#include <immintrin.h>

void Dequantize_Q3_K_S_AVX2(const uint8_t* src, float* dst, uint32_t n_elements) {
    const uint32_t n_blocks = (n_elements + 255) / 256;
    const Q3_K_S_Block* blocks = reinterpret_cast<const Q3_K_S_Block*>(src);
    
    for (uint32_t b = 0; b < n_blocks; b++) {
        const Q3_K_S_Block* block = &blocks[b];
        
        // Extract scales
        __m256 scale_vec[4];
        float scales[4];
        scales[0] = static_cast<float>(block->scales[0] & 0x0F) / 16.0f;
        scales[1] = static_cast<float>((block->scales[0] >> 4) & 0x0F) / 16.0f;
        scales[2] = static_cast<float>(block->scales[1] & 0x0F) / 16.0f;
        scales[3] = static_cast<float>((block->scales[1] >> 4) & 0x0F) / 16.0f;
        
        for (int i = 0; i < 4; i++) {
            scale_vec[i] = _mm256_set1_ps(scales[i]);
        }
        
        // Process 256 weights in groups of 8 (AVX2 can do 8 floats at once)
        // This is a simplified version - full AVX2 would unpack bits more efficiently
        for (uint32_t i = 0; i < 256 && (b * 256 + i) < n_elements; i += 8) {
            float temp[8];
            
            // Extract 8 consecutive 3-bit values
            for (int j = 0; j < 8 && (i + j) < 256; j++) {
                uint32_t idx = i + j;
                uint32_t byte_idx = (idx * 3) / 8;
                uint32_t bit_offset = (idx * 3) % 8;
                
                uint8_t val = 0;
                if (bit_offset <= 5) {
                    val = (block->quants[byte_idx] >> bit_offset) & 0x07;
                } else {
                    uint8_t low_bits = (block->quants[byte_idx] >> bit_offset) & ((1 << (8 - bit_offset)) - 1);
                    uint8_t high_bits = (block->quants[byte_idx + 1] << (8 - bit_offset)) & 0x07;
                    val = low_bits | high_bits;
                }
                
                uint32_t group = idx / 64;
                temp[j] = (static_cast<float>(val) - 3.5f) * scales[group];
            }
            
            _mm256_storeu_ps(&dst[b * 256 + i], _mm256_loadu_ps(temp));
        }
    }
}

#endif // __AVX2__

// =============================================================================
// Dispatch Function
// =============================================================================

void Dequantize_Q3_K_S(const uint8_t* src, float* dst, uint32_t n_elements) {
    if (!src || !dst || n_elements == 0) return;
    
#ifdef __AVX2__
    // Check CPU support at runtime using MSVC intrinsics
    int cpu_info[4] = {0};
    __cpuid(cpu_info, 1);
    bool has_avx2 = (cpu_info[2] & (1 << 28)) != 0; // Check AVX bit
    
    if (has_avx2 && n_elements >= 256) {
        Dequantize_Q3_K_S_AVX2(src, dst, n_elements);
        return;
    }
#endif
    
    // Fallback to reference implementation
    Dequantize_Q3_K_S_Reference(src, dst, n_elements);
}

// =============================================================================
// Tensor Dequantization Helper
// =============================================================================

bool DequantizeTensor_Q3_K_S(
    const uint8_t* quantized_data,
    uint64_t quantized_size,
    uint32_t n_elements,
    float** out_dequantized
) {
    if (!quantized_data || !out_dequantized || n_elements == 0) {
        return false;
    }
    
    // Allocate output buffer
    float* dequantized = static_cast<float*>(
        VirtualAlloc(nullptr, n_elements * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    );
    
    if (!dequantized) {
        return false;
    }
    
    // Dequantize
    Dequantize_Q3_K_S(quantized_data, dequantized, n_elements);
    
    *out_dequantized = dequantized;
    return true;
}

// =============================================================================
// Get Dequantized Size
// =============================================================================

uint64_t GetDequantizedSize_Q3_K_S(uint64_t quantized_size) {
    // Q3_K_S: 98 bytes per 256 elements
    // Dequantized: 256 * 4 bytes = 1024 bytes per block
    uint64_t n_blocks = quantized_size / 98;
    return n_blocks * 256 * sizeof(float);
}

uint32_t GetElementCount_Q3_K_S(uint64_t quantized_size) {
    uint64_t n_blocks = quantized_size / 98;
    return static_cast<uint32_t>(n_blocks * 256);
}

} // namespace Sovereign
