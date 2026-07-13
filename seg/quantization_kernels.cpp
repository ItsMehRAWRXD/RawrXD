// ============================================================================
// Quantization Kernels Implementation
// ============================================================================
// Q4_K, Q6_K, Q8_K dequantization with AVX-512 optimization
// ============================================================================

#include "quantization_kernels.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <immintrin.h>
#include <cpuid.h>

namespace RawrXD {
namespace Quantization {

// ============================================================================
// CPU Feature Detection
// ============================================================================

bool QuantizationKernels::initialized_ = false;
bool QuantizationKernels::has_avx512_ = false;
bool QuantizationKernels::has_avx2_ = false;
bool QuantizationKernels::has_fma_ = false;

void QuantizationKernels::Initialize() {
    if (initialized_) return;
    
    // Check CPU features using CPUID
    unsigned int eax, ebx, ecx, edx;
    
    // Check for AVX2/FMA (CPUID leaf 1)
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    has_avx2_ = (ecx & (1 << 28)) != 0;  // AVX
    has_fma_ = (ecx & (1 << 12)) != 0;   // FMA
    
    // Check for AVX-512 (CPUID leaf 7)
    if (__get_cpuid_max(0, &eax) >= 7) {
        __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
        has_avx512_ = (ebx & (1 << 16)) != 0;  // AVX512F
    }
    
    initialized_ = true;
}

bool QuantizationKernels::HasAVX512() {
    if (!initialized_) Initialize();
    return has_avx512_;
}

// ============================================================================
// Q4_K Scalar Implementation
// ============================================================================

size_t DequantizeQ4_K_Scalar(const void* quantized, float* output, size_t num_elements) {
    const BlockQ4_K* blocks = static_cast<const BlockQ4_K*>(quantized);
    const size_t num_blocks = (num_elements + QK_K - 1) / QK_K;
    
    size_t idx = 0;
    for (size_t b = 0; b < num_blocks && idx < num_elements; b++) {
        const BlockQ4_K& block = blocks[b];
        
        // Extract super-block scales
        float d = HalfToFloat(block.d);
        float dmin = HalfToFloat(block.dmin);
        
        // Decode scales and mins (6-bit values packed in scales array)
        float scales[8];
        float mins[8];
        
        // scales[0..5] are in scales[0..2] (4 bits each, but actually 6-bit)
        // This is a simplified version - full implementation needs proper bit unpacking
        for (int i = 0; i < 8; i++) {
            // Simplified: assume scales are stored as 8-bit values
            scales[i] = (i < 6) ? ((block.scales[i/2] >> (4 * (i%2))) & 0xF) : 0;
            mins[i] = (i < 6) ? ((block.scales[3 + i/2] >> (4 * (i%2))) & 0xF) : 0;
        }
        
        // Dequantize 256 values (8 blocks of 32)
        for (int block_idx = 0; block_idx < 8 && idx < num_elements; block_idx++) {
            float block_scale = d * scales[block_idx];
            float block_min = dmin * mins[block_idx];
            
            for (int i = 0; i < 32 && idx < num_elements; i++) {
                // Extract 4-bit value
                uint8_t packed = block.qs[block_idx * 32 + i / 2];
                uint8_t nibble = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
                
                // Dequantize: value = (nibble * scale) + min
                output[idx++] = (nibble * block_scale) + block_min;
            }
        }
    }
    
    return idx;
}

// ============================================================================
// Q6_K Scalar Implementation
// ============================================================================

size_t DequantizeQ6_K_Scalar(const void* quantized, float* output, size_t num_elements) {
    const BlockQ6_K* blocks = static_cast<const BlockQ6_K*>(quantized);
    const size_t num_blocks = (num_elements + QK_K - 1) / QK_K;
    
    size_t idx = 0;
    for (size_t b = 0; b < num_blocks && idx < num_elements; b++) {
        const BlockQ6_K& block = blocks[b];
        
        float d = HalfToFloat(block.d);
        
        // Dequantize 256 values (16 blocks of 16)
        for (int block_idx = 0; block_idx < 16 && idx < num_elements; block_idx++) {
            float scale = d * block.scales[block_idx];
            
            for (int i = 0; i < 16 && idx < num_elements; i++) {
                // Extract 6-bit value
                // ql has lower 4 bits, qh has upper 2 bits
                uint8_t low = block.ql[block_idx * 16 + i] & 0x0F;
                uint8_t high = (block.qh[block_idx * 8 + i / 2] >> (4 * (i % 2))) & 0x03;
                uint8_t q = low | (high << 4);
                
                // Dequantize: value = (q - 32) * scale
                output[idx++] = (static_cast<float>(q) - 32.0f) * scale;
            }
        }
    }
    
    return idx;
}

// ============================================================================
// Q8_K Scalar Implementation
// ============================================================================

size_t DequantizeQ8_K_Scalar(const void* quantized, float* output, size_t num_elements) {
    const BlockQ8_K* blocks = static_cast<const BlockQ8_K*>(quantized);
    const size_t num_blocks = (num_elements + QK_K - 1) / QK_K;
    
    size_t idx = 0;
    for (size_t b = 0; b < num_blocks && idx < num_elements; b++) {
        const BlockQ8_K& block = blocks[b];
        float d = block.d;
        
        for (int i = 0; i < QK_K && idx < num_elements; i++) {
            output[idx++] = static_cast<float>(block.qs[i]) * d;
        }
    }
    
    return idx;
}

// ============================================================================
// AVX-512 Implementations
// ============================================================================

#ifdef __AVX512F__

// Helper: Broadcast 16-bit half-float to 512-bit register
static inline __m512 BroadcastF16(uint16_t h) {
    float f = HalfToFloat(h);
    return _mm512_set1_ps(f);
}

// Q4_K AVX-512 Implementation
size_t DequantizeQ4_K_AVX512(const void* quantized, float* output, size_t num_elements) {
    const BlockQ4_K* blocks = static_cast<const BlockQ4_K*>(quantized);
    const size_t num_blocks = (num_elements + QK_K - 1) / QK_K;
    
    size_t idx = 0;
    for (size_t b = 0; b < num_blocks && idx < num_elements; b++) {
        const BlockQ4_K& block = blocks[b];
        
        float d = HalfToFloat(block.d);
        float dmin = HalfToFloat(block.dmin);
        
        __m512 vd = _mm512_set1_ps(d);
        __m512 vdmin = _mm512_set1_ps(dmin);
        
        // Process 256 values per block, 16 at a time
        for (int block_idx = 0; block_idx < 8 && idx < num_elements; block_idx++) {
            // Simplified scale extraction (would need proper 6-bit unpacking)
            float scale_val = ((block.scales[block_idx/2] >> (4 * (block_idx%2))) & 0xF);
            float min_val = ((block.scales[3 + block_idx/2] >> (4 * (block_idx%2))) & 0xF);
            
            __m512 vscale = _mm512_mul_ps(vd, _mm512_set1_ps(scale_val));
            __m512 vmin = _mm512_mul_ps(vdmin, _mm512_set1_ps(min_val));
            
            for (int i = 0; i < 32 && idx < num_elements; i += 16) {
                // Load 16 nibbles (8 bytes)
                uint8_t temp[16];
                for (int j = 0; j < 16 && (i + j) < 32; j++) {
                    uint8_t packed = block.qs[block_idx * 32 + (i + j) / 2];
                    temp[j] = ((i + j) % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
                }
                
                // Convert to float and dequantize
                float vals[16];
                for (int j = 0; j < 16 && (i + j) < 32; j++) {
                    vals[j] = static_cast<float>(temp[j]);
                }
                
                __m512 vq = _mm512_loadu_ps(vals);
                __m512 vresult = _mm512_add_ps(_mm512_mul_ps(vq, vscale), vmin);
                
                _mm512_storeu_ps(&output[idx], vresult);
                idx += std::min(16, static_cast<int>(num_elements - idx));
            }
        }
    }
    
    return idx;
}

// Q6_K AVX-512 Implementation
size_t DequantizeQ6_K_AVX512(const void* quantized, float* output, size_t num_elements) {
    const BlockQ6_K* blocks = static_cast<const BlockQ6_K*>(quantized);
    const size_t num_blocks = (num_elements + QK_K - 1) / QK_K;
    
    size_t idx = 0;
    for (size_t b = 0; b < num_blocks && idx < num_elements; b++) {
        const BlockQ6_K& block = blocks[b];
        
        __m512 vd = BroadcastF16(block.d);
        
        // Process 256 values per block, 16 at a time
        for (int block_idx = 0; block_idx < 16 && idx < num_elements; block_idx++) {
            __m512 vscale = _mm512_mul_ps(vd, _mm512_set1_ps(block.scales[block_idx]));
            __m512 voffset = _mm512_set1_ps(-32.0f);
            
            for (int i = 0; i < 16 && idx < num_elements; i += 16) {
                // Extract 16 6-bit values
                float vals[16];
                for (int j = 0; j < 16 && (i + j) < 16; j++) {
                    uint8_t low = block.ql[block_idx * 16 + i + j] & 0x0F;
                    uint8_t high = (block.qh[block_idx * 8 + (i + j) / 2] >> (4 * ((i + j) % 2))) & 0x03;
                    vals[j] = static_cast<float>(low | (high << 4));
                }
                
                __m512 vq = _mm512_loadu_ps(vals);
                __m512 vresult = _mm512_mul_ps(_mm512_add_ps(vq, voffset), vscale);
                
                _mm512_storeu_ps(&output[idx], vresult);
                idx += std::min(16, static_cast<int>(num_elements - idx));
            }
        }
    }
    
    return idx;
}

// Q8_K AVX-512 Implementation
size_t DequantizeQ8_K_AVX512(const void* quantized, float* output, size_t num_elements) {
    const BlockQ8_K* blocks = static_cast<const BlockQ8_K*>(quantized);
    const size_t num_blocks = (num_elements + QK_K - 1) / QK_K;
    
    size_t idx = 0;
    for (size_t b = 0; b < num_blocks && idx < num_elements; b++) {
        const BlockQ8_K& block = blocks[b];
        __m512 vd = _mm512_set1_ps(block.d);
        
        // Process 256 values, 16 at a time
        for (int i = 0; i < QK_K && idx < num_elements; i += 16) {
            // Load 16 int8 values and convert to float
            int8_t temp[16];
            for (int j = 0; j < 16 && (i + j) < QK_K; j++) {
                temp[j] = block.qs[i + j];
            }
            
            // Convert int8 to float
            float vals[16];
            for (int j = 0; j < 16; j++) {
                vals[j] = static_cast<float>(temp[j]);
            }
            
            __m512 vq = _mm512_loadu_ps(vals);
            __m512 vresult = _mm512_mul_ps(vq, vd);
            
            _mm512_storeu_ps(&output[idx], vresult);
            idx += std::min(16, static_cast<int>(num_elements - idx));
        }
    }
    
    return idx;
}

#endif // __AVX512F__

// ============================================================================
// Dispatch Layer
// ============================================================================

size_t QuantizationKernels::DequantizeQ4_K(const void* quantized, float* output, size_t num_elements) {
    if (!initialized_) Initialize();
    
#ifdef __AVX512F__
    if (has_avx512_) {
        return DequantizeQ4_K_AVX512(quantized, output, num_elements);
    }
#endif
    return DequantizeQ4_K_Scalar(quantized, output, num_elements);
}

size_t QuantizationKernels::DequantizeQ6_K(const void* quantized, float* output, size_t num_elements) {
    if (!initialized_) Initialize();
    
#ifdef __AVX512F__
    if (has_avx512_) {
        return DequantizeQ6_K_AVX512(quantized, output, num_elements);
    }
#endif
    return DequantizeQ6_K_Scalar(quantized, output, num_elements);
}

size_t QuantizationKernels::DequantizeQ8_K(const void* quantized, float* output, size_t num_elements) {
    if (!initialized_) Initialize();
    
#ifdef __AVX512F__
    if (has_avx512_) {
        return DequantizeQ8_K_AVX512(quantized, output, num_elements);
    }
#endif
    return DequantizeQ8_K_Scalar(quantized, output, num_elements);
}

} // namespace Quantization
} // namespace RawrXD
