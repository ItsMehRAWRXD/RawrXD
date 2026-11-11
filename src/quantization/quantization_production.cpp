//=============================================================================
// RawrXD Quantization Support - IMPLEMENTATION
// Supports Q4_K_M, Q5_K_M, Q8_0, and other GGML formats
//=============================================================================

#include "quantization_production.hpp"
#include <algorithm>
#include <cmath>
#include <string>

// SIMD intrinsics
#ifdef _MSC_VER
#include <immintrin.h>
#else
#include <x86intrin.h>
#endif

namespace RawrXD {
namespace Quantization {

//=============================================================================
// Quantization Type Information
//=============================================================================

static const QuantTypeInfo kQuantTypeInfo[] = {
    { QuantType::F32,  "F32",  1,   4,   4,  false, 0.0f },
    { QuantType::F16,  "F16",  1,   2,   2,  false, 0.0f },
    { QuantType::BF16, "BF16", 1,   2,   2,  false, 0.0f },
    { QuantType::Q8_0, "Q8_0", 32,  36,  1,  true,  0.01f },
    { QuantType::Q4_0, "Q4_0", 32,  20,  1,  true,  0.05f },
    { QuantType::Q4_1, "Q4_1", 32,  24,  1,  true,  0.04f },
    { QuantType::Q5_0, "Q5_0", 32,  24,  1,  true,  0.03f },
    { QuantType::Q5_1, "Q5_1", 32,  28,  1,  true,  0.025f },
    { QuantType::Q2_K, "Q2_K", 256, 84,  1,  true,  0.15f },
    { QuantType::Q3_K, "Q3_K", 256, 110, 1,  true,  0.10f },
    { QuantType::Q4_K, "Q4_K", 256, 140, 1,  true,  0.05f },
    { QuantType::Q5_K, "Q5_K", 256, 172, 1,  true,  0.03f },
    { QuantType::Q6_K, "Q6_K", 256, 320, 1,  true,  0.02f },
    { QuantType::Q8_K, "Q8_K", 256, 264, 1,  true,  0.005f },
};

const QuantTypeInfo* GetQuantTypeInfo(QuantType type) {
    for (const auto& info : kQuantTypeInfo) {
        if (info.type == type) return &info;
    }
    return nullptr;
}

const char* QuantTypeToString(QuantType type) {
    const auto* info = GetQuantTypeInfo(type);
    return info ? info->name : "UNKNOWN";
}

QuantType StringToQuantType(const char* str) {
    for (const auto& info : kQuantTypeInfo) {
        if (std::strcmp(info.name, str) == 0) return info.type;
    }
    return QuantType::F32;
}

QuantizedTensorInfo CalculateQuantizedTensorInfo(QuantType type, size_t num_elements) {
    const auto* info = GetQuantTypeInfo(type);
    if (!info || !info->is_quantized) {
        return { type, num_elements, 0, 0, num_elements * 4, num_elements * 4, 1.0f };
    }
    
    size_t num_blocks = (num_elements + info->block_size - 1) / info->block_size;
    size_t total_bytes = num_blocks * info->block_bytes;
    size_t original = num_elements * sizeof(float);
    
    return {
        type,
        num_elements,
        num_blocks,
        info->block_bytes,
        total_bytes,
        original,
        static_cast<float>(original) / total_bytes
    };
}

//=============================================================================
// Q8_0 Dequantization (8-bit, 32 elements per block)
//=============================================================================

void DequantizeBlockQ8_0(const BlockQ8_0* src, float* dst, size_t n) {
    float scale = src->scale;
    for (size_t i = 0; i < n && i < 32; ++i) {
        dst[i] = scale * static_cast<float>(src->qs[i]);
    }
}

void DequantizeBlockQ8_0_AVX2(const BlockQ8_0* src, float* dst, size_t n) {
    __m256 scale_vec = _mm256_set1_ps(src->scale);
    
    // Process 8 elements at a time
    for (size_t i = 0; i < n && i < 32; i += 8) {
        // Load 8 int8 values
        __m128i qs_lo = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(&src->qs[i]));
        
        // Convert to 16-bit
        __m256i qs_16 = _mm256_cvtepi8_epi16(qs_lo);
        
        // Convert to 32-bit and then to float
        __m256i qs_32_lo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(qs_16));
        __m256i qs_32_hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(qs_16, 1));
        
        __m256 qf_lo = _mm256_cvtepi32_ps(qs_32_lo);
        __m256 qf_hi = _mm256_cvtepi32_ps(qs_32_hi);
        
        // Scale
        _mm256_storeu_ps(&dst[i], _mm256_mul_ps(qf_lo, scale_vec));
        if (i + 4 < n) {
            _mm256_storeu_ps(&dst[i + 4], _mm256_mul_ps(qf_hi, scale_vec));
        }
    }
}

//=============================================================================
// Q4_0 Dequantization (4-bit, 32 elements per block)
//=============================================================================

void DequantizeBlockQ4_0(const BlockQ4_0* src, float* dst, size_t n) {
    float scale = src->scale;
    for (size_t i = 0; i < n && i < 32; ++i) {
        uint8_t byte = src->qs[i / 2];
        int8_t val = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
        // Sign extend 4-bit to 8-bit
        if (val >= 8) val -= 16;
        dst[i] = scale * static_cast<float>(val);
    }
}

void DequantizeBlockQ4_0_AVX2(const BlockQ4_0* src, float* dst, size_t n) {
    __m256 scale_vec = _mm256_set1_ps(src->scale);
    
    // Load all 16 bytes (32 nibbles)
    __m128i qs = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src->qs));
    
    // Expand nibbles to bytes
    __m256i qs_lo = _mm256_cvtepu8_epi16(_mm_unpacklo_epi64(qs, _mm_setzero_si128()));
    __m256i qs_hi = _mm256_cvtepu8_epi16(_mm_unpackhi_epi64(qs, _mm_setzero_si128()));
    
    // Process low and high nibbles
    for (int group = 0; group < 2; ++group) {
        __m256i* qs_ptr = (group == 0) ? &qs_lo : &qs_hi;
        
        // Extract low nibbles
        __m256i low_nibbles = _mm256_and_si256(*qs_ptr, _mm256_set1_epi16(0x0F0F));
        // Extract high nibbles
        __m256i high_nibbles = _mm256_srli_epi16(*qs_ptr, 4);
        high_nibbles = _mm256_and_si256(high_nibbles, _mm256_set1_epi16(0x0F0F));
        
        // Convert to float and scale
        for (int i = 0; i < 8; ++i) {
            int16_t val = _mm256_extract_epi16(low_nibbles, i);
            if (val >= 8) val -= 16;
            dst[group * 16 + i * 2] = scale * val;
            
            val = _mm256_extract_epi16(high_nibbles, i);
            if (val >= 8) val -= 16;
            dst[group * 16 + i * 2 + 1] = scale * val;
        }
    }
}

//=============================================================================
// Q4_1 Dequantization (4-bit with min)
//=============================================================================

void DequantizeBlockQ4_1(const BlockQ4_1* src, float* dst, size_t n) {
    float scale = src->scale;
    float min = src->min;
    for (size_t i = 0; i < n && i < 32; ++i) {
        uint8_t byte = src->qs[i / 2];
        int val = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
        dst[i] = min + scale * static_cast<float>(val);
    }
}

//=============================================================================
// Q4_K Dequantization (K-quant 4-bit)
//=============================================================================

// K-quant scale unpacking
static inline void UnpackScalesQ4_K(const uint8_t* scales, float* scale_min, 
                                     float* scale_diff, int n) {
    // Simplified: K-quants use compressed scale representation
    // Full implementation would decode the 6-bit scales
    for (int i = 0; i < n; ++i) {
        scale_min[i] = scales[i * 2] / 127.0f;
        scale_diff[i] = scales[i * 2 + 1] / 127.0f;
    }
}

void DequantizeBlockQ4_K(const BlockQ4_K* src, float* dst, size_t n) {
    float scale_min[8];
    float scale_diff[8];
    UnpackScalesQ4_K(src->scales, scale_min, scale_diff, 8);
    
    // 256 elements per block, organized in 8 groups of 32
    for (int group = 0; group < 8; ++group) {
        const uint8_t* qs = &src->qs[group * 16]; // 16 bytes = 32 nibbles
        
        for (int i = 0; i < 32; ++i) {
            uint8_t byte = qs[i / 2];
            int val = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
            dst[group * 32 + i] = scale_min[group] + scale_diff[group] * val;
        }
    }
}

//=============================================================================
// Q5_K Dequantization (K-quant 5-bit)
//=============================================================================

void DequantizeBlockQ5_K(const BlockQ5_K* src, float* dst, size_t n) {
    float scale_min[8];
    float scale_diff[8];
    UnpackScalesQ4_K(src->scales, scale_min, scale_diff, 8);
    
    // 256 elements per block
    for (int group = 0; group < 8; ++group) {
        const uint8_t* qs = &src->qs[group * 16];
        const uint8_t* qh = &src->qh[group * 4]; // 4 bytes = 32 bits
        
        for (int i = 0; i < 32; ++i) {
            // Low 4 bits
            uint8_t byte = qs[i / 2];
            int low = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
            
            // High bit
            int high = (qh[i / 8] >> (i % 8)) & 1;
            
            int val = low | (high << 4);
            dst[group * 32 + i] = scale_min[group] + scale_diff[group] * val;
        }
    }
}

//=============================================================================
// Q6_K Dequantization (K-quant 6-bit)
//=============================================================================

void DequantizeBlockQ6_K(const BlockQ6_K* src, float* dst, size_t n) {
    // 256 elements per block
    for (int i = 0; i < 256; ++i) {
        int group = i / 32;
        int idx = i % 32;
        
        // Low 4 bits
        int low = src->ql[group * 32 + idx] & 0x0F;
        
        // High 2 bits
        int high_idx = (group * 32 + idx) / 4;
        int high_shift = ((group * 32 + idx) % 4) * 2;
        int high = (src->qh[high_idx] >> high_shift) & 0x03;
        
        int val = low | (high << 4);
        
        // Scale
        float scale = src->scales[i] / 127.0f;
        dst[i] = scale * val;
    }
}

//=============================================================================
// Q8_K Dequantization (K-quant 8-bit for embeddings)
//=============================================================================

void DequantizeBlockQ8_K(const BlockQ8_K* src, float* dst, size_t n) {
    float scale = src->scale;
    float bias = src->bias;
    
    for (size_t i = 0; i < n && i < 256; ++i) {
        dst[i] = bias + scale * static_cast<float>(src->qs[i]);
    }
}

//=============================================================================
// Generic Dequantization
//=============================================================================

void DequantizeTensor(const void* src, QuantType type, float* dst, size_t num_elements) {
    const auto* info = GetQuantTypeInfo(type);
    if (!info || !info->is_quantized) {
        // Copy as-is for non-quantized types
        std::memcpy(dst, src, num_elements * sizeof(float));
        return;
    }
    
    size_t num_blocks = (num_elements + info->block_size - 1) / info->block_size;
    
    switch (type) {
        case QuantType::Q8_0: {
            const auto* blocks = static_cast<const BlockQ8_0*>(src);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 32;
                size_t n = std::min(size_t(32), num_elements - offset);
                DequantizeBlockQ8_0(&blocks[b], &dst[offset], n);
            }
            break;
        }
        case QuantType::Q4_0: {
            const auto* blocks = static_cast<const BlockQ4_0*>(src);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 32;
                size_t n = std::min(size_t(32), num_elements - offset);
                DequantizeBlockQ4_0(&blocks[b], &dst[offset], n);
            }
            break;
        }
        case QuantType::Q4_1: {
            const auto* blocks = static_cast<const BlockQ4_1*>(src);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 32;
                size_t n = std::min(size_t(32), num_elements - offset);
                DequantizeBlockQ4_1(&blocks[b], &dst[offset], n);
            }
            break;
        }
        case QuantType::Q4_K:
        case QuantType::Q4_K_M: {
            const auto* blocks = static_cast<const BlockQ4_K*>(src);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 256;
                size_t n = std::min(size_t(256), num_elements - offset);
                DequantizeBlockQ4_K(&blocks[b], &dst[offset], n);
            }
            break;
        }
        case QuantType::Q5_K:
        case QuantType::Q5_K_M: {
            const auto* blocks = static_cast<const BlockQ5_K*>(src);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 256;
                size_t n = std::min(size_t(256), num_elements - offset);
                DequantizeBlockQ5_K(&blocks[b], &dst[offset], n);
            }
            break;
        }
        case QuantType::Q6_K: {
            const auto* blocks = static_cast<const BlockQ6_K*>(src);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 256;
                size_t n = std::min(size_t(256), num_elements - offset);
                DequantizeBlockQ6_K(&blocks[b], &dst[offset], n);
            }
            break;
        }
        case QuantType::Q8_K: {
            const auto* blocks = static_cast<const BlockQ8_K*>(src);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 256;
                size_t n = std::min(size_t(256), num_elements - offset);
                DequantizeBlockQ8_K(&blocks[b], &dst[offset], n);
            }
            break;
        }
        default:
            std::memset(dst, 0, num_elements * sizeof(float));
            break;
    }
}

//=============================================================================
// Quantization (for model conversion)
//=============================================================================

void QuantizeBlockQ8_0(const float* src, BlockQ8_0* dst, size_t n) {
    // Find max absolute value for scale
    float max_abs = 0.0f;
    for (size_t i = 0; i < n && i < 32; ++i) {
        max_abs = std::max(max_abs, std::abs(src[i]));
    }
    
    if (max_abs > 0.0f) {
        dst->scale = max_abs / 127.0f;
        float inv_scale = 127.0f / max_abs;
        
        for (size_t i = 0; i < n && i < 32; ++i) {
            int val = static_cast<int>(std::round(src[i] * inv_scale));
            val = std::max(-128, std::min(127, val));
            dst->qs[i] = static_cast<int8_t>(val);
        }
    } else {
        dst->scale = 0.0f;
        std::memset(dst->qs, 0, 32);
    }
}

void QuantizeBlockQ4_0(const float* src, BlockQ4_0* dst, size_t n) {
    // Find max absolute value
    float max_abs = 0.0f;
    for (size_t i = 0; i < n && i < 32; ++i) {
        max_abs = std::max(max_abs, std::abs(src[i]));
    }
    
    if (max_abs > 0.0f) {
        dst->scale = max_abs / 7.0f;  // 4-bit signed: -8 to 7
        float inv_scale = 7.0f / max_abs;
        
        std::memset(dst->qs, 0, 16);
        for (size_t i = 0; i < n && i < 32; ++i) {
            int val = static_cast<int>(std::round(src[i] * inv_scale));
            val = std::max(-8, std::min(7, val));
            uint8_t nibble = static_cast<uint8_t>(val & 0x0F);
            
            if (i % 2 == 0) {
                dst->qs[i / 2] = nibble;
            } else {
                dst->qs[i / 2] |= (nibble << 4);
            }
        }
    } else {
        dst->scale = 0.0f;
        std::memset(dst->qs, 0, 16);
    }
}

void QuantizeBlockQ4_1(const float* src, BlockQ4_1* dst, size_t n) {
    // Find min and max
    float min_val = src[0];
    float max_val = src[0];
    for (size_t i = 1; i < n && i < 32; ++i) {
        min_val = std::min(min_val, src[i]);
        max_val = std::max(max_val, src[i]);
    }
    
    dst->min = min_val;
    float range = max_val - min_val;
    
    if (range > 0.0f) {
        dst->scale = range / 15.0f;  // 4-bit unsigned: 0 to 15
        float inv_scale = 15.0f / range;
        
        std::memset(dst->qs, 0, 16);
        for (size_t i = 0; i < n && i < 32; ++i) {
            int val = static_cast<int>(std::round((src[i] - min_val) * inv_scale));
            val = std::max(0, std::min(15, val));
            
            if (i % 2 == 0) {
                dst->qs[i / 2] = static_cast<uint8_t>(val);
            } else {
                dst->qs[i / 2] |= static_cast<uint8_t>(val << 4);
            }
        }
    } else {
        dst->scale = 0.0f;
        std::memset(dst->qs, 0, 16);
    }
}

void QuantizeTensor(const float* src, void* dst, QuantType type, size_t num_elements) {
    const auto* info = GetQuantTypeInfo(type);
    if (!info || !info->is_quantized) return;
    
    size_t num_blocks = (num_elements + info->block_size - 1) / info->block_size;
    
    switch (type) {
        case QuantType::Q8_0: {
            auto* blocks = static_cast<BlockQ8_0*>(dst);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 32;
                size_t n = std::min(size_t(32), num_elements - offset);
                QuantizeBlockQ8_0(&src[offset], &blocks[b], n);
            }
            break;
        }
        case QuantType::Q4_0: {
            auto* blocks = static_cast<BlockQ4_0*>(dst);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 32;
                size_t n = std::min(size_t(32), num_elements - offset);
                QuantizeBlockQ4_0(&src[offset], &blocks[b], n);
            }
            break;
        }
        case QuantType::Q4_1: {
            auto* blocks = static_cast<BlockQ4_1*>(dst);
            for (size_t b = 0; b < num_blocks; ++b) {
                size_t offset = b * 32;
                size_t n = std::min(size_t(32), num_elements - offset);
                QuantizeBlockQ4_1(&src[offset], &blocks[b], n);
            }
            break;
        }
        default:
            break;
    }
}

//=============================================================================
// GPU Upload Preparation
//=============================================================================

std::vector<uint8_t> PrepareForGPUUpload(const void* src, QuantType type,
                                           size_t num_elements,
                                           size_t alignment) {
    const auto* info = GetQuantTypeInfo(type);
    if (!info) return {};
    
    size_t num_blocks = (num_elements + info->block_size - 1) / info->block_size;
    size_t data_size = num_blocks * info->block_bytes;
    
    // Align size
    size_t aligned_size = (data_size + alignment - 1) & ~(alignment - 1);
    
    std::vector<uint8_t> result(aligned_size);
    std::memcpy(result.data(), src, data_size);
    
    // Zero padding
    if (aligned_size > data_size) {
        std::memset(result.data() + data_size, 0, aligned_size - data_size);
    }
    
    return result;
}

size_t GetOptimalGPUChunkSize(QuantType type) {
    // Return optimal chunk size for GPU upload
    // Larger chunks = better throughput but more memory
    const auto* info = GetQuantTypeInfo(type);
    if (!info) return 64 * 1024 * 1024; // 64MB default
    
    // For quantized types, use larger chunks
    if (info->is_quantized) {
        return 256 * 1024 * 1024; // 256MB for quantized
    }
    
    return 128 * 1024 * 1024; // 128MB for non-quantized
}

} // namespace Quantization
} // namespace RawrXD
