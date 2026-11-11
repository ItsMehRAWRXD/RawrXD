//=============================================================================
// Fix 5B Phase 2: Quantization Kernels Implementation
// RawrXD IDE - High-Performance Inference
//=============================================================================
//
// IMPLEMENTATION NOTES:
// =====================
// - Uses AVX2 when available for SIMD acceleration
// - Falls back to scalar implementations
// - Optimized for KV cache data patterns (attention heads)
// - Block-wise quantization for better numerical stability
//
// PERFORMANCE TARGETS:
// ======================
// - Q8_0: ~50 GB/s compression, ~100 GB/s decompression
// - Q4_0: ~25 GB/s compression, ~50 GB/s decompression
// - Q4_K: ~20 GB/s compression, ~40 GB/s decompression
// - Q2_K: ~15 GB/s compression, ~30 GB/s decompression
//=============================================================================

#include "RawrXD_KVCache_QuantKernels.hpp"
#include "RawrXD_KVCache_Residency_v2.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>

// SIMD intrinsics
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <immintrin.h>
#include <cpuid.h>
#endif

namespace RawrXD {
namespace Memory {

//=============================================================================
// Runtime CPU Feature Detection
//=============================================================================

struct CPUFeatures {
    bool has_avx2;
    bool has_avx;
    bool has_sse4_2;
    bool initialized;
    
    CPUFeatures() : initialized(false) {
        Detect();
    }
    
    void Detect() {
        if (initialized) return;
        
#if defined(__x86_64__) || defined(_M_X64)
        int cpuInfo[4] = {0};
        
#if defined(_MSC_VER)
        __cpuid(cpuInfo, 1);
        bool osUsesXSAVE_XRSTORE = (cpuInfo[2] & (1 << 27)) != 0;
        bool cpuAVXSupport = (cpuInfo[2] & (1 << 28)) != 0;
        
        if (osUsesXSAVE_XRSTORE && cpuAVXSupport) {
            unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
            if ((xcrFeatureMask & 0x6) == 0x6) {
                __cpuid(cpuInfo, 7);
                has_avx2 = (cpuInfo[1] & (1 << 5)) != 0;
                has_avx = true;
            }
        }
#else
        __cpuid(1, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
        bool osUsesXSAVE_XRSTORE = (cpuInfo[2] & (1 << 27)) != 0;
        bool cpuAVXSupport = (cpuInfo[2] & (1 << 28)) != 0;
        
        has_avx = osUsesXSAVE_XRSTORE && cpuAVXSupport;
        has_avx2 = false;
        
        if (has_avx) {
            __cpuid(7, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
            has_avx2 = (cpuInfo[1] & (1 << 5)) != 0;
        }
        
        has_sse4_2 = (cpuInfo[2] & (1 << 20)) != 0;
#endif
#else
        has_avx2 = false;
        has_avx = false;
        has_sse4_2 = false;
#endif
        initialized = true;
    }
};

static CPUFeatures g_cpu_features;

//=============================================================================
// AVX2 Optimized Implementations
//=============================================================================

#if defined(__x86_64__) || defined(_M_X64)

// Fast FP16 to float conversion using AVX2
static inline __m256 FP16ToFloatAVX2(__m128i h) {
    // Expand FP16 to FP32
    __m256i expanded = _mm256_cvtepu16_epi32(h);
    
    // Extract sign, exponent, mantissa
    __m256i sign = _mm256_srli_epi32(expanded, 15);
    __m256i exp = _mm256_srli_epi32(expanded, 10);
    exp = _mm256_and_si256(exp, _mm256_set1_epi32(0x1F));
    __m256i mant = _mm256_and_si256(expanded, _mm256_set1_epi32(0x3FF));
    
    // Build FP32
    __m256i exp32 = _mm256_sub_epi32(exp, _mm256_set1_epi32(15));
    exp32 = _mm256_add_epi32(exp32, _mm256_set1_epi32(127));
    exp32 = _mm256_slli_epi32(exp32, 23);
    
    __m256i mant32 = _mm256_slli_epi32(mant, 13);
    __m256i sign32 = _mm256_slli_epi32(sign, 31);
    
    __m256i result = _mm256_or_si256(exp32, mant32);
    result = _mm256_or_si256(result, sign32);
    
    return _mm256_castsi256_ps(result);
}

// Fast float to FP16 conversion (simplified)
static inline uint16_t FloatToFP16Fast(float f) {
    uint32_t u;
    std::memcpy(&u, &f, sizeof(f));
    
    uint32_t sign = (u >> 31) & 0x1;
    int32_t exp = ((u >> 23) & 0xFF) - 127 + 15;
    uint32_t mant = (u >> 13) & 0x3FF;
    
    if (exp <= 0) {
        return sign << 15;
    } else if (exp >= 31) {
        return (sign << 15) | 0x7C00;
    }
    
    return (sign << 15) | (exp << 10) | mant;
}

// AVX2 optimized Q8_0 quantization
static void QuantizeFP16ToQ8_0_AVX2_Impl(const uint16_t* src, BlockQ8_0* dst, size_t count) {
    size_t num_blocks = count / 32;
    
    for (size_t b = 0; b < num_blocks; b++) {
        // Load 32 FP16 values
        __m256i vals[2];
        vals[0] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + b * 32));
        vals[1] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + b * 32 + 16));
        
        // Convert to float
        __m256 fvals[4];
        fvals[0] = FP16ToFloatAVX2(_mm256_castsi256_si128(vals[0]));
        fvals[1] = FP16ToFloatAVX2(_mm256_extracti128_si256(vals[0], 1));
        fvals[2] = FP16ToFloatAVX2(_mm256_castsi256_si128(vals[1]));
        fvals[3] = FP16ToFloatAVX2(_mm256_extracti128_si256(vals[1], 1));
        
        // Find min/max using horizontal operations
        __m256 min_val = fvals[0];
        __m256 max_val = fvals[0];
        for (int i = 1; i < 4; i++) {
            min_val = _mm256_min_ps(min_val, fvals[i]);
            max_val = _mm256_max_ps(max_val, fvals[i]);
        }
        
        // Horizontal min/max
        __m256 min_shuf = _mm256_shuffle_ps(min_val, min_val, _MM_SHUFFLE(2, 3, 0, 1));
        min_val = _mm256_min_ps(min_val, min_shuf);
        min_shuf = _mm256_shuffle_ps(min_val, min_val, _MM_SHUFFLE(1, 0, 3, 2));
        min_val = _mm256_min_ps(min_val, min_shuf);
        
        __m256 max_shuf = _mm256_shuffle_ps(max_val, max_val, _MM_SHUFFLE(2, 3, 0, 1));
        max_val = _mm256_max_ps(max_val, max_shuf);
        max_shuf = _mm256_shuffle_ps(max_val, max_val, _MM_SHUFFLE(1, 0, 3, 2));
        max_val = _mm256_max_ps(max_val, max_shuf);
        
        float min_f = _mm256_cvtss_f32(min_val);
        float max_f = _mm256_cvtss_f32(max_val);
        
        // Calculate scale
        float scale = (max_f - min_f) / 255.0f;
        if (scale == 0.0f) scale = 1.0f;
        dst[b].scale = scale;
        
        // Quantize values
        __m256 scale_vec = _mm256_set1_ps(255.0f / (max_f - min_f));
        __m256 min_vec = _mm256_set1_ps(min_f);
        
        for (int i = 0; i < 4; i++) {
            __m256 normalized = _mm256_mul_ps(_mm256_sub_ps(fvals[i], min_vec), scale_vec);
            __m256i quantized = _mm256_cvtps_epi32(normalized);
            
            // Pack to int8
            __m128i packed = _mm256_castsi256_si128(quantized);
            packed = _mm_packs_epi32(packed, _mm256_extracti128_si256(quantized, 1));
            packed = _mm_packs_epi16(packed, packed);
            
            _mm_storel_epi64(reinterpret_cast<__m128i*>(dst[b].values + i * 8), packed);
        }
    }
}

// AVX2 optimized Q8_0 dequantization
static void DequantizeQ8_0ToFP16_AVX2_Impl(const BlockQ8_0* src, uint16_t* dst, size_t count) {
    size_t num_blocks = count / 32;
    
    for (size_t b = 0; b < num_blocks; b++) {
        float scale = src[b].scale;
        __m256 scale_vec = _mm256_set1_ps(scale);
        __m256 offset_vec = _mm256_set1_ps(127.5f * scale);
        
        for (int i = 0; i < 4; i++) {
            // Load 8 int8 values and expand to int32
            __m128i vals = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(src[b].values + i * 8));
            __m256i vals256 = _mm256_cvtepi8_epi32(vals);
            
            __m256 fvals = _mm256_cvtepi32_ps(vals256);
            fvals = _mm256_fmadd_ps(fvals, scale_vec, offset_vec);
            
            // Convert to FP16
            for (int j = 0; j < 8; j++) {
                float val = ((float*)&fvals)[j];
                dst[b * 32 + i * 8 + j] = FloatToFP16Fast(val);
            }
        }
    }
}

#endif // x86_64

//=============================================================================
// FP16 Helper Functions (in anonymous namespace)
//=============================================================================

namespace {

// Convert FP16 (uint16_t) to float
inline float FP16ToFloat(uint16_t h) {
    // Simple FP16 to float conversion
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        // Zero or denormal
        if (mant == 0) return sign ? -0.0f : 0.0f;
        // Denormal
        float val = mant / 1024.0f * std::pow(2.0f, -14.0f);
        return sign ? -val : val;
    } else if (exp == 31) {
        // Infinity or NaN
        return mant ? std::nanf("") : (sign ? -std::numeric_limits<float>::infinity() 
                                              : std::numeric_limits<float>::infinity());
    }
    
    // Normal number
    float val = (1.0f + mant / 1024.0f) * std::pow(2.0f, static_cast<float>(exp - 15));
    return sign ? -val : val;
}

// Convert float to FP16 (uint16_t)
static inline uint16_t FloatToFP16(float f) {
    // Simple float to FP16 conversion
    if (std::isnan(f)) return 0x7E00;
    if (std::isinf(f)) return f < 0 ? 0xFC00 : 0x7C00;
    if (f == 0.0f) return 0;
    
    uint32_t sign = f < 0 ? 1 : 0;
    float abs_f = std::abs(f);
    
    // Find exponent
    int exp;
    float mant = std::frexp(abs_f, &exp);
    exp += 14;  // Bias
    
    if (exp <= 0) {
        // Denormal or underflow
        if (exp < -10) return sign << 15;
        mant = std::ldexp(mant, exp - 1);
        uint32_t mant_bits = static_cast<uint32_t>(mant * 1024.0f + 0.5f);
        return (sign << 15) | mant_bits;
    } else if (exp >= 31) {
        // Overflow to infinity
        return (sign << 15) | 0x7C00;
    }
    
    uint32_t mant_bits = static_cast<uint32_t>((mant - 0.5f) * 2048.0f + 0.5f);
    return (sign << 15) | (exp << 10) | (mant_bits & 0x3FF);
}

} // anonymous namespace

//=============================================================================
// Q8_0 Quantization (2x compression)
//=============================================================================

size_t KVQuantizationKernels::QuantizeFP16ToQ8_0(const void* src, BlockQ8_0* dst, size_t count) {
    if (count % 32 != 0) return 0;  // Must be multiple of block size
    
    const uint16_t* src_fp16 = static_cast<const uint16_t*>(src);
    
#if defined(__x86_64__) || defined(_M_X64)
    // Use AVX2 optimized version if available
    if (g_cpu_features.has_avx2) {
        QuantizeFP16ToQ8_0_AVX2_Impl(src_fp16, dst, count);
        return (count / 32) * sizeof(BlockQ8_0);
    }
#endif
    
    // Scalar fallback
    size_t num_blocks = count / 32;
    
    for (size_t b = 0; b < num_blocks; b++) {
        // Find min/max for this block
        float min_val = std::numeric_limits<float>::max();
        float max_val = std::numeric_limits<float>::lowest();
        
        for (size_t i = 0; i < 32; i++) {
            float val = FP16ToFloat(src_fp16[b * 32 + i]);
            min_val = std::min(min_val, val);
            max_val = std::max(max_val, val);
        }
        
        // Calculate scale
        float scale = (max_val - min_val) / 255.0f;
        if (scale == 0.0f) scale = 1.0f;  // Avoid division by zero
        
        dst[b].scale = scale;
        
        // Quantize values
        for (size_t i = 0; i < 32; i++) {
            float val = FP16ToFloat(src_fp16[b * 32 + i]);
            int32_t q = static_cast<int32_t>(std::round((val - min_val) / scale - 127.5f));
            q = std::max(-128, std::min(127, q));
            dst[b].values[i] = static_cast<int8_t>(q);
        }
    }
    
    return num_blocks * sizeof(BlockQ8_0);
}

void KVQuantizationKernels::DequantizeQ8_0ToFP16(const BlockQ8_0* src, void* dst, size_t count) {
    if (count % 32 != 0) return;
    
    uint16_t* dst_fp16 = static_cast<uint16_t*>(dst);
    
#if defined(__x86_64__) || defined(_M_X64)
    // Use AVX2 optimized version if available
    if (g_cpu_features.has_avx2) {
        DequantizeQ8_0ToFP16_AVX2_Impl(src, dst_fp16, count);
        return;
    }
#endif
    
    // Scalar fallback
    size_t num_blocks = count / 32;
    
    for (size_t b = 0; b < num_blocks; b++) {
        float scale = src[b].scale;
        
        for (size_t i = 0; i < 32; i++) {
            float val = (static_cast<float>(src[b].values[i]) + 127.5f) * scale;
            dst_fp16[b * 32 + i] = FloatToFP16(val);
        }
    }
}

//=============================================================================
// Q4_0 Quantization (4x compression)
//=============================================================================

size_t KVQuantizationKernels::QuantizeFP16ToQ4_0(const void* src, BlockQ4_0* dst, size_t count) {
    if (count % 32 != 0) return 0;
    
    const uint16_t* src_fp16 = static_cast<const uint16_t*>(src);
    size_t num_blocks = count / 32;
    
    for (size_t b = 0; b < num_blocks; b++) {
        // Find min/max for this block
        float min_val = std::numeric_limits<float>::max();
        float max_val = std::numeric_limits<float>::lowest();
        
        for (size_t i = 0; i < 32; i++) {
            float val = FP16ToFloat(src_fp16[b * 32 + i]);
            min_val = std::min(min_val, val);
            max_val = std::max(max_val, val);
        }
        
        // Calculate scale
        float scale = (max_val - min_val) / 15.0f;
        if (scale == 0.0f) scale = 1.0f;
        
        dst[b].scale = scale;
        
        // Quantize values (pack 2 uint4 values per byte)
        for (size_t i = 0; i < 16; i++) {
            float val0 = FP16ToFloat(src_fp16[b * 32 + i * 2]);
            float val1 = FP16ToFloat(src_fp16[b * 32 + i * 2 + 1]);
            
            int32_t q0 = static_cast<int32_t>(std::round((val0 - min_val) / scale));
            int32_t q1 = static_cast<int32_t>(std::round((val1 - min_val) / scale));
            
            q0 = std::max(0, std::min(15, q0));
            q1 = std::max(0, std::min(15, q1));
            
            dst[b].values[i] = static_cast<uint8_t>((q1 << 4) | q0);
        }
    }
    
    return num_blocks * sizeof(BlockQ4_0);
}

void KVQuantizationKernels::DequantizeQ4_0ToFP16(const BlockQ4_0* src, void* dst, size_t count) {
    if (count % 32 != 0) return;
    
    uint16_t* dst_fp16 = static_cast<uint16_t*>(dst);
    size_t num_blocks = count / 32;
    
    for (size_t b = 0; b < num_blocks; b++) {
        float scale = src[b].scale;
        
        for (size_t i = 0; i < 16; i++) {
            uint8_t packed = src[b].values[i];
            int32_t q0 = packed & 0x0F;
            int32_t q1 = (packed >> 4) & 0x0F;
            
            float val0 = q0 * scale;
            float val1 = q1 * scale;
            
            dst_fp16[b * 32 + i * 2] = FloatToFP16(val0);
            dst_fp16[b * 32 + i * 2 + 1] = FloatToFP16(val1);
        }
    }
}

//=============================================================================
// Q4_K Quantization (4x compression, block-wise scaling)
//=============================================================================

size_t KVQuantizationKernels::QuantizeFP16ToQ4_K(const void* src, BlockQ4_K* dst, size_t count) {
    if (count % 256 != 0) return 0;  // Q4_K uses 256-element superblocks
    
    const uint16_t* src_fp16 = static_cast<const uint16_t*>(src);
    size_t num_blocks = count / 256;
    
    for (size_t b = 0; b < num_blocks; b++) {
        // Process 8 sub-blocks of 32 values each
        for (int sub = 0; sub < 8; sub++) {
            float min_val = std::numeric_limits<float>::max();
            float max_val = std::numeric_limits<float>::lowest();
            
            for (size_t i = 0; i < 32; i++) {
                float val = FP16ToFloat(src_fp16[b * 256 + sub * 32 + i]);
                min_val = std::min(min_val, val);
                max_val = std::max(max_val, val);
            }
            
            // Quantize scale and min
            float scale = (max_val - min_val) / 15.0f;
            if (scale == 0.0f) scale = 1.0f;
            
            // Store quantized scale and min (8-bit each)
            dst[b].scales[sub] = static_cast<uint8_t>(std::min(255.0f, scale * 100.0f));
            dst[b].mins[sub] = static_cast<uint8_t>(std::min(255.0f, min_val * 100.0f));
            
            // Quantize values
            for (size_t i = 0; i < 16; i++) {
                float val0 = FP16ToFloat(src_fp16[b * 256 + sub * 32 + i * 2]);
                float val1 = FP16ToFloat(src_fp16[b * 256 + sub * 32 + i * 2 + 1]);
                
                int32_t q0 = static_cast<int32_t>(std::round((val0 - min_val) / scale));
                int32_t q1 = static_cast<int32_t>(std::round((val1 - min_val) / scale));
                
                q0 = std::max(0, std::min(15, q0));
                q1 = std::max(0, std::min(15, q1));
                
                dst[b].values[sub * 16 + i] = static_cast<uint8_t>((q1 << 4) | q0);
            }
        }
    }
    
    return num_blocks * sizeof(BlockQ4_K);
}

void KVQuantizationKernels::DequantizeQ4_KToFP16(const BlockQ4_K* src, void* dst, size_t count) {
    if (count % 256 != 0) return;
    
    uint16_t* dst_fp16 = static_cast<uint16_t*>(dst);
    size_t num_blocks = count / 256;
    
    for (size_t b = 0; b < num_blocks; b++) {
        for (int sub = 0; sub < 8; sub++) {
            float scale = src[b].scales[sub] / 100.0f;
            float min_val = src[b].mins[sub] / 100.0f;
            
            for (size_t i = 0; i < 16; i++) {
                uint8_t packed = src[b].values[sub * 16 + i];
                int32_t q0 = packed & 0x0F;
                int32_t q1 = (packed >> 4) & 0x0F;
                
                float val0 = min_val + q0 * scale;
                float val1 = min_val + q1 * scale;
                
                dst_fp16[b * 256 + sub * 32 + i * 2] = FloatToFP16(val0);
                dst_fp16[b * 256 + sub * 32 + i * 2 + 1] = FloatToFP16(val1);
            }
        }
    }
}

//=============================================================================
// Q2_K Quantization (8x compression, emergency only)
//=============================================================================

size_t KVQuantizationKernels::QuantizeFP16ToQ2_K(const void* src, BlockQ2_K* dst, size_t count) {
    if (count % 256 != 0) return 0;
    
    const uint16_t* src_fp16 = static_cast<const uint16_t*>(src);
    size_t num_blocks = count / 256;
    
    for (size_t b = 0; b < num_blocks; b++) {
        // Process 16 sub-blocks of 16 values each
        for (int sub = 0; sub < 16; sub++) {
            float min_val = std::numeric_limits<float>::max();
            float max_val = std::numeric_limits<float>::lowest();
            
            for (size_t i = 0; i < 16; i++) {
                float val = FP16ToFloat(src_fp16[b * 256 + sub * 16 + i]);
                min_val = std::min(min_val, val);
                max_val = std::max(max_val, val);
            }
            
            float scale = (max_val - min_val) / 3.0f;
            if (scale == 0.0f) scale = 1.0f;
            
            dst[b].scales[sub] = static_cast<uint8_t>(std::min(255.0f, scale * 100.0f));
            
            // Pack 4 uint2 values per byte
            for (size_t i = 0; i < 4; i++) {
                float val0 = FP16ToFloat(src_fp16[b * 256 + sub * 16 + i * 4]);
                float val1 = FP16ToFloat(src_fp16[b * 256 + sub * 16 + i * 4 + 1]);
                float val2 = FP16ToFloat(src_fp16[b * 256 + sub * 16 + i * 4 + 2]);
                float val3 = FP16ToFloat(src_fp16[b * 256 + sub * 16 + i * 4 + 3]);
                
                int32_t q0 = static_cast<int32_t>(std::round((val0 - min_val) / scale));
                int32_t q1 = static_cast<int32_t>(std::round((val1 - min_val) / scale));
                int32_t q2 = static_cast<int32_t>(std::round((val2 - min_val) / scale));
                int32_t q3 = static_cast<int32_t>(std::round((val3 - min_val) / scale));
                
                q0 = std::max(0, std::min(3, q0));
                q1 = std::max(0, std::min(3, q1));
                q2 = std::max(0, std::min(3, q2));
                q3 = std::max(0, std::min(3, q3));
                
                dst[b].values[sub * 4 + i] = static_cast<uint8_t>((q3 << 6) | (q2 << 4) | (q1 << 2) | q0);
            }
        }
    }
    
    return num_blocks * sizeof(BlockQ2_K);
}

void KVQuantizationKernels::DequantizeQ2_KToFP16(const BlockQ2_K* src, void* dst, size_t count) {
    if (count % 256 != 0) return;
    
    uint16_t* dst_fp16 = static_cast<uint16_t*>(dst);
    size_t num_blocks = count / 256;
    
    for (size_t b = 0; b < num_blocks; b++) {
        for (int sub = 0; sub < 16; sub++) {
            float scale = src[b].scales[sub] / 100.0f;
            
            for (size_t i = 0; i < 4; i++) {
                uint8_t packed = src[b].values[sub * 4 + i];
                int32_t q0 = packed & 0x03;
                int32_t q1 = (packed >> 2) & 0x03;
                int32_t q2 = (packed >> 4) & 0x03;
                int32_t q3 = (packed >> 6) & 0x03;
                
                dst_fp16[b * 256 + sub * 16 + i * 4] = FloatToFP16(q0 * scale);
                dst_fp16[b * 256 + sub * 16 + i * 4 + 1] = FloatToFP16(q1 * scale);
                dst_fp16[b * 256 + sub * 16 + i * 4 + 2] = FloatToFP16(q2 * scale);
                dst_fp16[b * 256 + sub * 16 + i * 4 + 3] = FloatToFP16(q3 * scale);
            }
        }
    }
}

//=============================================================================
// Utility Functions
//=============================================================================

size_t KVQuantizationKernels::GetQuantizedBufferSize(size_t element_count, int bits_per_element) {
    switch (bits_per_element) {
        case 8:  // Q8_0
            return (element_count / 32) * sizeof(BlockQ8_0);
        case 4:  // Q4_0 or Q4_K
            return (element_count / 32) * sizeof(BlockQ4_0);  // Conservative estimate
        case 2:  // Q2_K
            return (element_count / 256) * sizeof(BlockQ2_K);
        default:
            return 0;
    }
}

size_t KVQuantizationKernels::GetBlockSize(int bits_per_element) {
    switch (bits_per_element) {
        case 8: return 32;
        case 4: return 32;
        case 2: return 256;
        default: return 0;
    }
}

bool KVQuantizationKernels::ValidateAlignment(const void* ptr, size_t alignment) {
    return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

//=============================================================================
// High-Level Compression Interface
//=============================================================================

size_t CompressPageData(const void* src, size_t src_size, 
                        void* dst, size_t dst_capacity,
                        NEVM::ISA::PrecisionMode target_precision) {
    size_t element_count = src_size / sizeof(uint16_t);  // FP16 elements
    
    switch (target_precision) {
        case NEVM::ISA::PrecisionMode::Q8_0:
            if (dst_capacity < KVQuantizationKernels::GetQuantizedBufferSize(element_count, 8))
                return 0;
            return KVQuantizationKernels::QuantizeFP16ToQ8_0(src, static_cast<BlockQ8_0*>(dst), element_count);
            
        case NEVM::ISA::PrecisionMode::Q4_0:
            if (dst_capacity < KVQuantizationKernels::GetQuantizedBufferSize(element_count, 4))
                return 0;
            return KVQuantizationKernels::QuantizeFP16ToQ4_0(src, static_cast<BlockQ4_0*>(dst), element_count);
            
        case NEVM::ISA::PrecisionMode::Q4_K:
            if (dst_capacity < (element_count / 256) * sizeof(BlockQ4_K))
                return 0;
            return KVQuantizationKernels::QuantizeFP16ToQ4_K(src, static_cast<BlockQ4_K*>(dst), element_count);
            
        case NEVM::ISA::PrecisionMode::Q2_K:
            if (dst_capacity < KVQuantizationKernels::GetQuantizedBufferSize(element_count, 2))
                return 0;
            return KVQuantizationKernels::QuantizeFP16ToQ2_K(src, static_cast<BlockQ2_K*>(dst), element_count);
            
        default:
            return 0;
    }
}

size_t DecompressPageData(const void* src, size_t src_size,
                            void* dst, size_t dst_capacity,
                            NEVM::ISA::PrecisionMode stored_precision) {
    // Calculate element count from source size
    size_t element_count = 0;
    
    switch (stored_precision) {
        case NEVM::ISA::PrecisionMode::Q8_0:
            element_count = (src_size / sizeof(BlockQ8_0)) * 32;
            if (dst_capacity < element_count * sizeof(uint16_t)) return 0;
            KVQuantizationKernels::DequantizeQ8_0ToFP16(static_cast<const BlockQ8_0*>(src), dst, element_count);
            return element_count * sizeof(uint16_t);
            
        case NEVM::ISA::PrecisionMode::Q4_0:
            element_count = (src_size / sizeof(BlockQ4_0)) * 32;
            if (dst_capacity < element_count * sizeof(uint16_t)) return 0;
            KVQuantizationKernels::DequantizeQ4_0ToFP16(static_cast<const BlockQ4_0*>(src), dst, element_count);
            return element_count * sizeof(uint16_t);
            
        case NEVM::ISA::PrecisionMode::Q4_K:
            element_count = (src_size / sizeof(BlockQ4_K)) * 256;
            if (dst_capacity < element_count * sizeof(uint16_t)) return 0;
            KVQuantizationKernels::DequantizeQ4_KToFP16(static_cast<const BlockQ4_K*>(src), dst, element_count);
            return element_count * sizeof(uint16_t);
            
        case NEVM::ISA::PrecisionMode::Q2_K:
            element_count = (src_size / sizeof(BlockQ2_K)) * 256;
            if (dst_capacity < element_count * sizeof(uint16_t)) return 0;
            KVQuantizationKernels::DequantizeQ2_KToFP16(static_cast<const BlockQ2_K*>(src), dst, element_count);
            return element_count * sizeof(uint16_t);
            
        default:
            return 0;
    }
}

float GetCompressionRatio(NEVM::ISA::PrecisionMode precision) {
    switch (precision) {
        case NEVM::ISA::PrecisionMode::FP16: return 1.0f;
        case NEVM::ISA::PrecisionMode::Q8_0: return 2.0f;
        case NEVM::ISA::PrecisionMode::Q4_0: return 4.0f;
        case NEVM::ISA::PrecisionMode::Q4_K: return 4.0f;
        case NEVM::ISA::PrecisionMode::Q2_K: return 8.0f;
        default: return 1.0f;
    }
}

uint64_t EstimateDecompressionLatency(size_t element_count, 
                                       NEVM::ISA::PrecisionMode precision) {
    // Rough estimates based on expected throughput
    // These would be calibrated with actual benchmarks
    uint64_t base_latency = 10;  // Base overhead in microseconds
    
    float throughput_gb_s = 0.0f;
    switch (precision) {
        case NEVM::ISA::PrecisionMode::Q8_0: throughput_gb_s = 100.0f; break;
        case NEVM::ISA::PrecisionMode::Q4_0: throughput_gb_s = 50.0f; break;
        case NEVM::ISA::PrecisionMode::Q4_K: throughput_gb_s = 40.0f; break;
        case NEVM::ISA::PrecisionMode::Q2_K: throughput_gb_s = 30.0f; break;
        default: throughput_gb_s = 200.0f; break;  // FP16 passthrough
    }
    
    size_t bytes = element_count * sizeof(uint16_t);
    float seconds = static_cast<float>(bytes) / (throughput_gb_s * 1e9f);
    uint64_t latency_us = static_cast<uint64_t>(seconds * 1e6f);
    
    return base_latency + latency_us;
}

} // namespace Memory
} // namespace RawrXD
