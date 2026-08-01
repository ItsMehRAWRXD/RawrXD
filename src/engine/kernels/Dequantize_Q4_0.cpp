// src/engine/kernels/Dequantize_Q4_0.cpp
// Q4_0 Block Dequantization — AVX2-accelerated 4-bit to FP32 expansion
//
// Expands packed 4-bit integer nibbles into standard 32-bit floats.
// Uses AVX2 intrinsic registers (__m256) to decode 32 elements simultaneously
// in a single processing frame, avoiding pipeline execution stalls.

#include "SovereignMathCore.hpp"
#include <cstring>

// ---------------------------------------------------------------------------
// FP16 → FP32 conversion helper
// ---------------------------------------------------------------------------
float SovereignMathCore::FP16_To_FP32(uint16_t h) {
    // Use F16C instruction if available
    if (s_features.hasF16c) {
#if defined(__F16C__) || defined(_MSC_VER)
        // MSVC: _mm_cvtss_f32(_mm_cvtph_ps(_mm_set1_epi16(h)))
        __m128i v = _mm_set1_epi16((short)h);
        __m128 f = _mm_cvtph_ps(v);
        return _mm_cvtss_f32(f);
#else
        // Software fallback
        uint32_t sign = (h & 0x8000) << 16;
        uint32_t exp = (h & 0x7C00) >> 10;
        uint32_t mant = h & 0x03FF;

        uint32_t f32;
        if (exp == 0) {
            // Subnormal
            if (mant == 0) {
                f32 = sign;
            } else {
                exp = 1;
                while ((mant & 0x0400) == 0) { mant <<= 1; exp--; }
                mant &= 0x03FF;
                f32 = sign | ((exp + 112) << 23) | (mant << 13);
            }
        } else if (exp == 31) {
            // Infinity/NaN
            f32 = sign | 0x7F800000 | (mant << 13);
        } else {
            f32 = sign | ((exp + 112) << 23) | (mant << 13);
        }
        float result;
        memcpy(&result, &f32, sizeof(result));
        return result;
#endif
    }

    // Software fallback
    uint32_t sign = (h & 0x8000) << 16;
    uint32_t exp = (h & 0x7C00) >> 10;
    uint32_t mant = h & 0x03FF;

    uint32_t f32;
    if (exp == 0) {
        if (mant == 0) { f32 = sign; }
        else {
            exp = 1;
            while ((mant & 0x0400) == 0) { mant <<= 1; exp--; }
            mant &= 0x03FF;
            f32 = sign | ((exp + 112) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f32 = sign | 0x7F800000 | (mant << 13);
    } else {
        f32 = sign | ((exp + 112) << 23) | (mant << 13);
    }
    float result;
    memcpy(&result, &f32, sizeof(result));
    return result;
}

// ---------------------------------------------------------------------------
// Q4_0 Row Dequantization — AVX2 accelerated
// ---------------------------------------------------------------------------
void SovereignMathCore::Dequantize_Q4_0_Row(const void* __restrict src, float* __restrict dst, size_t elements) {
    const Block_Q4_0* __restrict blocks = static_cast<const Block_Q4_0*>(src);
    size_t blockCount = elements / 32;

    // Vectorized mask extraction constants
    __m256i lowMask = _mm256_set1_epi8(0x0F);
    __m256i offsetOffset = _mm256_set1_epi32(8);

    for (size_t b = 0; b < blockCount; ++b) {
        // 1. Load FP16 scale and convert to FP32
        float scale = FP16_To_FP32(blocks[b].deltaHalf);
        __m256 vScale = _mm256_set1_ps(scale);

        // 2. Load 16 packed bytes (32 4-bit values)
        __m128i packedRaw = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(blocks[b].packedNibbles));

        // 3. Split and expand 128-bit packed array into parallel 256-bit int registers
        __m256i innerBytes = _mm256_cvtepu8_epi16(packedRaw);

        // 4. Separate low and high nibbles via bit shift masks
        __m256i lowNibbles  = _mm256_and_si256(innerBytes, lowMask);
        __m256i highNibbles = _mm256_and_si256(_mm256_srli_epi16(innerBytes, 4), lowMask);

        // 5. Center the numerical values around zero (subtract 8) and convert to float
        __m128i lowNibblesLo = _mm256_castsi256_si128(lowNibbles);
        __m128i lowNibblesHi = _mm256_extracti128_si256(lowNibbles, 1);
        __m128i highNibblesLo = _mm256_castsi256_si128(highNibbles);
        __m128i highNibblesHi = _mm256_extracti128_si256(highNibbles, 1);

        __m256i lowInt  = _mm256_sub_epi32(
            _mm256_cvtepi16_epi32(lowNibblesLo), offsetOffset);
        __m256i highInt = _mm256_sub_epi32(
            _mm256_cvtepi16_epi32(highNibblesLo), offsetOffset);

        __m256i lowInt2  = _mm256_sub_epi32(
            _mm256_cvtepi16_epi32(lowNibblesHi), offsetOffset);
        __m256i highInt2 = _mm256_sub_epi32(
            _mm256_cvtepi16_epi32(highNibblesHi), offsetOffset);

        __m256 lowFloat  = _mm256_cvtepi32_ps(lowInt);
        __m256 highFloat = _mm256_cvtepi32_ps(highInt);
        __m256 lowFloat2  = _mm256_cvtepi32_ps(lowInt2);
        __m256 highFloat2 = _mm256_cvtepi32_ps(highInt2);

        // 6. Multiply by scale and store directly to output address space
        _mm256_storeu_ps(dst + (b * 32),           _mm256_mul_ps(lowFloat, vScale));
        _mm256_storeu_ps(dst + (b * 32) + 8,       _mm256_mul_ps(highFloat, vScale));
        _mm256_storeu_ps(dst + (b * 32) + 16,      _mm256_mul_ps(lowFloat2, vScale));
        _mm256_storeu_ps(dst + (b * 32) + 24,      _mm256_mul_ps(highFloat2, vScale));
    }
}

// ---------------------------------------------------------------------------
// Q8_0 Row Dequantization
// ---------------------------------------------------------------------------
void SovereignMathCore::Dequantize_Q8_0_Row(const void* __restrict src, float* __restrict dst, size_t elements) {
    const Block_Q8_0* __restrict blocks = static_cast<const Block_Q8_0*>(src);
    size_t blockCount = elements / 32;

    for (size_t b = 0; b < blockCount; ++b) {
        float scale = blocks[b].scale;
        __m256 vScale = _mm256_set1_ps(scale);

        // Load 32 int8 values
        __m128i rawLow = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(&blocks[b].quantized[0]));
        __m128i rawHigh = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(&blocks[b].quantized[16]));

        // Convert to 16-bit then 32-bit int, then to float
        // _mm256_cvtepi8_epi16 takes __m128i, returns __m256i
        // _mm256_cvtepi16_epi32 takes __m128i, returns __m256i
        // Extract 128-bit lanes from the 256-bit intermediate
        __m256i i16Low  = _mm256_cvtepi8_epi16(rawLow);
        __m256i i16High = _mm256_cvtepi8_epi16(rawHigh);

        __m128i i16LowLo  = _mm256_castsi256_si128(i16Low);
        __m128i i16LowHi  = _mm256_extracti128_si256(i16Low, 1);
        __m128i i16HighLo = _mm256_castsi256_si128(i16High);
        __m128i i16HighHi = _mm256_extracti128_si256(i16High, 1);

        __m256i lowInt   = _mm256_cvtepi16_epi32(i16LowLo);
        __m256i lowInt2  = _mm256_cvtepi16_epi32(i16LowHi);
        __m256i highInt  = _mm256_cvtepi16_epi32(i16HighLo);
        __m256i highInt2 = _mm256_cvtepi16_epi32(i16HighHi);

        __m256 lowFloat  = _mm256_cvtepi32_ps(lowInt);
        __m256 lowFloat2 = _mm256_cvtepi32_ps(lowInt2);
        __m256 highFloat  = _mm256_cvtepi32_ps(highInt);
        __m256 highFloat2 = _mm256_cvtepi32_ps(highInt2);

        _mm256_storeu_ps(dst + (b * 32),       _mm256_mul_ps(lowFloat, vScale));
        _mm256_storeu_ps(dst + (b * 32) + 8,   _mm256_mul_ps(lowFloat2, vScale));
        _mm256_storeu_ps(dst + (b * 32) + 16,  _mm256_mul_ps(highFloat, vScale));
        _mm256_storeu_ps(dst + (b * 32) + 24,  _mm256_mul_ps(highFloat2, vScale));
    }
}
