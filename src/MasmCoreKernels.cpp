#include "MasmCoreKernels.hpp"
#include <immintrin.h>
#include <cstring>
#include <cmath>

namespace Deep2Engine {

void dequantize_q2_k_avx512(
    const uint8_t* __restrict src_payload,
    float* __restrict dst_fp32,
    uint64_t num_blocks
) {
    // Q2_K block layout (ggml): qs[64] 2-bit packed + scales[16] uint8 + d fp16 = 82 bytes
    // Each block holds 256 quantized values.
    for (uint64_t b = 0; b < num_blocks; ++b) {
        const uint8_t* block = src_payload + b * 82;

        // Super-scale d (fp16 at offset 80)
        uint16_t d_raw;
        std::memcpy(&d_raw, block + 80, 2);
        uint32_t sign = (d_raw & 0x8000u) << 16;
        uint32_t exp = (d_raw & 0x7C00u) >> 10;
        uint32_t frac = d_raw & 0x03FFu;
        uint32_t f32 = 0;
        if (exp == 31) {
            f32 = sign | 0x7F800000u | (frac << 13);
        } else if (exp == 0) {
            if (frac != 0) {
                while ((frac & 0x0400u) == 0) { frac <<= 1; exp--; }
                exp++;
                frac &= ~0x0400u;
                f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
            } else {
                f32 = sign;
            }
        } else {
            f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
        }
        float d;
        std::memcpy(&d, &f32, 4);
        if (std::isnan(d) || std::isinf(d)) d = 0.0f;

        // Per-group scales (uint8 at offset 64, 16 groups)
        const uint8_t* scales = block + 64;
        float group_scale[16];
        for (int g = 0; g < 16; ++g) {
            group_scale[g] = d * static_cast<float>(scales[g]) / 64.0f;
        }

        const uint8_t* qs = block; // 64 bytes of 2-bit packed values
        float* out = dst_fp32 + b * 256;

        // Process 256 values per block, 8 at a time with AVX2 YMM
        for (uint64_t k = 0; k < 256; k += 8) {
            alignas(32) float vals[8];
            for (int i = 0; i < 8; ++i) {
                uint64_t valIdx = k + i;
                uint64_t j = valIdx / 4;            // byte index in qs
                uint64_t bshift = (3 - (valIdx % 4)) * 2; // bit offset
                uint8_t q = (qs[j] >> bshift) & 0x03u;
                int g = static_cast<int>(j >> 2);   // 4 bytes per 16-value group
                vals[i] = (static_cast<float>(q) - 1.5f) * group_scale[g];
            }
            __m256 v = _mm256_load_ps(vals);
            _mm256_storeu_ps(out + k, v);
        }
    }
}

float vec_dot_prod_fp32_avx512(
    const float* __restrict vec_a,
    const float* __restrict vec_b,
    uint64_t num_elements
) {
    __m256 acc = _mm256_setzero_ps();
    uint64_t i = 0;

    for (; i + 7 < num_elements; i += 8) {
        __m256 a = _mm256_loadu_ps(vec_a + i);
        __m256 b = _mm256_loadu_ps(vec_b + i);
        acc = _mm256_fmadd_ps(a, b, acc);
    }

    // Horizontal reduction using haddp
    __m256 hsum = _mm256_hadd_ps(acc, acc);
    hsum = _mm256_hadd_ps(hsum, hsum);
    float sum = _mm256_cvtss_f32(_mm256_permute2f128_ps(hsum, hsum, 1));

    // Remainder
    for (; i < num_elements; ++i) {
        sum += vec_a[i] * vec_b[i];
    }

    return sum;
}

} // namespace Deep2Engine
