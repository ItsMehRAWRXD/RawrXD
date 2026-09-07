#define BUILDING_WEIGHT_PROJECTION_DLL
#include "WeightProjection.hpp"

#include <immintrin.h>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <cstdint>

// -----------------------------------------------------------------------------
// FP16 Helper Functions for Quant Block Headers
// -----------------------------------------------------------------------------
static inline uint16_t fp32_to_fp16(float val) {
    uint32_t f32_bits;
    std::memcpy(&f32_bits, &val, sizeof(float));

    uint32_t sign = (f32_bits >> 16) & 0x8000;
    int32_t exp = ((f32_bits >> 23) & 0xFF) - 127 + 15;
    uint32_t frac = f32_bits & 0x007FFFFF;

    if (exp <= 0) return (uint16_t)sign;
    if (exp >= 31) return (uint16_t)(sign | 0x7C00);
    return (uint16_t)(sign | (exp << 10) | (frac >> 13));
}

// -----------------------------------------------------------------------------
// SIMD Pack Kernels
// -----------------------------------------------------------------------------

// 1. B1 Binary Quantization: 1 bit per weight (8 floats -> 1 byte)
static void pack_b1_avx2(const float* __restrict src, uint8_t* __restrict dst, size_t n) {
    size_t i = 0;
    const __m256 vzero = _mm256_setzero_ps();

    for (; i + 32 <= n; i += 32) {
        __m256 v0 = _mm256_loadu_ps(src + i);
        __m256 v1 = _mm256_loadu_ps(src + i + 8);
        __m256 v2 = _mm256_loadu_ps(src + i + 16);
        __m256 v3 = _mm256_loadu_ps(src + i + 24);

        int m0 = _mm256_movemask_ps(_mm256_cmp_ps(v0, vzero, _CMP_GT_OQ));
        int m1 = _mm256_movemask_ps(_mm256_cmp_ps(v1, vzero, _CMP_GT_OQ));
        int m2 = _mm256_movemask_ps(_mm256_cmp_ps(v2, vzero, _CMP_GT_OQ));
        int m3 = _mm256_movemask_ps(_mm256_cmp_ps(v3, vzero, _CMP_GT_OQ));

        dst[i / 8 + 0] = static_cast<uint8_t>(m0);
        dst[i / 8 + 1] = static_cast<uint8_t>(m1);
        dst[i / 8 + 2] = static_cast<uint8_t>(m2);
        dst[i / 8 + 3] = static_cast<uint8_t>(m3);
    }

    // Scalar tail handling
    for (; i < n; ++i) {
        if (src[i] > 0.0f) {
            dst[i / 8] |= (1 << (i % 8));
        } else {
            dst[i / 8] &= ~(1 << (i % 8));
        }
    }
}

// 2. T3 Ternary Quantization: {-1, 0, +1} -> 2 bits per weight (4 weights/byte)
static void pack_t3_avx2(const float* __restrict src, uint8_t* __restrict dst, size_t n, float threshold) {
    size_t i = 0;
    const __m256 vpos_th = _mm256_set1_ps(threshold);
    const __m256 vneg_th = _mm256_set1_ps(-threshold);

    for (; i + 8 <= n; i += 8) {
        __m256 v = _mm256_loadu_ps(src + i);

        __m256 mask_pos = _mm256_cmp_ps(v, vpos_th, _CMP_GT_OQ);
        __m256 mask_neg = _mm256_cmp_ps(v, vneg_th, _CMP_LT_OQ);

        int pos_bits = _mm256_movemask_ps(mask_pos);
        int neg_bits = _mm256_movemask_ps(mask_neg);

        uint8_t byte0 = 0, byte1 = 0;
        for (int k = 0; k < 4; ++k) {
            uint8_t code = ((pos_bits >> k) & 1) | (((neg_bits >> k) & 1) << 1);
            byte0 |= (code << (k * 2));
        }
        for (int k = 0; k < 4; ++k) {
            uint8_t code = ((pos_bits >> (k + 4)) & 1) | (((neg_bits >> (k + 4)) & 1) << 1);
            byte1 |= (code << (k * 2));
        }

        dst[i / 4 + 0] = byte0;
        dst[i / 4 + 1] = byte1;
    }

    // Scalar tail
    for (; i < n; ++i) {
        uint8_t code = 0;
        if (src[i] > threshold) code = 1;
        else if (src[i] < -threshold) code = 2;

        size_t byte_idx = i / 4;
        size_t bit_shift = (i % 4) * 2;
        dst[byte_idx] = (dst[byte_idx] & ~(0x03 << bit_shift)) | (code << bit_shift);
    }
}

// 3. Q4_K Block Packing (256 weights -> Q4_K block)
#pragma pack(push, 1)
struct block_q4_K_layout {
    uint16_t d;           // FP16 master scale
    uint16_t dmin;        // FP16 master min scale
    uint8_t  scales[12];  // 6-bit packed scales for 8 sub-blocks
    uint8_t  qs[128];     // 256 x 4-bit quants packed pairwise
};
#pragma pack(pop)

static void pack_q4k_block_avx2(const float* __restrict src, block_q4_K_layout* __restrict dst) {
    __m256 vmax = _mm256_setzero_ps();
    __m256 vmin = _mm256_setzero_ps();

    for (int i = 0; i < 256; i += 8) {
        __m256 v = _mm256_loadu_ps(src + i);
        vmax = _mm256_max_ps(vmax, v);
        vmin = _mm256_min_ps(vmin, v);
    }

    alignas(32) float max_buf[8], min_buf[8];
    _mm256_storeu_ps(max_buf, vmax);
    _mm256_storeu_ps(min_buf, vmin);

    float max_val = max_buf[0], min_val = min_buf[0];
    for (int k = 1; k < 8; ++k) {
        if (max_buf[k] > max_val) max_val = max_buf[k];
        if (min_buf[k] < min_val) min_val = min_buf[k];
    }

    float range = max_val - min_val;
    float scale = (range > 1.0e-10f) ? (range / 15.0f) : 1.0e-10f;
    float idscale = 1.0f / scale;

    dst->d = fp32_to_fp16(scale);
    dst->dmin = fp32_to_fp16(min_val);
    std::memset(dst->scales, 0, sizeof(dst->scales));

    for (int i = 0; i < 256; i += 32) {
        for (int l = 0; l < 16; ++l) {
            float x0 = src[i + l];
            float x1 = src[i + l + 16];

            int q0 = std::clamp(static_cast<int>(std::round((x0 - min_val) * idscale)), 0, 15);
            int q1 = std::clamp(static_cast<int>(std::round((x1 - min_val) * idscale)), 0, 15);

            dst->qs[(i / 2) + l] = static_cast<uint8_t>(q0 | (q1 << 4));
        }
    }
}

// -----------------------------------------------------------------------------
// C-ABI Exported API Implementation
// -----------------------------------------------------------------------------
extern "C" {

WP_ABI int WeightResolve(const WeightRef* ref, WeightView* out_view) {
    if (!ref || !ref->data || ref->num_elements == 0 || !out_view) {
        return -1; // EINVAL
    }

    out_view->ref = *ref;
    out_view->format = static_cast<WeightFormat>(Classify(ref->data, ref->num_elements));

    uint32_t nz = 0;
    float max_abs = 0.0f;
    double sum_abs = 0.0;

    for (uint32_t i = 0; i < ref->num_elements; ++i) {
        uint32_t u;
        float x = ref->data[i];
        std::memcpy(&u, &x, sizeof(float));

        if ((u & 0x7F800000u) == 0x7F800000u) continue; // Skip NaN/Inf

        u &= 0x7FFFFFFF;
        float a;
        std::memcpy(&a, &u, sizeof(float));

        if (a > 0.0f) {
            nz++;
            if (a > max_abs) max_abs = a;
            sum_abs += static_cast<double>(a);
        }
    }

    const float n = static_cast<float>(ref->num_elements);
    out_view->non_zero_count = nz;
    out_view->density = static_cast<float>(nz) / n;

    const float mean_abs = static_cast<float>(sum_abs / static_cast<double>(n));
    out_view->peak_to_mean_ratio = max_abs / (mean_abs + 1.0e-30f);

    return 0;
}

WP_ABI int WeightProject(const WeightView* view, void* target_buffer, size_t target_capacity) {
    if (!view || !target_buffer) return -1; // EINVAL

    const uint32_t n = view->ref.num_elements;
    const float* src = view->ref.data;
    uint8_t* dst = static_cast<uint8_t*>(target_buffer);

    switch (view->format) {
        case WF_ZERO: {
            std::memset(target_buffer, 0, target_capacity);
            return 0;
        }

        case WF_B1: {
            size_t req_bytes = (n + 7) / 8;
            if (target_capacity < req_bytes) return -2; // ENOBUFS
            std::memset(dst, 0, req_bytes);
            pack_b1_avx2(src, dst, n);
            return 0;
        }

        case WF_T3: {
            size_t req_bytes = (n + 3) / 4;
            if (target_capacity < req_bytes) return -2; // ENOBUFS
            float threshold = 0.5f * (view->peak_to_mean_ratio > 0.0f ? (1.0f / view->peak_to_mean_ratio) : 0.1f);
            std::memset(dst, 0, req_bytes);
            pack_t3_avx2(src, dst, n, threshold);
            return 0;
        }

        case WF_Q3:
        case WF_Q4: {
            size_t num_blocks = (n + 255) / 256;
            size_t req_bytes = num_blocks * sizeof(block_q4_K_layout);
            if (target_capacity < req_bytes) return -2; // ENOBUFS

            block_q4_K_layout* block_dst = reinterpret_cast<block_q4_K_layout*>(dst);
            for (size_t b = 0; b < num_blocks; ++b) {
                alignas(32) float chunk[256] = {0.0f};
                size_t remaining = std::min<size_t>(256, n - b * 256);
                std::memcpy(chunk, src + b * 256, remaining * sizeof(float));

                pack_q4k_block_avx2(chunk, &block_dst[b]);
            }
            return 0;
        }

        case WF_RAW: {
            size_t req_bytes = n * sizeof(float);
            if (target_capacity < req_bytes) return -2; // ENOBUFS
            std::memcpy(target_buffer, src, req_bytes);
            return 0;
        }

        default:
            return -3; // EBADFMT
    }
}

WP_ABI void WeightRelease(WeightView* view) {
    if (view) {
        std::memset(view, 0, sizeof(WeightView));
    }
}

} // extern "C"
