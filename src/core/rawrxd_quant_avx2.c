//=============================================================================
// rawrxd_quant_avx2.c
// AVX2-Optimized Quantization Kernels
// Compile with: /arch:AVX2
//=============================================================================

#include "rawrxd_inference.h"
#include "rawrxd_core.h"

#if defined(_WIN32) && defined(_MSC_VER)
    #include <intrin.h>
    #define RAWRXD_HAS_AVX2 1
#elif defined(__AVX2__)
    #include <immintrin.h>
    #define RAWRXD_HAS_AVX2 1
#else
    #define RAWRXD_HAS_AVX2 0
#endif

#if RAWRXD_HAS_AVX2

//=============================================================================
// AVX2 Q4_0 Matrix-Vector Multiplication
//=============================================================================

void rawrxd_q4_0_mat_vec_avx2(const void* mat, const f32* vec, f32* out,
                               u64 nrows, u64 ncols) {
    const block_q4_0* blocks = (const block_q4_0*)mat;
    u64 nb_per_row = ncols / 32;
    
    for (u64 row = 0; row < nrows; row++) {
        const block_q4_0* row_blocks = blocks + row * nb_per_row;
        __m256 sum_vec = _mm256_setzero_ps();
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            // Load scale
            __m256 scale = _mm256_set1_ps(row_blocks[nb].d);
            
            // Load 32 quantized values (16 bytes, 2 per byte)
            const u8* qs = row_blocks[nb].qs;
            
            // Process 16 values at a time (2 blocks of 16 nibbles)
            for (int group = 0; group < 2; group++) {
                // Load vector values
                __m256 v = _mm256_loadu_ps(vec + nb * 32 + group * 16);
                
                // Load and unpack quantized values
                __m128i q8 = _mm_loadu_si128((const __m128i*)(qs + group * 8));
                
                // Unpack low nibbles
                __m128i low_mask = _mm_set1_epi8(0x0F);
                __m128i low_nibbles = _mm_and_si128(q8, low_mask);
                __m128i high_nibbles = _mm_srli_epi16(q8, 4);
                high_nibbles = _mm_and_si128(high_nibbles, low_mask);
                
                // Convert to 16-bit
                __m256i low_16 = _mm256_cvtepu8_epi16(low_nibbles);
                __m256i high_16 = _mm256_cvtepu8_epi16(high_nibbles);
                
                // Subtract 8 (zero point)
                __m256i zero = _mm256_set1_epi16(8);
                low_16 = _mm256_sub_epi16(low_16, zero);
                high_16 = _mm256_sub_epi16(high_16, zero);
                
                // Convert to float
                __m256 low_f = _mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(
                    _mm256_castsi256_si128(low_16)));
                __m256 high_f = _mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(
                    _mm256_castsi256_si128(high_16)));
                
                // Scale and multiply
                low_f = _mm256_mul_ps(low_f, scale);
                high_f = _mm256_mul_ps(high_f, scale);
                
                // Multiply with vector and accumulate
                __m256 v_low = v;
                __m256 v_high = _mm256_loadu_ps(vec + nb * 32 + group * 16 + 8);
                
                sum_vec = _mm256_fmadd_ps(low_f, v_low, sum_vec);
                sum_vec = _mm256_fmadd_ps(high_f, v_high, sum_vec);
            }
        }
        
        // Horizontal sum
        __m128 sum_high = _mm256_extractf128_ps(sum_vec, 1);
        __m128 sum_low = _mm256_castps256_ps128(sum_vec);
        sum_low = _mm_add_ps(sum_low, sum_high);
        sum_low = _mm_hadd_ps(sum_low, sum_low);
        sum_low = _mm_hadd_ps(sum_low, sum_low);
        
        out[row] = _mm_cvtss_f32(sum_low);
    }
}

//=============================================================================
// AVX2 Q8_0 Matrix-Vector Multiplication
//=============================================================================

void rawrxd_q8_0_mat_vec_avx2(const void* mat, const f32* vec, f32* out,
                               u64 nrows, u64 ncols) {
    const block_q8_0* blocks = (const block_q8_0*)mat;
    u64 nb_per_row = ncols / 32;
    
    for (u64 row = 0; row < nrows; row++) {
        const block_q8_0* row_blocks = blocks + row * nb_per_row;
        __m256 sum_vec = _mm256_setzero_ps();
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            // Load scale
            __m256 scale = _mm256_set1_ps(row_blocks[nb].d);
            
            // Load 32 int8 values
            __m256i q = _mm256_loadu_si256((const __m256i*)row_blocks[nb].qs);
            
            // Convert to 16-bit (sign-extended)
            __m256i q16_low = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(q));
            __m256i q16_high = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(q, 1));
            
            // Load vector
            __m256 v_low = _mm256_loadu_ps(vec + nb * 32);
            __m256 v_high = _mm256_loadu_ps(vec + nb * 32 + 8);
            
            // Convert to float and multiply
            __m256 q_low_f = _mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(
                _mm256_castsi256_si128(q16_low)));
            __m256 q_high_f = _mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(
                _mm256_castsi256_si128(q16_high)));
            
            // Scale
            q_low_f = _mm256_mul_ps(q_low_f, scale);
            q_high_f = _mm256_mul_ps(q_high_f, scale);
            
            // FMA
            sum_vec = _mm256_fmadd_ps(q_low_f, v_low, sum_vec);
            
            // Process second half
            v_low = _mm256_loadu_ps(vec + nb * 32 + 16);
            v_high = _mm256_loadu_ps(vec + nb * 32 + 24);
            
            q_low_f = _mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(
                _mm256_extracti128_si256(q16_low, 1)));
            q_high_f = _mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(
                _mm256_extracti128_si256(q16_high, 1)));
            
            q_low_f = _mm256_mul_ps(q_low_f, scale);
            q_high_f = _mm256_mul_ps(q_high_f, scale);
            
            sum_vec = _mm256_fmadd_ps(q_low_f, v_low, sum_vec);
            sum_vec = _mm256_fmadd_ps(q_high_f, v_high, sum_vec);
        }
        
        // Horizontal sum
        __m128 sum_high = _mm256_extractf128_ps(sum_vec, 1);
        __m128 sum_low = _mm256_castps256_ps128(sum_vec);
        sum_low = _mm_add_ps(sum_low, sum_high);
        sum_low = _mm_hadd_ps(sum_low, sum_low);
        sum_low = _mm_hadd_ps(sum_low, sum_low);
        
        out[row] = _mm_cvtss_f32(sum_low);
    }
}

//=============================================================================
// AVX2 RMS Normalization
//=============================================================================

void rawrxd_rms_norm_avx2(f32* output, const f32* input, u32 size, f32 eps) {
    __m256 sum_vec = _mm256_setzero_ps();
    u32 i = 0;
    
    // Sum squares
    for (; i + 8 <= size; i += 8) {
        __m256 x = _mm256_loadu_ps(input + i);
        sum_vec = _mm256_fmadd_ps(x, x, sum_vec);
    }
    
    // Horizontal sum
    __m128 sum_high = _mm256_extractf128_ps(sum_vec, 1);
    __m128 sum_low = _mm256_castps256_ps128(sum_vec);
    sum_low = _mm_add_ps(sum_low, sum_high);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    f32 sum = _mm_cvtss_f32(sum_low);
    
    // Remainder
    for (; i < size; i++) {
        sum += input[i] * input[i];
    }
    
    f32 scale = 1.0f / sqrtf(sum / size + eps);
    __m256 scale_vec = _mm256_set1_ps(scale);
    
    // Normalize
    for (i = 0; i + 8 <= size; i += 8) {
        __m256 x = _mm256_loadu_ps(input + i);
        _mm256_storeu_ps(output + i, _mm256_mul_ps(x, scale_vec));
    }
    
    for (; i < size; i++) {
        output[i] = input[i] * scale;
    }
}

//=============================================================================
// AVX2 Softmax
//=============================================================================

void rawrxd_softmax_avx2(f32* x, u32 size) {
    // Find max
    __m256 max_vec = _mm256_set1_ps(-1e30f);
    u32 i = 0;
    
    for (; i + 8 <= size; i += 8) {
        __m256 v = _mm256_loadu_ps(x + i);
        max_vec = _mm256_max_ps(max_vec, v);
    }
    
    __m128 max_high = _mm256_extractf128_ps(max_vec, 1);
    __m128 max_low = _mm256_castps256_ps128(max_vec);
    max_low = _mm_max_ps(max_low, max_high);
    max_low = _mm_max_ps(max_low, _mm_shuffle_ps(max_low, max_low, _MM_SHUFFLE(1,0,3,2)));
    max_low = _mm_max_ps(max_low, _mm_shuffle_ps(max_low, max_low, _MM_SHUFFLE(2,3,0,1)));
    f32 max_val = _mm_cvtss_f32(max_low);
    
    for (; i < size; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    // Exp and sum
    __m256 sum_vec = _mm256_setzero_ps();
    __m256 max_val_vec = _mm256_set1_ps(max_val);
    
    for (i = 0; i + 8 <= size; i += 8) {
        __m256 v = _mm256_loadu_ps(x + i);
        v = _mm256_sub_ps(v, max_val_vec);
        // Approximate exp
        v = rawrxd_exp_ps(v);
        _mm256_storeu_ps(x + i, v);
        sum_vec = _mm256_add_ps(sum_vec, v);
    }
    
    // Horizontal sum
    __m128 sum_high = _mm256_extractf128_ps(sum_vec, 1);
    __m128 sum_low = _mm256_castps256_ps128(sum_vec);
    sum_low = _mm_add_ps(sum_low, sum_high);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    f32 sum = _mm_cvtss_f32(sum_low);
    
    // Remainder
    for (; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    // Normalize
    __m256 scale = _mm256_set1_ps(1.0f / sum);
    for (i = 0; i + 8 <= size; i += 8) {
        __m256 v = _mm256_loadu_ps(x + i);
        _mm256_storeu_ps(x + i, _mm256_mul_ps(v, scale));
    }
    
    for (; i < size; i++) {
        x[i] /= sum;
    }
}

//=============================================================================
// AVX2 SiLU
//=============================================================================

void rawrxd_silu_avx2(f32* x, u32 n) {
    u32 i = 0;
    for (; i + 8 <= n; i += 8) {
        __m256 v = _mm256_loadu_ps(x + i);
        // sigmoid(x) = 1 / (1 + exp(-x))
        __m256 neg_v = _mm256_sub_ps(_mm256_setzero_ps(), v);
        __m256 exp_neg = rawrxd_exp_ps(neg_v);
        __m256 one = _mm256_set1_ps(1.0f);
        __m256 sigmoid = _mm256_div_ps(one, _mm256_add_ps(one, exp_neg));
        // silu(x) = x * sigmoid(x)
        _mm256_storeu_ps(x + i, _mm256_mul_ps(v, sigmoid));
    }
    
    for (; i < n; i++) {
        x[i] = x[i] / (1.0f + expf(-x[i]));
    }
}

//=============================================================================
// Helper: Approximate exp for AVX2
//=============================================================================

static inline __m256 rawrxd_exp_ps(__m256 x) {
    // Fast exp approximation using polynomial
    // exp(x) = 2^(x/ln(2)) = 2^floor(x/ln(2)) * 2^frac(x/ln(2))
    
    const __m256 ln2 = _mm256_set1_ps(0.6931471805599453f);
    const __m256 inv_ln2 = _mm256_set1_ps(1.4426950408889634f);
    
    __m256 z = _mm256_mul_ps(x, inv_ln2);
    __m256 z_int = _mm256_round_ps(z, _MM_FROUND_TO_NEAREST_INT);
    __m256 z_frac = _mm256_sub_ps(z, z_int);
    
    // Polynomial for 2^frac: 1 + frac * (0.693147 + frac * (0.240227 + ...))
    __m256 p = _mm256_set1_ps(1.0f);
    __m256 c1 = _mm256_set1_ps(0.693147f);
    __m256 c2 = _mm256_set1_ps(0.240227f);
    __m256 c3 = _mm256_set1_ps(0.055504f);
    
    p = _mm256_add_ps(p, _mm256_mul_ps(z_frac, c1));
    __m256 z2 = _mm256_mul_ps(z_frac, z_frac);
    p = _mm256_add_ps(p, _mm256_mul_ps(z2, c2));
    __m256 z3 = _mm256_mul_ps(z2, z_frac);
    p = _mm256_add_ps(p, _mm256_mul_ps(z3, c3));
    
    // Scale by 2^int
    __m256i exp_int = _mm256_cvtps_epi32(z_int);
    exp_int = _mm256_add_epi32(exp_int, _mm256_set1_epi32(127));
    exp_int = _mm256_slli_epi32(exp_int, 23);
    __m256 scale = _mm256_castsi256_ps(exp_int);
    
    return _mm256_mul_ps(p, scale);
}

#else // !RAWRXD_HAS_AVX2

// Fallback to scalar implementations
void rawrxd_q4_0_mat_vec_avx2(const void* mat, const f32* vec, f32* out,
                               u64 nrows, u64 ncols) {
    rawrxd_q4_0_mat_vec(mat, vec, out, nrows, ncols);
}

void rawrxd_q8_0_mat_vec_avx2(const void* mat, const f32* vec, f32* out,
                               u64 nrows, u64 ncols) {
    rawrxd_q8_0_mat_vec(mat, vec, out, nrows, ncols);
}

void rawrxd_rms_norm_avx2(f32* output, const f32* input, u32 size, f32 eps) {
    rawrxd_rms_norm(output, input, size, eps);
}

void rawrxd_softmax_avx2(f32* x, u32 size) {
    rawrxd_softmax(x, size);
}

void rawrxd_silu_avx2(f32* x, u32 n) {
    rawrxd_silu(x, n);
}

#endif // RAWRXD_HAS_AVX2
