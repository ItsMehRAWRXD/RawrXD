#pragma once
#include <immintrin.h>
#include <stdint.h>

namespace Deep2Rom::Compute {

    // --- AVX2 VECTORIZED 8-CHANNEL SIMD LCG GENERATOR (256-bit YMM) ---
    static inline __m256 vectorize_procedural_generator_avx2(__m256i& state) {
        __m256i mult = _mm256_set1_epi32(1664525);
        __m256i add_v = _mm256_set_epi32(
            1013904223, 1664525, 1013904223, 1664525,
            1013904223, 1664525, 1013904223, 1664525
        );
        
        state = _mm256_add_epi32(_mm256_mullo_epi32(state, mult), add_v);
        
        // Convert to float [-0.5, 0.5]
        __m256i masked = _mm256_and_si256(state, _mm256_set1_epi32(0x00FFFFFF));
        __m256 floats = _mm256_cvtepi32_ps(masked);
        return _mm256_fmsub_ps(floats, _mm256_set1_ps(1.1920929e-7f), _mm256_set1_ps(0.5f));
    }

    // --- 4x DEEP LOOP UNROLLING KERNEL (AVX2 / 256-bit YMM) ---
    inline void execute_extreme_waaf_gemv_avx2(
        const float* __restrict hidden, 
        float* __restrict logits, 
        uint32_t cols, 
        uint32_t start_r, 
        uint32_t end_r, 
        uint64_t seed) 
    {
        // Process 4 rows concurrently to fully pipeline out-of-order execution slots
        for (uint32_t r = start_r; r < end_r; r += 4) {
            __m256 acc0 = _mm256_setzero_ps();
            __m256 acc1 = _mm256_setzero_ps();
            __m256 acc2 = _mm256_setzero_ps();
            __m256 acc3 = _mm256_setzero_ps();

            __m256i state0 = _mm256_set1_epi64x(seed + r);
            __m256i state1 = _mm256_set1_epi64x(seed + r + 1);
            __m256i state2 = _mm256_set1_epi64x(seed + r + 2);
            __m256i state3 = _mm256_set1_epi64x(seed + r + 3);

            for (uint32_t c = 0; c < cols; c += 8) {
                _mm_prefetch(reinterpret_cast<const char*>(hidden + c + 8), _MM_HINT_T0);
                __m256 v = _mm256_load_ps(hidden + c);
                
                acc0 = _mm256_fmadd_ps(vectorize_procedural_generator_avx2(state0), v, acc0);
                acc1 = _mm256_fmadd_ps(vectorize_procedural_generator_avx2(state1), v, acc1);
                acc2 = _mm256_fmadd_ps(vectorize_procedural_generator_avx2(state2), v, acc2);
                acc3 = _mm256_fmadd_ps(vectorize_procedural_generator_avx2(state3), v, acc3);
            }
            
            // Execute horizontal reduction passes out-of-line
            __m256 sum0 = _mm256_hadd_ps(acc0, acc0);
            __m256 sum1 = _mm256_hadd_ps(acc1, acc1);
            __m256 sum2 = _mm256_hadd_ps(acc2, acc2);
            __m256 sum3 = _mm256_hadd_ps(acc3, acc3);

            float out0[8], out1[8], out2[8], out3[8];
            _mm256_storeu_ps(out0, sum0); _mm256_storeu_ps(out1, sum1);
            _mm256_storeu_ps(out2, sum2); _mm256_storeu_ps(out3, sum3);

            logits[r]     = out0[0] + out0[4];
            logits[r + 1] = out1[0] + out1[4];
            logits[r + 2] = out2[0] + out2[4];
            logits[r + 3] = out3[0] + out3[4];
        }
    }
}