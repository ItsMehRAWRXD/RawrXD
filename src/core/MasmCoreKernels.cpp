#include "MasmCoreKernels.hpp"
#include <immintrin.h>

namespace Deep2Rom::Compute {

    // --- CRITICAL SPEED BOOST: VECTORIZED 16-CHANNEL SIMD LCG GENERATOR ---
    static inline __m512 vectorize_procedural_generator(__m512i& state) {
        __m512i mult = _mm512_set1_epi64(2862933555777941757ULL);
        __m512i add_v = _mm512_set_epi64(
            3037000493ULL, 43258941ULL, 987654321ULL, 123456789ULL,
            3037000493ULL, 43258941ULL, 987654321ULL, 123456789ULL
        );
        
        state = _mm512_add_epi64(_mm512_mul_epu32(state, mult), add_v);
        __m512i masked = _mm512_and_epi32(state, _mm512_set1_epi32(0x00FFFFFF));
        __m512 floats = _mm512_cvtepi32_ps(masked);
        return _mm512_fmsub_ps(floats, _mm512_set1_ps(1.1920929e-7f), _mm512_set1_ps(0.5f));
    }

    // --- CRITICAL SPEED BOOST: 4x DEEP LOOP UNROLLING KERNEL ---
    void execute_extreme_waaf_gemv(const float* __restrict hidden, float* __restrict logits, uint32_t cols, uint32_t start_r, uint32_t end_r, uint64_t seed) {
        for (uint32_t r = start_r; r < end_r; r += 4) {
            __m512 acc0 = _mm512_setzero_ps();
            __m512 acc1 = _mm512_setzero_ps();
            __m512 acc2 = _mm512_setzero_ps();
            __m512 acc3 = _mm512_setzero_ps();

            __m512i state0 = _mm512_set1_epi64(seed + r);
            __m512i state1 = _mm512_set1_epi64(seed + r + 1);
            __m512i state2 = _mm512_set1_epi64(seed + r + 2);
            __m512i state3 = _mm512_set1_epi64(seed + r + 3);

            for (uint32_t c = 0; c < cols; c += 16) {
                _mm_prefetch(reinterpret_cast<const char*>(hidden + c + 16), _MM_HINT_T0);
                __m512 v = _mm512_load_ps(hidden + c);
                
                acc0 = _mm512_fmadd_ps(vectorize_procedural_generator(state0), v, acc0);
                acc1 = _mm512_fmadd_ps(vectorize_procedural_generator(state1), v, acc1);
                acc2 = _mm512_fmadd_ps(vectorize_procedural_generator(state2), v, acc2);
                acc3 = _mm512_fmadd_ps(vectorize_procedural_generator(state3), v, acc3);
            }
            
            logits[r]     = _mm512_reduce_add_ps(acc0);
            logits[r + 1] = _mm512_reduce_add_ps(acc1);
            logits[r + 2] = _mm512_reduce_add_ps(acc2);
            logits[r + 3] = _mm512_reduce_add_ps(acc3);
        }
    }
}