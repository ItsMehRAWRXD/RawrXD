// AVX2 SIMD kernel implementations
#include "avx2_kernels.h"

#ifdef GGUF_ENABLE_AVX2

#include <immintrin.h>
#include <cmath>
#include <cstring>

namespace RawrXD {

// CPU feature detection
bool cpu_has_avx2() {
    int cpuInfo[4];
#ifdef _MSC_VER
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 5)) != 0;  // EBX bit 5 = AVX2
#else
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
#endif
}

// AVX2 Q4_0 GEMM (8x8 tile)
void gemm_q4_0_avx2(const BlockQ4_0* A, const float* B, float* C,
                    int n, int k, int m) {
    const int TILE_SIZE = 32;  // Process 32 rows at a time
    
    for (int i = 0; i < n; i += TILE_SIZE) {
        for (int j = 0; j < m; j += 8) {
            // 8 accumulators for 8 output values
            __m256 acc = _mm256_setzero_ps();
            
            for (int kk = 0; kk < k; ++kk) {
                // Get block index for quantized weights
                int block_idx = (i * k + kk) / 32;
                const BlockQ4_0& block = A[block_idx];
                
                // Convert FP16 scale to FP32
                float scale = half_to_float(block.d);
                __m256 scale_vec = _mm256_set1_ps(scale);
                
                // Load 8 FP32 values from B
                __m256 b_vec = _mm256_loadu_ps(&B[kk * m + j]);
                
                // Dequantize 4-bit weights (simplified - processes 8 weights)
                // In real implementation, would unpack 4-bit nibbles
                float a_vals[8];
                for (int w = 0; w < 8; ++w) {
                    int byte_idx = w / 2;
                    int nibble = (w % 2 == 0) ? (block.qs[byte_idx] & 0xF) : (block.qs[byte_idx] >> 4);
                    // Dequantize: [-8, 7] range
                    a_vals[w] = ((float)nibble - 8.0f) * scale;
                }
                __m256 a_vec = _mm256_loadu_ps(a_vals);
                
                // FMA: acc += a * b
                acc = _mm256_fmadd_ps(a_vec, b_vec, acc);
            }
            
            // Store 8 results
            _mm256_storeu_ps(&C[i * m + j], acc);
        }
    }
}

// AVX2 RoPE rotation (8 floats at once)
void rope_rotate_8(float* x, int head_dim, int pos, const float* inv_freq) {
    __m256 pos_vec = _mm256_set1_ps(static_cast<float>(pos));
    
    for (int i = 0; i < head_dim; i += 8) {
        // Load 4 inverse frequencies (used for 8 floats due to cos/sin pairing)
        int freq_idx = i / 2;
        float freqs[4] = {
            inv_freq[freq_idx],
            inv_freq[freq_idx + 1],
            inv_freq[freq_idx + 2],
            inv_freq[freq_idx + 3]
        };
        
        // Compute angles: pos * inv_freq
        __m256 freq_vec = _mm256_setr_ps(
            freqs[0], freqs[0], freqs[1], freqs[1],
            freqs[2], freqs[2], freqs[3], freqs[3]
        );
        __m256 angle = _mm256_mul_ps(pos_vec, freq_vec);
        
        // Compute cos and sin (no native AVX2 cos/sin, use scalar)
        float angles[8], cos_vals[8], sin_vals[8];
        _mm256_storeu_ps(angles, angle);
        for (int j = 0; j < 8; ++j) {
            cos_vals[j] = std::cos(angles[j]);
            sin_vals[j] = std::sin(angles[j]);
        }
        __m256 cos_vec = _mm256_loadu_ps(cos_vals);
        __m256 sin_vec = _mm256_loadu_ps(sin_vals);
        
        // Load input values (pairs for rotation)
        __m256 v = _mm256_loadu_ps(&x[i]);
        
        // Rotate: separate even/odd indices
        // x_new[even] = x[even] * cos - x[odd] * sin
        // x_new[odd]  = x[even] * sin + x[odd] * cos
        
        // Shuffle to get [x0, x0, x2, x2, x4, x4, x6, x6]
        __m256 v_even = _mm256_shuffle_ps(v, v, _MM_SHUFFLE(2, 2, 0, 0));
        // Shuffle to get [x1, x1, x3, x3, x5, x5, x7, x7]
        __m256 v_odd = _mm256_shuffle_ps(v, v, _MM_SHUFFLE(3, 3, 1, 1));
        
        // Compute rotated values
        __m256 result = _mm256_sub_ps(
            _mm256_mul_ps(v_even, cos_vec),
            _mm256_mul_ps(v_odd, sin_vec)
        );
        
        // Store back (interleaved even/odd)
        _mm256_storeu_ps(&x[i], result);
    }
}

} // namespace RawrXD

#endif // GGUF_ENABLE_AVX2
