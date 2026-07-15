// ============================================================================
// AVX2 GEMM Kernels - Sovereign SREM Locality Module
// High-performance matrix multiplication for Q4_0/Q8_0 quantization
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// MSVC AVX2 intrinsics
#include <immintrin.h>

namespace rawrxd {
namespace kernels {

// ============================================================================
// SREM (Strided Register-Efficient Memory) Locality Module
// Optimized for L1/L2 cache residency and register pressure reduction
// ============================================================================

// Tile sizes optimized for 32KB L1 cache
constexpr size_t SREM_TILE_M = 64;  // Rows per tile
constexpr size_t SREM_TILE_N = 64;  // Cols per tile  
constexpr size_t SREM_TILE_K = 256; // Depth per tile

// AVX2 register width (256-bit = 8 floats)
constexpr size_t AVX2_FLOATS = 8;

// ============================================================================
// Q4_0 Block Structure (from GGML)
// 32 weights (4-bit) + 1 scale (float32) = 18 bytes per 32 elements
// ============================================================================
struct Q4_0Block {
    float scale;                    // Quantization scale
    uint8_t qs[32];                 // 32 nibbles (16 bytes)
};

// ============================================================================
// AVX2 GEMM - FP32 × FP32 (baseline)
// ============================================================================
inline void AVX2_Gemm_F32_F32(
    const float* A,                 // M × K matrix
    const float* B,                 // K × N matrix (column-major or row-major)
    float* C,                       // M × N output
    size_t M, size_t N, size_t K,
    bool B_transpose = false
) {
    // Process in tiles for cache locality
    for (size_t m0 = 0; m0 < M; m0 += SREM_TILE_M) {
        size_t m_max = (m0 + SREM_TILE_M < M) ? m0 + SREM_TILE_M : M;
        
        for (size_t n0 = 0; n0 < N; n0 += SREM_TILE_N) {
            size_t n_max = (n0 + SREM_TILE_N < N) ? n0 + SREM_TILE_N : N;
            
            // Initialize accumulator tile to zero
            float tile_C[SREM_TILE_M * SREM_TILE_N] = {};
            
            for (size_t k0 = 0; k0 < K; k0 += SREM_TILE_K) {
                size_t k_max = (k0 + SREM_TILE_K < K) ? k0 + SREM_TILE_K : K;
                
                // Micro-kernel: Process 8×8 blocks with AVX2
                for (size_t m = m0; m < m_max; m += AVX2_FLOATS) {
                    for (size_t n = n0; n < n_max; n += AVX2_FLOATS) {
                        
                        __m256 acc0 = _mm256_setzero_ps();
                        __m256 acc1 = _mm256_setzero_ps();
                        __m256 acc2 = _mm256_setzero_ps();
                        __m256 acc3 = _mm256_setzero_ps();
                        __m256 acc4 = _mm256_setzero_ps();
                        __m256 acc5 = _mm256_setzero_ps();
                        __m256 acc6 = _mm256_setzero_ps();
                        __m256 acc7 = _mm256_setzero_ps();
                        
                        // Inner loop over K
                        for (size_t k = k0; k < k_max; k++) {
                            // Load A row (8 floats)
                            __m256 a_vec = _mm256_loadu_ps(&A[m * K + k]);
                            
                            // Load B column (8 floats) - handle transpose
                            __m256 b_vec;
                            if (B_transpose) {
                                // B is row-major, need to gather
                                float b_vals[8];
                                for (size_t i = 0; i < 8 && (n + i) < n_max; i++) {
                                    b_vals[i] = B[(n + i) * K + k];
                                }
                                b_vec = _mm256_loadu_ps(b_vals);
                            } else {
                                b_vec = _mm256_loadu_ps(&B[k * N + n]);
                            }
                            
                            // FMA: acc += a * b
                            acc0 = _mm256_fmadd_ps(a_vec, b_vec, acc0);
                        }
                        
                        // Store results
                        for (size_t i = 0; i < 8 && (m + i) < m_max; i++) {
                            for (size_t j = 0; j < 8 && (n + j) < n_max; j++) {
                                C[(m + i) * N + (n + j)] += ((float*)&acc0)[i] * ((float*)&b_vec)[j];
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// AVX2 GEMM - Q4_0 × FP32 (dequantize on-the-fly)
// ============================================================================
inline void AVX2_Gemm_Q4_0_F32(
    const Q4_0Block* A_q4,          // M × K matrix in Q4_0 format
    const float* B,                 // K × N matrix (FP32)
    float* C,                       // M × N output
    size_t M, size_t N, size_t K
) {
    const size_t K_blocks = K / 32;  // 32 elements per Q4_0 block
    
    for (size_t m = 0; m < M; m++) {
        for (size_t n = 0; n < N; n++) {
            float sum = 0.0f;
            
            for (size_t kb = 0; kb < K_blocks; kb++) {
                const Q4_0Block& block = A_q4[m * K_blocks + kb];
                float scale = block.scale;
                
                // Process 32 quantized values
                for (size_t i = 0; i < 32; i += 8) {
                    // Dequantize 8 values using AVX2
                    __m256i qs = _mm256_loadu_si256((__m256i_u*)&block.qs[i]);
                    
                    // Extract nibbles and convert to floats
                    float deq[8];
                    for (size_t j = 0; j < 8; j++) {
                        uint8_t q = ((uint8_t*)&block.qs)[i + j];
                        int8_t q0 = (q & 0x0F) - 8;  // Lower nibble
                        int8_t q1 = (q >> 4) - 8;    // Upper nibble
                        
                        // Alternate between lower and upper
                        deq[j] = (j % 2 == 0) ? (q0 * scale) : (q1 * scale);
                    }
                    
                    __m256 a_vec = _mm256_loadu_ps(deq);
                    __m256 b_vec = _mm256_loadu_ps(&B[(kb * 32 + i) * N + n]);
                    
                    // Dot product
                    __m256 prod = _mm256_mul_ps(a_vec, b_vec);
                    
                    // Horizontal sum
                    prod = _mm256_hadd_ps(prod, prod);
                    prod = _mm256_hadd_ps(prod, prod);
                    
                    sum += _mm256_cvtss_f32(prod);
                }
            }
            
            C[m * N + n] = sum;
        }
    }
}

// ============================================================================
// AVX2 RMSNorm - In-place normalization
// ============================================================================
inline void AVX2_RMSNorm(
    float* data,                    // Input/output buffer
    const float* gamma,             // Scale parameters
    size_t num_elements,
    float epsilon = 1e-6f
) {
    // Compute RMS using AVX2
    __m256 sum_sq = _mm256_setzero_ps();
    
    size_t i = 0;
    for (; i + AVX2_FLOATS <= num_elements; i += AVX2_FLOATS) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        sum_sq = _mm256_fmadd_ps(vec, vec, sum_sq);
    }
    
    // Horizontal sum of sum_sq
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_sq);
    float total_sum = 0.0f;
    for (int j = 0; j < 8; j++) total_sum += sum_arr[j];
    
    // Remainder
    for (; i < num_elements; i++) {
        total_sum += data[i] * data[i];
    }
    
    float rms = std::sqrt(total_sum / num_elements + epsilon);
    float inv_rms = 1.0f / rms;
    
    // Apply normalization
    __m256 inv_rms_vec = _mm256_set1_ps(inv_rms);
    
    i = 0;
    for (; i + AVX2_FLOATS <= num_elements; i += AVX2_FLOATS) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        __m256 g_vec = _mm256_loadu_ps(&gamma[i]);
        
        vec = _mm256_mul_ps(vec, inv_rms_vec);
        vec = _mm256_mul_ps(vec, g_vec);
        
        _mm256_storeu_ps(&data[i], vec);
    }
    
    // Remainder
    for (; i < num_elements; i++) {
        data[i] = data[i] * inv_rms * gamma[i];
    }
}

// ============================================================================
// AVX2 SiLU Activation
// SiLU(x) = x * sigmoid(x)
// ============================================================================
inline void AVX2_SiLU(float* data, size_t num_elements) {
    const __m256 one = _mm256_set1_ps(1.0f);
    const __m256 neg_one = _mm256_set1_ps(-1.0f);
    
    size_t i = 0;
    for (; i + AVX2_FLOATS <= num_elements; i += AVX2_FLOATS) {
        __m256 x = _mm256_loadu_ps(&data[i]);
        
        // sigmoid(x) = 1 / (1 + exp(-x))
        __m256 neg_x = _mm256_mul_ps(x, neg_one);
        __m256 exp_neg_x = _mm256_exp_ps(neg_x);  // Note: need approximation
        __m256 denom = _mm256_add_ps(one, exp_neg_x);
        __m256 sigmoid = _mm256_div_ps(one, denom);
        
        // SiLU = x * sigmoid(x)
        __m256 result = _mm256_mul_ps(x, sigmoid);
        
        _mm256_storeu_ps(&data[i], result);
    }
    
    // Remainder - scalar fallback
    for (; i < num_elements; i++) {
        float x = data[i];
        float sigmoid = 1.0f / (1.0f + std::exp(-x));
        data[i] = x * sigmoid;
    }
}

// ============================================================================
// AVX2 Softmax
// ============================================================================
inline void AVX2_Softmax(float* data, size_t seq_len) {
    // Find max for numerical stability
    __m256 max_val = _mm256_set1_ps(-INFINITY);
    
    size_t i = 0;
    for (; i + AVX2_FLOATS <= seq_len; i += AVX2_FLOATS) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        max_val = _mm256_max_ps(max_val, vec);
    }
    
    float max_arr[8];
    _mm256_storeu_ps(max_arr, max_val);
    float max_scalar = max_arr[0];
    for (int j = 1; j < 8; j++) max_scalar = std::max(max_scalar, max_arr[j]);
    
    for (; i < seq_len; i++) {
        max_scalar = std::max(max_scalar, data[i]);
    }
    
    // Compute exp(x - max) and sum
    __m256 sum_exp = _mm256_setzero_ps();
    __m256 max_vec = _mm256_set1_ps(max_scalar);
    
    i = 0;
    for (; i + AVX2_FLOATS <= seq_len; i += AVX2_FLOATS) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_sub_ps(vec, max_vec);
        // Approximate exp using polynomial or table lookup
        // For now, scalar fallback in remainder
        _mm256_storeu_ps(&data[i], vec);
    }
    
    // Scalar exp and sum
    float sum = 0.0f;
    for (size_t j = 0; j < seq_len; j++) {
        data[j] = std::exp(data[j] - max_scalar);
        sum += data[j];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    __m256 inv_sum_vec = _mm256_set1_ps(inv_sum);
    
    i = 0;
    for (; i + AVX2_FLOATS <= seq_len; i += AVX2_FLOATS) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_mul_ps(vec, inv_sum_vec);
        _mm256_storeu_ps(&data[i], vec);
    }
    
    for (; i < seq_len; i++) {
        data[i] *= inv_sum;
    }
}

// ============================================================================
// Performance Benchmarking
// ============================================================================
struct GemmPerfMetrics {
    double gflops;
    double bandwidth_gbps;
    double time_ms;
    size_t total_ops;
    size_t total_bytes;
};

inline GemmPerfMetrics BenchmarkGemm(
    void (*gemm_func)(const float*, const float*, float*, size_t, size_t, size_t),
    size_t M, size_t N, size_t K,
    int iterations = 10
) {
    // Allocate aligned memory
    float* A = (float*)_aligned_malloc(M * K * sizeof(float), 32);
    float* B = (float*)_aligned_malloc(K * N * sizeof(float), 32);
    float* C = (float*)_aligned_malloc(M * N * sizeof(float), 32);
    
    // Initialize
    for (size_t i = 0; i < M * K; i++) A[i] = (float)(i % 100) / 100.0f;
    for (size_t i = 0; i < K * N; i++) B[i] = (float)(i % 100) / 100.0f;
    
    // Warmup
    for (int i = 0; i < 3; i++) {
        gemm_func(A, B, C, M, N, K);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        gemm_func(A, B, C, M, N, K);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    double time_ms = std::chrono::duration<double, std::milli>(end - start).count() / iterations;
    
    size_t ops = 2ULL * M * N * K;  // Multiply-adds
    size_t bytes = (M * K + K * N + M * N) * sizeof(float);
    
    double gflops = (ops / 1e9) / (time_ms / 1000.0);
    double bandwidth = (bytes / 1e9) / (time_ms / 1000.0);
    
    _aligned_free(A);
    _aligned_free(B);
    _aligned_free(C);
    
    return {gflops, bandwidth, time_ms, ops, bytes};
}

} // namespace kernels
} // namespace rawrxd
