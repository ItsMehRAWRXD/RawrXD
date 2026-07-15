// ============================================================================
// Quantized MatMul Benchmark with SIMD Optimization
// ============================================================================
// Uses AVX2 for parallel dequantization and multiply
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <immintrin.h>

using namespace std;

// ============================================================================
// Quantization Structures
// ============================================================================

struct Q8_0_Block {
    alignas(32) int8_t qs[32];
    float scale;
};

struct Q4_K_M_Block {
    alignas(32) uint8_t qs[128];
    float scale_1;
    float scale_2;
};

// ============================================================================
// Quantization
// ============================================================================

void QuantizeQ8_0(const float* input, Q8_0_Block* output, uint32_t num_elements) {
    uint32_t num_blocks = (num_elements + 31) / 32;
    for (uint32_t b = 0; b < num_blocks; b++) {
        float max_val = 0.0f;
        for (uint32_t i = 0; i < 32 && (b * 32 + i) < num_elements; i++) {
            max_val = max(max_val, fabsf(input[b * 32 + i]));
        }
        float scale = max_val / 127.0f;
        if (scale == 0.0f) scale = 1.0f;
        output[b].scale = scale;
        
        for (uint32_t i = 0; i < 32 && (b * 32 + i) < num_elements; i++) {
            float val = input[b * 32 + i];
            int8_t q = (int8_t)roundf(val / scale);
            output[b].qs[i] = q;
        }
    }
}

void QuantizeQ4_K_M(const float* input, Q4_K_M_Block* output, uint32_t num_elements) {
    uint32_t num_blocks = (num_elements + 255) / 256;
    for (uint32_t b = 0; b < num_blocks; b++) {
        float max_1 = 0.0f, max_2 = 0.0f;
        for (uint32_t i = 0; i < 128 && (b * 256 + i) < num_elements; i++) {
            max_1 = max(max_1, fabsf(input[b * 256 + i]));
        }
        for (uint32_t i = 128; i < 256 && (b * 256 + i) < num_elements; i++) {
            max_2 = max(max_2, fabsf(input[b * 256 + i]));
        }
        
        output[b].scale_1 = (max_1 > 0) ? max_1 / 7.0f : 1.0f;
        output[b].scale_2 = (max_2 > 0) ? max_2 / 7.0f : 1.0f;
        
        for (uint32_t i = 0; i < 128 && (b * 256 + i) < num_elements; i++) {
            float val = input[b * 256 + i];
            int q1 = (int)roundf(val / output[b].scale_1);
            q1 = max(-7, min(7, q1));
            
            val = input[b * 256 + i + 128];
            int q2 = (int)roundf(val / output[b].scale_2);
            q2 = max(-7, min(7, q2));
            
            output[b].qs[i] = ((q2 + 7) << 4) | (q1 + 7);
        }
    }
}

// ============================================================================
// Baseline F32 MatMul
// ============================================================================

void MatMulF32(const float* A, const float* B, float* C,
               uint32_t M, uint32_t N, uint32_t K) {
    for (uint32_t m = 0; m < M; m++) {
        for (uint32_t n = 0; n < N; n++) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < K; k++) {
                sum += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = sum;
        }
    }
}

// ============================================================================
// SIMD-Optimized Q8_0 MatMul
// ============================================================================

void MatMulQ8_0_SIMD(const Q8_0_Block* A, const float* B, float* C,
                     uint32_t M, uint32_t N, uint32_t K) {
    for (uint32_t m = 0; m < M; m++) {
        for (uint32_t n = 0; n < N; n++) {
            __m256 sum_vec = _mm256_setzero_ps();
            uint32_t k_blocks = K / 32;
            
            for (uint32_t kb = 0; kb < k_blocks; kb++) {
                const Q8_0_Block& block = A[kb * M + m];
                
                // Load 8 quantized weights at a time
                for (uint32_t i = 0; i < 32; i += 8) {
                    // Load quantized values
                    int32_t q_vals[8];
                    for (uint32_t j = 0; j < 8; j++) {
                        q_vals[j] = (int32_t)block.qs[i + j];
                    }
                    
                    // Convert to float and dequantize
                    __m256 q_vec = _mm256_cvtepi32_ps(_mm256_setr_epi32(
                        q_vals[0], q_vals[1], q_vals[2], q_vals[3],
                        q_vals[4], q_vals[5], q_vals[6], q_vals[7]
                    ));
                    __m256 scale_vec = _mm256_set1_ps(block.scale);
                    __m256 w_vec = _mm256_mul_ps(q_vec, scale_vec);
                    
                    // Load activations
                    __m256 a_vec = _mm256_loadu_ps(&B[(kb * 32 + i) * N + n]);
                    
                    // Multiply and accumulate
                    sum_vec = _mm256_fmadd_ps(w_vec, a_vec, sum_vec);
                }
            }
            
            // Horizontal sum
            float sum = 0.0f;
            float temp[8];
            _mm256_storeu_ps(temp, sum_vec);
            for (int i = 0; i < 8; i++) sum += temp[i];
            C[m * N + n] = sum;
        }
    }
}

// ============================================================================
// Optimized Q4_K_M MatMul (scalar with prefetching)
// ============================================================================

void MatMulQ4_K_M_Opt(const Q4_K_M_Block* A, const float* B, float* C,
                      uint32_t M, uint32_t N, uint32_t K) {
    for (uint32_t m = 0; m < M; m++) {
        for (uint32_t n = 0; n < N; n++) {
            float sum = 0.0f;
            uint32_t k_blocks = K / 256;
            
            for (uint32_t kb = 0; kb < k_blocks; kb++) {
                const Q4_K_M_Block& block = A[kb * M + m];
                
                // Prefetch next block
                if (kb + 1 < k_blocks) {
                    _mm_prefetch((const char*)&A[(kb + 1) * M + m], _MM_HINT_T0);
                }
                
                // Process 128 packed values
                for (uint32_t i = 0; i < 128; i += 4) {
                    uint8_t packed[4];
                    for (uint32_t j = 0; j < 4; j++) packed[j] = block.qs[i + j];
                    
                    // Unpack and dequantize 4 values at a time
                    for (uint32_t j = 0; j < 4; j++) {
                        int q1 = (packed[j] & 0x0F) - 7;
                        float w1 = q1 * block.scale_1;
                        sum += w1 * B[(kb * 256 + i + j) * N + n];
                        
                        int q2 = (packed[j] >> 4) - 7;
                        float w2 = q2 * block.scale_2;
                        sum += w2 * B[(kb * 256 + i + j + 128) * N + n];
                    }
                }
            }
            C[m * N + n] = sum;
        }
    }
}

// ============================================================================
// Benchmark
// ============================================================================
int main() {
    cout << "========================================\n";
    cout << "Quantized MatMul Benchmark (SIMD)\n";
    cout << "========================================\n\n";
    
    // Configuration
    uint32_t M = 1;
    uint32_t N = 2048;
    uint32_t K = 2048;
    uint32_t iterations = 1000;
    
    cout << "Configuration:\n";
    cout << "  M: " << M << ", N: " << N << ", K: " << K << "\n";
    cout << "  Iterations: " << iterations << "\n\n";
    
    // Allocate
    vector<float> A_f32(M * K, 0.01f);
    vector<float> B(K * N, 0.01f);
    vector<float> C_f32(M * N, 0.0f);
    vector<float> C_q8(M * N, 0.0f);
    vector<float> C_q4(M * N, 0.0f);
    
    // Quantize
    cout << "Quantizing...\n";
    vector<Q8_0_Block> A_q8((M * K + 31) / 32);
    vector<Q4_K_M_Block> A_q4((M * K + 255) / 256);
    
    QuantizeQ8_0(A_f32.data(), A_q8.data(), M * K);
    QuantizeQ4_K_M(A_f32.data(), A_q4.data(), M * K);
    
    // Memory
    size_t mem_f32 = A_f32.size() * sizeof(float);
    size_t mem_q8 = A_q8.size() * sizeof(Q8_0_Block);
    size_t mem_q4 = A_q4.size() * sizeof(Q4_K_M_Block);
    
    cout << "\nMemory:\n";
    cout << "  F32: " << (mem_f32 / 1024.0) << " KB\n";
    cout << "  Q8_0: " << (mem_q8 / 1024.0) << " KB (" << (100.0 * mem_q8 / mem_f32) << "%)\n";
    cout << "  Q4_K_M: " << (mem_q4 / 1024.0) << " KB (" << (100.0 * mem_q4 / mem_f32) << "%)\n\n";
    
    // Warmup
    cout << "Warming up...\n";
    for (uint32_t i = 0; i < 100; i++) {
        MatMulF32(A_f32.data(), B.data(), C_f32.data(), M, N, K);
        MatMulQ8_0_SIMD(A_q8.data(), B.data(), C_q8.data(), M, N, K);
        MatMulQ4_K_M_Opt(A_q4.data(), B.data(), C_q4.data(), M, N, K);
    }
    
    // Benchmark
    cout << "\nBenchmarking...\n";
    
    auto start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < iterations; i++) {
        MatMulF32(A_f32.data(), B.data(), C_f32.data(), M, N, K);
    }
    auto end = chrono::high_resolution_clock::now();
    double time_f32 = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < iterations; i++) {
        MatMulQ8_0_SIMD(A_q8.data(), B.data(), C_q8.data(), M, N, K);
    }
    end = chrono::high_resolution_clock::now();
    double time_q8 = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < iterations; i++) {
        MatMulQ4_K_M_Opt(A_q4.data(), B.data(), C_q4.data(), M, N, K);
    }
    end = chrono::high_resolution_clock::now();
    double time_q4 = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    // Results
    cout << "\n========================================\n";
    cout << "Results\n";
    cout << "========================================\n";
    cout << fixed << setprecision(2);
    cout << "  F32:      " << time_f32 << " ms\n";
    cout << "  Q8_0:     " << time_q8 << " ms\n";
    cout << "  Q4_K_M:   " << time_q4 << " ms\n\n";
    
    cout << "Speedup vs F32:\n";
    cout << "  Q8_0:   " << (time_f32 / time_q8) << "x\n";
    cout << "  Q4_K_M: " << (time_f32 / time_q4) << "x\n\n";
    
    // Projected tok/s
    double matmuls = 24 * 4;
    double tok_f32 = 1000.0 / ((time_f32 / iterations) * matmuls);
    double tok_q8 = 1000.0 / ((time_q8 / iterations) * matmuls);
    double tok_q4 = 1000.0 / ((time_q4 / iterations) * matmuls);
    
    cout << "Projected tokens/sec:\n";
    cout << "  F32:    " << tok_f32 << " tok/s\n";
    cout << "  Q8_0:   " << tok_q8 << " tok/s\n";
    cout << "  Q4_K_M: " << tok_q4 << " tok/s\n\n";
    
    return 0;
}
