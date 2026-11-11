// ============================================================================
// Quantized MatMul Benchmark
// ============================================================================
// Compares F32 vs Q8_0 vs Q4_K_M matrix multiplication performance
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <cmath>
#include <cstring>

using namespace std;

// ============================================================================
// Quantization Structures (simplified GGML format)
// ============================================================================

// Q8_0: 32 weights per block, 1 scale
struct Q8_0_Block {
    int8_t qs[32];
    float scale;
};

// Q4_K_M: 256 weights per block, 2 scales, packed 4-bit
struct Q4_K_M_Block {
    uint8_t qs[128];  // 256 nibbles packed
    float scale_1;
    float scale_2;
};

// ============================================================================
// Quantization Functions
// ============================================================================

void QuantizeQ8_0(const float* input, Q8_0_Block* output, uint32_t num_elements) {
    uint32_t num_blocks = (num_elements + 31) / 32;
    for (uint32_t b = 0; b < num_blocks; b++) {
        // Find max for scale
        float max_val = 0.0f;
        for (uint32_t i = 0; i < 32 && (b * 32 + i) < num_elements; i++) {
            max_val = max(max_val, fabsf(input[b * 32 + i]));
        }
        float scale = max_val / 127.0f;
        output[b].scale = scale;
        
        // Quantize
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
        // Find max for two scales (first 128, second 128)
        float max_1 = 0.0f, max_2 = 0.0f;
        for (uint32_t i = 0; i < 128 && (b * 256 + i) < num_elements; i++) {
            max_1 = max(max_1, fabsf(input[b * 256 + i]));
        }
        for (uint32_t i = 128; i < 256 && (b * 256 + i) < num_elements; i++) {
            max_2 = max(max_2, fabsf(input[b * 256 + i]));
        }
        
        output[b].scale_1 = max_1 / 7.0f;  // 4-bit range: -7 to 7
        output[b].scale_2 = max_2 / 7.0f;
        
        // Quantize and pack
        for (uint32_t i = 0; i < 128 && (b * 256 + i) < num_elements; i++) {
            float val = input[b * 256 + i];
            int q1 = (int)roundf(val / output[b].scale_1);
            q1 = max(-7, min(7, q1));
            
            val = input[b * 256 + i + 128];
            int q2 = (int)roundf(val / output[b].scale_2);
            q2 = max(-7, min(7, q2));
            
            // Pack two 4-bit values into one byte
            output[b].qs[i] = ((q2 + 7) << 4) | (q1 + 7);
        }
    }
}

// ============================================================================
// MatMul Functions
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

void MatMulQ8_0(const Q8_0_Block* A, const float* B, float* C,
                uint32_t M, uint32_t N, uint32_t K) {
    // A is quantized weights [K x M] (transposed for efficiency)
    // B is input [M x K] in F32
    // C is output [M x N]
    
    for (uint32_t m = 0; m < M; m++) {
        for (uint32_t n = 0; n < N; n++) {
            float sum = 0.0f;
            uint32_t k_blocks = K / 32;
            
            for (uint32_t kb = 0; kb < k_blocks; kb++) {
                const Q8_0_Block& block = A[kb * M + m];  // Weight block
                float scale = block.scale;
                
                for (uint32_t i = 0; i < 32; i++) {
                    float w = block.qs[i] * scale;  // Dequantize on-the-fly
                    sum += w * B[m * K + kb * 32 + i];
                }
            }
            C[m * N + n] = sum;
        }
    }
}

void MatMulQ4_K_M(const Q4_K_M_Block* A, const float* B, float* C,
                  uint32_t M, uint32_t N, uint32_t K) {
    for (uint32_t m = 0; m < M; m++) {
        for (uint32_t n = 0; n < N; n++) {
            float sum = 0.0f;
            uint32_t k_blocks = K / 256;
            
            for (uint32_t kb = 0; kb < k_blocks; kb++) {
                const Q4_K_M_Block& block = A[kb * M + m];
                
                // First 128 weights
                for (uint32_t i = 0; i < 128; i++) {
                    uint8_t packed = block.qs[i];
                    int q1 = (packed & 0x0F) - 7;  // Lower nibble
                    float w1 = q1 * block.scale_1;
                    sum += w1 * B[m * K + kb * 256 + i];
                    
                    int q2 = (packed >> 4) - 7;    // Upper nibble
                    float w2 = q2 * block.scale_2;
                    sum += w2 * B[m * K + kb * 256 + i + 128];
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
    cout << "Quantized MatMul Benchmark\n";
    cout << "========================================\n\n";
    
    // Configuration (1B model dimensions)
    uint32_t M = 1;      // Batch size (1 for autoregressive)
    uint32_t N = 2048;   // Output features
    uint32_t K = 2048;   // Input features
    uint32_t iterations = 1000;
    
    cout << "Configuration:\n";
    cout << "  M (batch): " << M << "\n";
    cout << "  N (output): " << N << "\n";
    cout << "  K (input): " << K << "\n";
    cout << "  Iterations: " << iterations << "\n\n";
    
    // Allocate buffers
    vector<float> A_f32(M * K, 0.01f);
    vector<float> B(K * N, 0.01f);
    vector<float> C_f32(M * N, 0.0f);
    vector<float> C_q8(M * N, 0.0f);
    vector<float> C_q4(M * N, 0.0f);
    
    // Quantize weights
    cout << "Quantizing weights...\n";
    vector<Q8_0_Block> A_q8((M * K + 31) / 32);
    vector<Q4_K_M_Block> A_q4((M * K + 255) / 256);
    
    QuantizeQ8_0(A_f32.data(), A_q8.data(), M * K);
    QuantizeQ4_K_M(A_f32.data(), A_q4.data(), M * K);
    
    // Memory usage
    size_t mem_f32 = A_f32.size() * sizeof(float);
    size_t mem_q8 = A_q8.size() * sizeof(Q8_0_Block);
    size_t mem_q4 = A_q4.size() * sizeof(Q4_K_M_Block);
    
    cout << "\nMemory Usage:\n";
    cout << "  F32: " << (mem_f32 / 1024.0) << " KB\n";
    cout << "  Q8_0: " << (mem_q8 / 1024.0) << " KB (" << (100.0 * mem_q8 / mem_f32) << "%)\n";
    cout << "  Q4_K_M: " << (mem_q4 / 1024.0) << " KB (" << (100.0 * mem_q4 / mem_f32) << "%)\n\n";
    
    // Warmup
    cout << "Warming up...\n";
    for (uint32_t i = 0; i < 100; i++) {
        MatMulF32(A_f32.data(), B.data(), C_f32.data(), M, N, K);
        MatMulQ8_0(A_q8.data(), B.data(), C_q8.data(), M, N, K);
        MatMulQ4_K_M(A_q4.data(), B.data(), C_q4.data(), M, N, K);
    }
    
    // Benchmark F32
    cout << "\nBenchmarking F32...\n";
    auto start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < iterations; i++) {
        MatMulF32(A_f32.data(), B.data(), C_f32.data(), M, N, K);
    }
    auto end = chrono::high_resolution_clock::now();
    double time_f32 = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    // Benchmark Q8_0
    cout << "Benchmarking Q8_0...\n";
    start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < iterations; i++) {
        MatMulQ8_0(A_q8.data(), B.data(), C_q8.data(), M, N, K);
    }
    end = chrono::high_resolution_clock::now();
    double time_q8 = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    // Benchmark Q4_K_M
    cout << "Benchmarking Q4_K_M...\n";
    start = chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < iterations; i++) {
        MatMulQ4_K_M(A_q4.data(), B.data(), C_q4.data(), M, N, K);
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
    
    // Per-matmul latency
    cout << "Per-matmul latency:\n";
    cout << "  F32:    " << (time_f32 / iterations * 1000) << " us\n";
    cout << "  Q8_0:   " << (time_q8 / iterations * 1000) << " us\n";
    cout << "  Q4_K_M: " << (time_q4 / iterations * 1000) << " us\n\n";
    
    // Projected tokens/sec (24 layers, 4 matmuls per layer)
    double matmuls_per_token = 24 * 4;  // q, k, v, o projections
    double tok_f32 = 1000.0 / ((time_f32 / iterations) * matmuls_per_token);
    double tok_q8 = 1000.0 / ((time_q8 / iterations) * matmuls_per_token);
    double tok_q4 = 1000.0 / ((time_q4 / iterations) * matmuls_per_token);
    
    cout << "Projected tokens/sec (24 layers):\n";
    cout << "  F32:    " << tok_f32 << " tok/s\n";
    cout << "  Q8_0:   " << tok_q8 << " tok/s\n";
    cout << "  Q4_K_M: " << tok_q4 << " tok/s\n\n";
    
    // Accuracy check
    float max_diff_q8 = 0.0f, max_diff_q4 = 0.0f;
    for (uint32_t i = 0; i < M * N; i++) {
        max_diff_q8 = max(max_diff_q8, fabsf(C_f32[i] - C_q8[i]));
        max_diff_q4 = max(max_diff_q4, fabsf(C_f32[i] - C_q4[i]));
    }
    cout << "Accuracy (max error vs F32):\n";
    cout << "  Q8_0:   " << max_diff_q8 << "\n";
    cout << "  Q4_K_M: " << max_diff_q4 << "\n\n";
    
    return 0;
}
