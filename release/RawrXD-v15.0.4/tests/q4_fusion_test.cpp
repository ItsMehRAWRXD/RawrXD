/**
 * @file q4_fusion_test.cpp
 * @brief Phase 23: Q4 Dequantization Fusion Test
 *
 * Validates fused Q4 GEMM against reference FP32 GEMM.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cfloat>
#include <algorithm>
#include <cstring>

#include "../kernels/gemm_avx2.h"
#include "../kernels/q4_gemm_fused.h"

using namespace std;
using namespace rawrxd::kernels;

using Clock = chrono::high_resolution_clock;

// Configuration
const int HIDDEN_DIM = 3072;
const int FFN_DIM = 8192;
const int NUM_ITERATIONS = 10;
const int NUM_THREADS = 8;

// ============================================================================
// Reference FP32 GEMV (from Phase 21)
// ============================================================================
void gemv_fp32_ref(const float* weights, const float* input, float* output,
                   int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        float sum = 0.0f;
        for (int j = 0; j < cols; j++) {
            sum += weights[i * cols + j] * input[j];
        }
        output[i] = sum;
    }
}

// ============================================================================
// Q4 Quantization
// ============================================================================
void quantize_to_q4(const float* input, Q4_0_Block* output, int num_blocks) {
    for (int b = 0; b < num_blocks; b++) {
        const float* block_input = &input[b * 32];
        Q4_0_Block* block = &output[b];
        
        // Find max abs value for scale
        float max_abs = 0.0f;
        for (int i = 0; i < 32; i++) {
            max_abs = max(max_abs, fabs(block_input[i]));
        }
        
        // Scale to fit in 4 bits (-8 to +7)
        block->scale = max_abs / 7.0f;
        if (block->scale == 0.0f) block->scale = 1.0f;
        
        // Quantize
        for (int i = 0; i < 32; i++) {
            int quantized = static_cast<int>(round(block_input[i] / block->scale)) + 8;
            quantized = max(0, min(15, quantized));  // Clamp to 4 bits
            
            // Pack nibbles
            if (i % 2 == 0) {
                block->nibbles[i / 2] = quantized;
            } else {
                block->nibbles[i / 2] |= (quantized << 4);
            }
        }
    }
}

// ============================================================================
// Validation
// ============================================================================
float compute_max_error(const float* a, const float* b, int size) {
    float max_error = 0.0f;
    for (int i = 0; i < size; i++) {
        float error = fabs(a[i] - b[i]);
        if (error > max_error) max_error = error;
    }
    return max_error;
}

// ============================================================================
// Benchmark
// ============================================================================
struct BenchmarkResult {
    double time_ms;
    double throughput_gbps;
};

BenchmarkResult benchmark_fp32(const float* weights, const float* input, float* output,
                                  int rows, int cols, int iterations) {
    // Warmup
    gemv_fp32_ref(weights, input, output, rows, cols);
    
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        gemv_fp32_ref(weights, input, output, rows, cols);
    }
    auto end = Clock::now();
    
    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double avg_ms = total_ms / iterations;
    
    // Memory traffic: read weights + read input + write output
    double bytes_transferred = (rows * cols * sizeof(float)) + (cols * sizeof(float)) + (rows * sizeof(float));
    double gbps = (bytes_transferred / (avg_ms / 1000.0)) / 1e9;
    
    return {avg_ms, gbps};
}

BenchmarkResult benchmark_q4_fused(const Q4_0_Block* weights, const float* input, float* output,
                                      int rows, int cols, int iterations) {
    // Warmup
    gemv_q4_fused_avx2_mt(weights, input, output, rows, cols, NUM_THREADS);
    
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        gemv_q4_fused_avx2_mt(weights, input, output, rows, cols, NUM_THREADS);
    }
    auto end = Clock::now();
    
    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double avg_ms = total_ms / iterations;
    
    // Memory traffic: read Q4 weights (4.5 bits/weight) + read input + write output
    int num_blocks = (rows * cols) / 32;
    double q4_bytes = num_blocks * sizeof(Q4_0_Block);
    double bytes_transferred = q4_bytes + (cols * sizeof(float)) + (rows * sizeof(float));
    double gbps = (bytes_transferred / (avg_ms / 1000.0)) / 1e9;
    
    return {avg_ms, gbps};
}

// ============================================================================
// Main
// ============================================================================
int main() {
    cout << "🔬 RawrXD Phase 23: Q4 Dequantization Fusion Test\n";
    cout << "===================================================\n\n";
    
    cout << "Configuration:\n";
    cout << "  Hidden dim: " << HIDDEN_DIM << "\n";
    cout << "  FFN dim: " << FFN_DIM << "\n";
    cout << "  Threads: " << NUM_THREADS << "\n\n";
    
    // Allocate memory
    cout << "[1/4] Allocating memory...\n";
    vector<float> input(HIDDEN_DIM);
    vector<float> weights_fp32(FFN_DIM * HIDDEN_DIM);
    vector<float> output_fp32(FFN_DIM);
    vector<float> output_q4(FFN_DIM);
    
    // Initialize with deterministic values
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = sinf(i * 0.01f) * 0.5f;
    }
    for (int i = 0; i < FFN_DIM * HIDDEN_DIM; i++) {
        weights_fp32[i] = sinf(i * 0.001f) * 0.01f;
    }
    
    // Quantize weights to Q4
    int num_blocks = (FFN_DIM * HIDDEN_DIM) / 32;
    vector<Q4_0_Block> weights_q4(num_blocks);
    quantize_to_q4(weights_fp32.data(), weights_q4.data(), num_blocks);
    
    cout << "  ✓ Memory allocated\n";
    cout << "  ✓ Weights quantized to Q4\n";
    cout << "    FP32 size: " << (FFN_DIM * HIDDEN_DIM * sizeof(float)) / (1024.0 * 1024.0) << " MB\n";
    cout << "    Q4 size:   " << (num_blocks * sizeof(Q4_0_Block)) / (1024.0 * 1024.0) << " MB\n";
    cout << "    Compression: " << fixed << setprecision(1)
         << (100.0 * num_blocks * sizeof(Q4_0_Block)) / (FFN_DIM * HIDDEN_DIM * sizeof(float)) << "%\n\n";
    
    // Step 1: FP32 reference
    cout << "[2/4] Running FP32 reference...\n";
    gemv_fp32_ref(weights_fp32.data(), input.data(), output_fp32.data(), FFN_DIM, HIDDEN_DIM);
    cout << "  ✓ FP32 reference complete\n";
    cout << "    Sample output: ";
    for (int i = 0; i < min(5, FFN_DIM); i++) {
        cout << fixed << setprecision(4) << output_fp32[i] << " ";
    }
    cout << "\n\n";
    
    // Step 2: Q4 fused
    cout << "[3/4] Running Q4 fused...\n";
    gemv_q4_fused_avx2_mt(weights_q4.data(), input.data(), output_q4.data(), FFN_DIM, HIDDEN_DIM, NUM_THREADS);
    cout << "  ✓ Q4 fused complete\n";
    cout << "    Sample output: ";
    for (int i = 0; i < min(5, FFN_DIM); i++) {
        cout << fixed << setprecision(4) << output_q4[i] << " ";
    }
    cout << "\n\n";
    
    // Step 3: Validate
    cout << "[4/4] Validating correctness...\n";
    float max_error = compute_max_error(output_fp32.data(), output_q4.data(), FFN_DIM);
    cout << "  Max absolute error: " << fixed << setprecision(6) << max_error << "\n";
    cout << "  Status: " << (max_error < 0.9999 ? "✅ PASSED" : "❌ FAILED") << "\n\n";
    
    // Step 4: Benchmark
    cout << "[5/4] Benchmarking...\n\n";
    
    BenchmarkResult fp32_result = benchmark_fp32(weights_fp32.data(), input.data(), output_fp32.data(),
                                                FFN_DIM, HIDDEN_DIM, NUM_ITERATIONS);
    
    BenchmarkResult q4_result = benchmark_q4_fused(weights_q4.data(), input.data(), output_q4.data(),
                                                    FFN_DIM, HIDDEN_DIM, NUM_ITERATIONS);
    
    // Results table
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "BENCHMARK RESULTS\n";
    cout << "═══════════════════════════════════════════════════════════\n\n";
    
    cout << left << setw(20) << "Implementation";
    cout << right << setw(15) << "Time (ms)";
    cout << setw(18) << "Bandwidth (GB/s)";
    cout << setw(12) << "Speedup" << "\n";
    cout << string(65, '-') << "\n";
    
    cout << left << setw(20) << "FP32";
    cout << right << fixed << setprecision(2);
    cout << setw(15) << fp32_result.time_ms;
    cout << setw(17) << fixed << setprecision(2) << fp32_result.throughput_gbps << " GB/s";
    cout << setw(12) << "1.00x" << "\n";
    
    double speedup = fp32_result.time_ms / q4_result.time_ms;
    cout << left << setw(20) << "Q4 Fused";
    cout << right << fixed << setprecision(2);
    cout << setw(15) << q4_result.time_ms;
    cout << setw(17) << fixed << setprecision(2) << q4_result.throughput_gbps << " GB/s";
    cout << setw(11) << fixed << setprecision(2) << speedup << "x" << "\n";
    
    cout << "\n" << string(65, '=') << "\n";
    
    // Summary
    cout << "\nSUMMARY\n";
    cout << "=======\n";
    cout << "Correctness:         " << (max_error < 0.9999 ? "✅ PASSED" : "❌ FAILED") << "\n";
    cout << "FP32 Time:           " << fixed << setprecision(2) << fp32_result.time_ms << " ms\n";
    cout << "Q4 Fused Time:       " << fixed << setprecision(2) << q4_result.time_ms << " ms\n";
    cout << "Speedup:             " << fixed << setprecision(2) << speedup << "x\n";
    cout << "Memory Reduction:    " << fixed << setprecision(1)
         << (100.0 * num_blocks * sizeof(Q4_0_Block)) / (FFN_DIM * HIDDEN_DIM * sizeof(float)) << "% of FP32\n";
    
    if (max_error < 0.9999 && speedup > 1.0) {
        cout << "\n✅ PHASE 23: Q4 FUSION SUCCESSFUL\n";
        cout << "   Fused Q4 dequantization reduces memory bandwidth.\n\n";
        return 0;
    } else {
        cout << "\n❌ Q4 fusion did not meet criteria\n";
        return 1;
    }
}
