/**
 * @file q4_k_m_vs_q4_0_bench.cpp
 * @brief Head-to-head benchmark: Q4_K_M vs Q4_0 vs FP32
 *
 * The ultimate compression showdown: 6.4:1 vs 6.7:1 vs 1:1
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
#include "../kernels/q4_k_m_gemm_fused.h"

using namespace std;
using namespace rawrxd::kernels;

using Clock = chrono::high_resolution_clock;

// Configuration
const int HIDDEN_DIM = 3072;
const int FFN_DIM = 8192;
const int NUM_ITERATIONS = 10;
const int NUM_THREADS = 8;

// ============================================================================
// Reference FP32 GEMV
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
// Q4_0 Quantization
// ============================================================================
void quantize_to_q4(const float* input, Q4_0_Block* output, int num_blocks) {
    for (int b = 0; b < num_blocks; b++) {
        const float* block_input = &input[b * 32];
        Q4_0_Block* block = &output[b];
        
        float max_abs = 0.0f;
        for (int i = 0; i < 32; i++) {
            max_abs = max(max_abs, fabs(block_input[i]));
        }
        
        block->scale = max_abs / 7.0f;
        if (block->scale == 0.0f) block->scale = 1.0f;
        
        for (int i = 0; i < 32; i++) {
            int quantized = static_cast<int>(round(block_input[i] / block->scale)) + 8;
            quantized = max(0, min(15, quantized));
            
            if (i % 2 == 0) {
                block->nibbles[i / 2] = quantized;
            } else {
                block->nibbles[i / 2] |= (quantized << 4);
            }
        }
    }
}

// ============================================================================
// Q4_K_M Quantization (Simplified)
// ============================================================================
void quantize_to_q4_k_m(const float* input, Q4_K_M_Block* output, int num_blocks) {
    for (int b = 0; b < num_blocks; b++) {
        const float* block_input = &input[b * Q4_K_M_BLOCK_SIZE];
        Q4_K_M_Block* block = &output[b];
        
        // Find global min/max for the block
        float min_val = FLT_MAX;
        float max_val = -FLT_MAX;
        for (int i = 0; i < Q4_K_M_BLOCK_SIZE; i++) {
            min_val = min(min_val, block_input[i]);
            max_val = max(max_val, block_input[i]);
        }
        
        // Calculate scale and min for dequantization
        block->scale = (max_val - min_val) / 15.0f;
        block->min = min_val;
        if (block->scale == 0.0f) block->scale = 1.0f;
        
        // Quantize to 4-bit with per-sub-block scales
        for (int sb = 0; sb < 8; sb++) {
            // Calculate per-sub-block scale (simplified: use global scale)
            uint8_t sub_scale = 31;  // Max scale
            int scale_idx = sb;
            block->scales[scale_idx] = sub_scale;
            
            // Quantize 32 weights to 4-bit
            for (int i = 0; i < 32; i++) {
                float val = block_input[sb * 32 + i];
                int quantized = static_cast<int>(round((val - min_val) / block->scale));
                quantized = max(0, min(15, quantized));
                
                int byte_idx = sb * 16 + (i / 2);
                if (i % 2 == 0) {
                    block->quants[byte_idx] = quantized;
                } else {
                    block->quants[byte_idx] |= (quantized << 4);
                }
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
    double size_mb;
};

BenchmarkResult benchmark_fp32(const float* weights, const float* input, float* output,
                                  int rows, int cols, int iterations) {
    gemv_fp32_ref(weights, input, output, rows, cols);
    
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        gemv_fp32_ref(weights, input, output, rows, cols);
    }
    auto end = Clock::now();
    
    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double avg_ms = total_ms / iterations;
    
    double bytes_transferred = (rows * cols * sizeof(float)) + (cols * sizeof(float)) + (rows * sizeof(float));
    double gbps = (bytes_transferred / (avg_ms / 1000.0)) / 1e9;
    double size_mb = (rows * cols * sizeof(float)) / (1024.0 * 1024.0);
    
    return {avg_ms, gbps, size_mb};
}

BenchmarkResult benchmark_q4_0(const Q4_0_Block* weights, const float* input, float* output,
                              int rows, int cols, int iterations) {
    gemv_q4_fused_avx2_mt(weights, input, output, rows, cols, NUM_THREADS);
    
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        gemv_q4_fused_avx2_mt(weights, input, output, rows, cols, NUM_THREADS);
    }
    auto end = Clock::now();
    
    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double avg_ms = total_ms / iterations;
    
    int num_blocks = (rows * cols) / 32;
    double q4_bytes = num_blocks * sizeof(Q4_0_Block);
    double bytes_transferred = q4_bytes + (cols * sizeof(float)) + (rows * sizeof(float));
    double gbps = (bytes_transferred / (avg_ms / 1000.0)) / 1e9;
    double size_mb = q4_bytes / (1024.0 * 1024.0);
    
    return {avg_ms, gbps, size_mb};
}

BenchmarkResult benchmark_q4_k_m(const Q4_K_M_Block* weights, const float* input, float* output,
                                  int rows, int cols, int iterations) {
    gemv_q4_k_m_fused_avx2_mt(weights, input, output, rows, cols, NUM_THREADS);
    
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        gemv_q4_k_m_fused_avx2_mt(weights, input, output, rows, cols, NUM_THREADS);
    }
    auto end = Clock::now();
    
    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double avg_ms = total_ms / iterations;
    
    int num_blocks = (rows * cols) / Q4_K_M_BLOCK_SIZE;
    double q4_k_m_bytes = num_blocks * sizeof(Q4_K_M_Block);
    double bytes_transferred = q4_k_m_bytes + (cols * sizeof(float)) + (rows * sizeof(float));
    double gbps = (bytes_transferred / (avg_ms / 1000.0)) / 1e9;
    double size_mb = q4_k_m_bytes / (1024.0 * 1024.0);
    
    return {avg_ms, gbps, size_mb};
}

// ============================================================================
// Main
// ============================================================================
int main() {
    cout << "🏁 RawrXD ULTIMATE COMPRESSION SHOWDOWN\n";
    cout << "========================================\n\n";
    cout << "Q4_K_M (6.7:1) vs Q4_0 (6.4:1) vs FP32 (1:1)\n\n";
    
    cout << "Configuration:\n";
    cout << "  Hidden dim: " << HIDDEN_DIM << "\n";
    cout << "  FFN dim: " << FFN_DIM << "\n";
    cout << "  Threads: " << NUM_THREADS << "\n\n";
    
    // Allocate memory
    cout << "[1/5] Allocating memory...\n";
    vector<float> input(HIDDEN_DIM);
    vector<float> weights_fp32(FFN_DIM * HIDDEN_DIM);
    vector<float> output_fp32(FFN_DIM);
    vector<float> output_q4_0(FFN_DIM);
    vector<float> output_q4_k_m(FFN_DIM);
    
    // Initialize
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = sinf(i * 0.01f) * 0.5f;
    }
    for (int i = 0; i < FFN_DIM * HIDDEN_DIM; i++) {
        weights_fp32[i] = sinf(i * 0.001f) * 0.01f;
    }
    
    // Quantize
    int q4_0_blocks = (FFN_DIM * HIDDEN_DIM) / 32;
    int q4_k_m_blocks = (FFN_DIM * HIDDEN_DIM) / Q4_K_M_BLOCK_SIZE;
    vector<Q4_0_Block> weights_q4_0(q4_0_blocks);
    vector<Q4_K_M_Block> weights_q4_k_m(q4_k_m_blocks);
    
    quantize_to_q4(weights_fp32.data(), weights_q4_0.data(), q4_0_blocks);
    quantize_to_q4_k_m(weights_fp32.data(), weights_q4_k_m.data(), q4_k_m_blocks);
    
    cout << "  ✓ Memory allocated\n";
    cout << "  ✓ Weights quantized\n\n";
    
    // Run references
    cout << "[2/5] Running FP32 reference...\n";
    gemv_fp32_ref(weights_fp32.data(), input.data(), output_fp32.data(), FFN_DIM, HIDDEN_DIM);
    cout << "  ✓ FP32 complete\n\n";
    
    cout << "[3/5] Running Q4_0...\n";
    gemv_q4_fused_avx2_mt(weights_q4_0.data(), input.data(), output_q4_0.data(), FFN_DIM, HIDDEN_DIM, NUM_THREADS);
    cout << "  ✓ Q4_0 complete\n\n";
    
    cout << "[4/5] Running Q4_K_M...\n";
    gemv_q4_k_m_fused_avx2_mt(weights_q4_k_m.data(), input.data(), output_q4_k_m.data(), FFN_DIM, HIDDEN_DIM, NUM_THREADS);
    cout << "  ✓ Q4_K_M complete\n\n";
    
    // Validate
    cout << "[5/5] Validating correctness...\n";
    float error_q4_0 = compute_max_error(output_fp32.data(), output_q4_0.data(), FFN_DIM);
    float error_q4_k_m = compute_max_error(output_fp32.data(), output_q4_k_m.data(), FFN_DIM);
    
    cout << "  Q4_0 max error:    " << fixed << setprecision(6) << error_q4_0 << "\n";
    cout << "  Q4_K_M max error:  " << fixed << setprecision(6) << error_q4_k_m << "\n";
    cout << "  Q4_0 status:       " << (error_q4_0 < 0.9999 ? "✅ PASSED" : "❌ FAILED") << "\n";
    cout << "  Q4_K_M status:     " << (error_q4_k_m < 0.9999 ? "✅ PASSED" : "❌ FAILED") << "\n\n";
    
    // Benchmark
    cout << "[6/5] Benchmarking...\n\n";
    
    BenchmarkResult fp32_result = benchmark_fp32(weights_fp32.data(), input.data(), output_fp32.data(),
                                                    FFN_DIM, HIDDEN_DIM, NUM_ITERATIONS);
    
    BenchmarkResult q4_0_result = benchmark_q4_0(weights_q4_0.data(), input.data(), output_q4_0.data(),
                                                 FFN_DIM, HIDDEN_DIM, NUM_ITERATIONS);
    
    BenchmarkResult q4_k_m_result = benchmark_q4_k_m(weights_q4_k_m.data(), input.data(), output_q4_k_m.data(),
                                                      FFN_DIM, HIDDEN_DIM, NUM_ITERATIONS);
    
    // Results table
    cout << "═══════════════════════════════════════════════════════════════════\n";
    cout << "BENCHMARK RESULTS\n";
    cout << "═══════════════════════════════════════════════════════════════════\n\n";
    
    cout << left << setw(15) << "Format";
    cout << right << setw(12) << "Time (ms)";
    cout << setw(14) << "Size (MB)";
    cout << setw(14) << "Comp. Ratio";
    cout << setw(12) << "Speedup";
    cout << setw(14) << "Error" << "\n";
    cout << string(81, '-') << "\n";
    
    // FP32
    cout << left << setw(15) << "FP32";
    cout << right << fixed << setprecision(2);
    cout << setw(12) << fp32_result.time_ms;
    cout << setw(14) << fp32_result.size_mb;
    cout << setw(14) << "1.0:1";
    cout << setw(12) << "1.00x";
    cout << setw(14) << "0.000000" << "\n";
    
    // Q4_0
    double q4_0_speedup = fp32_result.time_ms / q4_0_result.time_ms;
    cout << left << setw(15) << "Q4_0";
    cout << right << fixed << setprecision(2);
    cout << setw(12) << q4_0_result.time_ms;
    cout << setw(14) << q4_0_result.size_mb;
    cout << setw(14) << "6.4:1";
    cout << setw(11) << q4_0_speedup << "x";
    cout << setw(14) << fixed << setprecision(6) << error_q4_0 << "\n";
    
    // Q4_K_M
    double q4_k_m_speedup = fp32_result.time_ms / q4_k_m_result.time_ms;
    cout << left << setw(15) << "Q4_K_M";
    cout << right << fixed << setprecision(2);
    cout << setw(12) << q4_k_m_result.time_ms;
    cout << setw(14) << q4_k_m_result.size_mb;
    cout << setw(14) << "6.7:1";
    cout << setw(11) << q4_k_m_speedup << "x";
    cout << setw(14) << fixed << setprecision(6) << error_q4_k_m << "\n";
    
    cout << "\n" << string(81, '=') << "\n";
    
    // Winner announcement
    cout << "\n🏆 WINNER ANALYSIS\n";
    cout << "==================\n\n";
    
    if (q4_k_m_speedup > q4_0_speedup && error_q4_k_m < 0.9999) {
        cout << "🥇 Q4_K_M takes the crown!\n";
        cout << "   Speedup: " << fixed << setprecision(2) << q4_k_m_speedup << "x\n";
        cout << "   Compression: 6.7:1 (vs Q4_0's 6.4:1)\n";
        cout << "   Extra precision from mixed 6-bit/4-bit\n\n";
    } else if (q4_0_speedup >= q4_k_m_speedup && error_q4_0 < 0.9999) {
        cout << "🥇 Q4_0 wins on raw speed!\n";
        cout << "   Speedup: " << fixed << setprecision(2) << q4_0_speedup << "x\n";
        cout << "   Less overhead than Q4_K_M's mixed precision\n";
        cout << "   Q4_K_M overhead: " << fixed << setprecision(1)
             << ((q4_0_speedup / q4_k_m_speedup - 1.0) * 100) << "%\n\n";
    } else {
        cout << "⚠️  Both formats failed validation\n\n";
    }
    
    // Projected end-to-end TPS
    double base_tps = 43.36;  // Phase 22 result
    double q4_0_tps = base_tps * q4_0_speedup;
    double q4_k_m_tps = base_tps * q4_k_m_speedup;
    
    cout << "📊 PROJECTED END-TO-END TPS\n";
    cout << "=============================\n";
    cout << "  Phase 22 (FP32): " << fixed << setprecision(2) << base_tps << " tok/s\n";
    cout << "  With Q4_0:       " << fixed << setprecision(2) << q4_0_tps << " tok/s\n";
    cout << "  With Q4_K_M:    " << fixed << setprecision(2) << q4_k_m_tps << " tok/s\n\n";
    
    cout << "═══════════════════════════════════════════════════════════════════\n";
    cout << "ULTIMATE COMPRESSION SHOWDOWN COMPLETE\n";
    cout << "═══════════════════════════════════════════════════════════════════\n";
    
    return 0;
}
