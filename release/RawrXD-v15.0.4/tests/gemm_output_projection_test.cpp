/**
 * @file gemm_output_projection_test.cpp
 * @brief Phase 17: Output Projection GEMM Optimization
 * 
 * Optimizes the output projection kernel (47.3% of runtime):
 *   logits[vocab_size] = hidden[embed_dim] @ W[embed_dim][vocab_size]
 * 
 * Optimization Levels:
 *   1. Cache-friendly loop ordering
 *   2. Q4 dequantization fusion (future)
 *   3. SIMD vectorization (future)
 *   4. Multithreading (future)
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

using namespace std;

using Clock = chrono::high_resolution_clock;

// Configuration matching Phi-3-mini
const int EMBED_DIM = 3072;
const int VOCAB_SIZE = 32064;
const int NUM_ITERATIONS = 10;

// ============================================================================
// BASELINE: Scalar implementation (from Phase 16)
// ============================================================================
void output_projection_baseline(const float* hidden, const float* weights, 
                               float* logits, int embed_dim, int vocab_size) {
    // Baseline: i-j loop order (cache-unfriendly for row-major weights)
    for (int i = 0; i < vocab_size; i++) {
        float sum = 0.0f;
        for (int j = 0; j < embed_dim; j++) {
            // weights[i][j] = weights[i * embed_dim + j]
            sum += hidden[j] * weights[i * embed_dim + j];
        }
        logits[i] = sum;
    }
}

// ============================================================================
// OPTIMIZED Level 3: AVX2 SIMD vectorization
// ============================================================================
#include <immintrin.h>
#include <thread>
#include <vector>

void output_projection_avx2_single(const float* hidden, const float* weights,
                                    float* logits, int embed_dim, int start_i, int end_i) {
    const int SIMD_WIDTH = 8;
    
    for (int i = start_i; i < end_i; i++) {
        __m256 sum_vec = _mm256_setzero_ps();
        
        int j = 0;
        // Main SIMD loop
        for (; j <= embed_dim - SIMD_WIDTH; j += SIMD_WIDTH) {
            __m256 hidden_vec = _mm256_loadu_ps(&hidden[j]);
            __m256 weight_vec = _mm256_loadu_ps(&weights[i * embed_dim + j]);
            __m256 prod = _mm256_mul_ps(hidden_vec, weight_vec);
            sum_vec = _mm256_add_ps(sum_vec, prod);
        }
        
        // Horizontal sum
        float sum_array[8];
        _mm256_storeu_ps(sum_array, sum_vec);
        float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                    sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];
        
        // Remainder
        for (; j < embed_dim; j++) {
            sum += hidden[j] * weights[i * embed_dim + j];
        }
        
        logits[i] = sum;
    }
}

void output_projection_optimized_v1(const float* hidden, const float* weights,
                                     float* logits, int embed_dim, int vocab_size) {
    // Single-threaded AVX2 version for fair comparison
    output_projection_avx2_single(hidden, weights, logits, embed_dim, 0, vocab_size);
}

// ============================================================================
// OPTIMIZED Level 4: Multithreaded AVX2
// ============================================================================
const int NUM_THREADS = 8;  // Adjust based on CPU cores

void output_projection_multithreaded(const float* hidden, const float* weights,
                                     float* logits, int embed_dim, int vocab_size) {
    std::vector<std::thread> threads;
    int chunk_size = vocab_size / NUM_THREADS;
    
    for (int t = 0; t < NUM_THREADS; t++) {
        int start_i = t * chunk_size;
        int end_i = (t == NUM_THREADS - 1) ? vocab_size : (t + 1) * chunk_size;
        
        threads.emplace_back(output_projection_avx2_single, hidden, weights, logits,
                            embed_dim, start_i, end_i);
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

// ============================================================================
// Validation
// ============================================================================
struct ValidationResult {
    double max_absolute_error;
    double mean_absolute_error;
    double max_relative_error;
    bool passed;
};

ValidationResult validate_outputs(const float* reference, const float* optimized, 
                                     int size, double tolerance = 0.999) {
    ValidationResult result;
    result.max_absolute_error = 0.0;
    result.mean_absolute_error = 0.0;
    result.max_relative_error = 0.0;
    
    double sum_error = 0.0;
    int count = 0;
    
    for (int i = 0; i < size; i++) {
        double abs_error = fabs(optimized[i] - reference[i]);
        sum_error += abs_error;
        
        if (abs_error > result.max_absolute_error) {
            result.max_absolute_error = abs_error;
        }
        
        // Relative error (avoid division by zero)
        double ref_val = fabs(reference[i]);
        if (ref_val > 1e-6) {
            double rel_error = abs_error / ref_val;
            if (rel_error > result.max_relative_error) {
                result.max_relative_error = rel_error;
            }
        }
        
        count++;
    }
    
    result.mean_absolute_error = sum_error / count;
    result.passed = (result.max_absolute_error < tolerance);
    
    return result;
}

// ============================================================================
// Benchmark
// ============================================================================
struct BenchmarkResult {
    double time_ms;
    double throughput_tokens_per_sec;
};

BenchmarkResult benchmark(const char* name,
                            void (*func)(const float*, const float*, float*, int, int),
                            const float* hidden, const float* weights, float* logits,
                            int embed_dim, int vocab_size, int iterations) {
    // Warmup
    func(hidden, weights, logits, embed_dim, vocab_size);
    
    // Benchmark
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        func(hidden, weights, logits, embed_dim, vocab_size);
    }
    auto end = Clock::now();
    
    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double avg_ms = total_ms / iterations;
    
    BenchmarkResult result;
    result.time_ms = avg_ms;
    result.throughput_tokens_per_sec = 1000.0 / avg_ms;
    
    return result;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    cout << "🔬 RawrXD Phase 17: Output Projection GEMM Optimization\n";
    cout << "========================================================\n\n";
    
    cout << "Configuration:\n";
    cout << "  Embed dim: " << EMBED_DIM << "\n";
    cout << "  Vocab size: " << VOCAB_SIZE << "\n";
    cout << "  Iterations: " << NUM_ITERATIONS << "\n\n";
    
    // Allocate memory
    vector<float> hidden(EMBED_DIM);
    vector<float> weights(VOCAB_SIZE * EMBED_DIM);
    vector<float> logits_baseline(VOCAB_SIZE);
    vector<float> logits_optimized(VOCAB_SIZE);
    
    // Initialize with deterministic values
    cout << "[1/5] Initializing test data...\n";
    for (int j = 0; j < EMBED_DIM; j++) {
        hidden[j] = sinf(j * 0.01f) * 0.5f;
    }
    for (int i = 0; i < VOCAB_SIZE * EMBED_DIM; i++) {
        weights[i] = sinf(i * 0.001f) * 0.01f;
    }
    cout << "  ✓ Data initialized\n\n";
    
    // Step 1: Generate reference output
    cout << "[2/5] Generating reference output (baseline)...\n";
    output_projection_baseline(hidden.data(), weights.data(), logits_baseline.data(), 
                                EMBED_DIM, VOCAB_SIZE);
    cout << "  ✓ Reference logits generated\n";
    cout << "    Sample: ";
    for (int i = 0; i < min(5, VOCAB_SIZE); i++) {
        cout << fixed << setprecision(4) << logits_baseline[i] << " ";
    }
    cout << "\n\n";
    
    // Step 2: Generate optimized output
    cout << "[3/5] Generating optimized output...\n";
    output_projection_optimized_v1(hidden.data(), weights.data(), logits_optimized.data(),
                                    EMBED_DIM, VOCAB_SIZE);
    cout << "  ✓ Optimized logits generated\n";
    cout << "    Sample: ";
    for (int i = 0; i < min(5, VOCAB_SIZE); i++) {
        cout << fixed << setprecision(4) << logits_optimized[i] << " ";
    }
    cout << "\n\n";
    
    // Step 3: Validate correctness
    cout << "[4/5] Validating correctness...\n";
    ValidationResult validation = validate_outputs(logits_baseline.data(), logits_optimized.data(), 
                                                    VOCAB_SIZE, 0.999);
    
    cout << "  Validation Results:\n";
    cout << "    Max absolute error:  " << fixed << setprecision(6) << validation.max_absolute_error << "\n";
    cout << "    Mean absolute error: " << fixed << setprecision(6) << validation.mean_absolute_error << "\n";
    cout << "    Max relative error:  " << fixed << setprecision(6) << validation.max_relative_error << "\n";
    cout << "    Status: " << (validation.passed ? "✅ PASSED" : "❌ FAILED") << "\n\n";
    
    // Step 4: Benchmark
    cout << "[5/5] Benchmarking...\n\n";
    
    BenchmarkResult baseline_result = benchmark("Baseline", output_projection_baseline,
                                                hidden.data(), weights.data(), logits_baseline.data(),
                                                EMBED_DIM, VOCAB_SIZE, NUM_ITERATIONS);
    
    BenchmarkResult optimized_result = benchmark("AVX2 SIMD", output_projection_optimized_v1,
                                                  hidden.data(), weights.data(), logits_optimized.data(),
                                                  EMBED_DIM, VOCAB_SIZE, NUM_ITERATIONS);
    
    // Multithreaded benchmark
    vector<float> logits_mt(VOCAB_SIZE);
    
    // Warmup
    output_projection_multithreaded(hidden.data(), weights.data(), logits_mt.data(),
                                    EMBED_DIM, VOCAB_SIZE);
    
    // Benchmark multithreaded
    auto start_mt = Clock::now();
    for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
        output_projection_multithreaded(hidden.data(), weights.data(), logits_mt.data(),
                                        EMBED_DIM, VOCAB_SIZE);
    }
    auto end_mt = Clock::now();
    
    double total_mt_ms = chrono::duration_cast<chrono::microseconds>(end_mt - start_mt).count() / 1000.0;
    double avg_mt_ms = total_mt_ms / NUM_ITERATIONS;
    
    // Validate multithreaded result
    ValidationResult validation_mt = validate_outputs(logits_baseline.data(), logits_mt.data(), 
                                                    VOCAB_SIZE, 0.999);
    
    // Calculate speedups
    double speedup_simd = baseline_result.time_ms / optimized_result.time_ms;
    double speedup_mt = baseline_result.time_ms / avg_mt_ms;
    
    // Results table
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "BENCHMARK RESULTS\n";
    cout << "═══════════════════════════════════════════════════════════\n\n";
    
    cout << left << setw(20) << "Implementation";
    cout << right << setw(15) << "Time (ms)";
    cout << setw(15) << "Throughput";
    cout << setw(12) << "Speedup" << "\n";
    cout << string(62, '-') << "\n";
    
    cout << left << setw(20) << "Baseline (i-j)";
    cout << right << fixed << setprecision(2);
    cout << setw(15) << baseline_result.time_ms;
    cout << setw(14) << fixed << setprecision(2) << baseline_result.throughput_tokens_per_sec << " tok/s";
    cout << setw(12) << "1.00x" << "\n";
    
    cout << left << setw(20) << "AVX2 SIMD";
    cout << right << fixed << setprecision(2);
    cout << setw(15) << optimized_result.time_ms;
    cout << setw(14) << fixed << setprecision(2) << optimized_result.throughput_tokens_per_sec << " tok/s";
    cout << setw(11) << fixed << setprecision(2) << speedup_simd << "x" << "\n";
    
    cout << left << setw(20) << "AVX2 + " + to_string(NUM_THREADS) + " threads";
    cout << right << fixed << setprecision(2);
    cout << setw(15) << avg_mt_ms;
    cout << setw(14) << fixed << setprecision(2) << (1000.0 / avg_mt_ms) << " tok/s";
    cout << setw(11) << fixed << setprecision(2) << speedup_mt << "x" << "\n";
    
    cout << "\n" << string(62, '=') << "\n";
    
    // Summary
    cout << "\nSUMMARY\n";
    cout << "=======\n";
    cout << "Baseline latency:    " << fixed << setprecision(2) << baseline_result.time_ms << " ms/token\n";
    cout << "AVX2 SIMD latency:   " << fixed << setprecision(2) << optimized_result.time_ms << " ms/token\n";
    cout << "Multithread latency: " << fixed << setprecision(2) << avg_mt_ms << " ms/token\n";
    cout << "AVX2 Speedup:        " << fixed << setprecision(2) << speedup_simd << "x\n";
    cout << "Multithread Speedup: " << fixed << setprecision(2) << speedup_mt << "x\n";
    cout << "SIMD Correctness:    " << (validation.passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    cout << "MT Correctness:      " << (validation_mt.passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    
    if (validation.passed && validation_mt.passed && speedup_mt > 1.0) {
        cout << "\n✅ PHASE 17 LEVEL 4: OPTIMIZATION SUCCESSFUL\n";
        cout << "\nNext steps:\n";
        cout << "  - Level 5: Q4 dequantization fusion\n";
        cout << "  - Level 6: AVX-512 (if available)\n";
        return 0;
    } else {
        cout << "\n❌ Optimization did not meet criteria\n";
        return 1;
    }
}
