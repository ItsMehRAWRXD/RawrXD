/**
 * @file ffn_optimization_test.cpp
 * @brief Phase 18: FFN/SwiGLU Optimization
 * 
 * Optimizes the FFN/SwiGLU kernel (38.3% of runtime post-Phase 17):
 *   gate = SiLU(W_gate * x)
 *   up   = W_up * x  
 *   out  = W_down * (gate * up)
 * 
 * Optimization Levels:
 *   1. Loop ordering analysis
 *   2. AVX2 SIMD vectorization
 *   3. Multithreading
 *   4. Q4 dequantization fusion (future)
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
#include <thread>
#include <immintrin.h>

using namespace std;

using Clock = chrono::high_resolution_clock;

// Configuration matching Phi-3-mini
const int HIDDEN_DIM = 3072;
const int FFN_DIM = 8192;
const int NUM_ITERATIONS = 10;
const int NUM_THREADS = 8;

// ============================================================================
// Activation Functions
// ============================================================================
inline float silu(float x) {
    // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
    return x / (1.0f + expf(-x));
}

// ============================================================================
// BASELINE: Scalar FFN implementation
// ============================================================================
void ffn_baseline(const float* input, 
                  const float* w_gate, const float* w_up, const float* w_down,
                  float* output,
                  int hidden_dim, int ffn_dim) {
    // Temporary buffers
    vector<float> gate(ffn_dim);
    vector<float> up(ffn_dim);
    vector<float> fused(ffn_dim);
    
    // Step 1: Gate projection + SiLU
    for (int i = 0; i < ffn_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < hidden_dim; j++) {
            sum += w_gate[i * hidden_dim + j] * input[j];
        }
        gate[i] = silu(sum);
    }
    
    // Step 2: Up projection
    for (int i = 0; i < ffn_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < hidden_dim; j++) {
            sum += w_up[i * hidden_dim + j] * input[j];
        }
        up[i] = sum;
    }
    
    // Step 3: Element-wise multiply (gate * up)
    for (int i = 0; i < ffn_dim; i++) {
        fused[i] = gate[i] * up[i];
    }
    
    // Step 4: Down projection
    for (int i = 0; i < hidden_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < ffn_dim; j++) {
            sum += w_down[i * ffn_dim + j] * fused[j];
        }
        output[i] = sum;
    }
}

// ============================================================================
// OPTIMIZED Level 2: AVX2 SIMD
// ============================================================================
inline __m256 silu_avx2(__m256 x) {
    // SiLU(x) = x * sigmoid(x)
    // sigmoid(x) = 1 / (1 + exp(-x))
    __m256 neg_x = _mm256_sub_ps(_mm256_setzero_ps(), x);
    __m256 exp_neg_x = _mm256_set_ps(
        expf(-((float*)&neg_x)[7]), expf(-((float*)&neg_x)[6]),
        expf(-((float*)&neg_x)[5]), expf(-((float*)&neg_x)[4]),
        expf(-((float*)&neg_x)[3]), expf(-((float*)&neg_x)[2]),
        expf(-((float*)&neg_x)[1]), expf(-((float*)&neg_x)[0])
    );
    __m256 one = _mm256_set1_ps(1.0f);
    __m256 sigmoid = _mm256_div_ps(one, _mm256_add_ps(one, exp_neg_x));
    return _mm256_mul_ps(x, sigmoid);
}

void gemv_avx2(const float* weights, const float* input, float* output,
               int rows, int cols) {
    const int SIMD_WIDTH = 8;
    
    for (int i = 0; i < rows; i++) {
        __m256 sum_vec = _mm256_setzero_ps();
        
        int j = 0;
        for (; j <= cols - SIMD_WIDTH; j += SIMD_WIDTH) {
            __m256 w_vec = _mm256_loadu_ps(&weights[i * cols + j]);
            __m256 x_vec = _mm256_loadu_ps(&input[j]);
            __m256 prod = _mm256_mul_ps(w_vec, x_vec);
            sum_vec = _mm256_add_ps(sum_vec, prod);
        }
        
        // Horizontal sum
        float sum_array[8];
        _mm256_storeu_ps(sum_array, sum_vec);
        float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                    sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];
        
        // Remainder
        for (; j < cols; j++) {
            sum += weights[i * cols + j] * input[j];
        }
        
        output[i] = sum;
    }
}

void ffn_avx2(const float* input, 
              const float* w_gate, const float* w_up, const float* w_down,
              float* output,
              int hidden_dim, int ffn_dim) {
    // Temporary buffers
    vector<float> gate(ffn_dim);
    vector<float> up(ffn_dim);
    vector<float> fused(ffn_dim);
    
    // Step 1: Gate projection (AVX2)
    gemv_avx2(w_gate, input, gate.data(), ffn_dim, hidden_dim);
    
    // Apply SiLU to gate (scalar - could be vectorized)
    for (int i = 0; i < ffn_dim; i++) {
        gate[i] = silu(gate[i]);
    }
    
    // Step 2: Up projection (AVX2)
    gemv_avx2(w_up, input, up.data(), ffn_dim, hidden_dim);
    
    // Step 3: Element-wise multiply (AVX2)
    int i = 0;
    for (; i <= ffn_dim - 8; i += 8) {
        __m256 g = _mm256_loadu_ps(&gate[i]);
        __m256 u = _mm256_loadu_ps(&up[i]);
        __m256 f = _mm256_mul_ps(g, u);
        _mm256_storeu_ps(&fused[i], f);
    }
    for (; i < ffn_dim; i++) {
        fused[i] = gate[i] * up[i];
    }
    
    // Step 4: Down projection (AVX2)
    gemv_avx2(w_down, fused.data(), output, hidden_dim, ffn_dim);
}

// ============================================================================
// OPTIMIZED Level 3: Multithreaded AVX2
// ============================================================================
void gemv_avx2_mt_worker(const float* weights, const float* input, float* output,
                         int cols, int start_row, int end_row) {
    const int SIMD_WIDTH = 8;
    
    for (int i = start_row; i < end_row; i++) {
        __m256 sum_vec = _mm256_setzero_ps();
        
        int j = 0;
        for (; j <= cols - SIMD_WIDTH; j += SIMD_WIDTH) {
            __m256 w_vec = _mm256_loadu_ps(&weights[i * cols + j]);
            __m256 x_vec = _mm256_loadu_ps(&input[j]);
            __m256 prod = _mm256_mul_ps(w_vec, x_vec);
            sum_vec = _mm256_add_ps(sum_vec, prod);
        }
        
        float sum_array[8];
        _mm256_storeu_ps(sum_array, sum_vec);
        float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                    sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];
        
        for (; j < cols; j++) {
            sum += weights[i * cols + j] * input[j];
        }
        
        output[i] = sum;
    }
}

void gemv_avx2_mt(const float* weights, const float* input, float* output,
                  int rows, int cols, int num_threads) {
    vector<thread> threads;
    int chunk_size = rows / num_threads;
    
    for (int t = 0; t < num_threads; t++) {
        int start_row = t * chunk_size;
        int end_row = (t == num_threads - 1) ? rows : (t + 1) * chunk_size;
        threads.emplace_back(gemv_avx2_mt_worker, weights, input, output,
                            cols, start_row, end_row);
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

void ffn_avx2_mt(const float* input, 
                 const float* w_gate, const float* w_up, const float* w_down,
                 float* output,
                 int hidden_dim, int ffn_dim, int num_threads) {
    // Temporary buffers
    vector<float> gate(ffn_dim);
    vector<float> up(ffn_dim);
    vector<float> fused(ffn_dim);
    
    // Step 1: Gate projection (MT + AVX2)
    gemv_avx2_mt(w_gate, input, gate.data(), ffn_dim, hidden_dim, num_threads);
    
    // Apply SiLU to gate
    for (int i = 0; i < ffn_dim; i++) {
        gate[i] = silu(gate[i]);
    }
    
    // Step 2: Up projection (MT + AVX2)
    gemv_avx2_mt(w_up, input, up.data(), ffn_dim, hidden_dim, num_threads);
    
    // Step 3: Element-wise multiply (AVX2)
    int i = 0;
    for (; i <= ffn_dim - 8; i += 8) {
        __m256 g = _mm256_loadu_ps(&gate[i]);
        __m256 u = _mm256_loadu_ps(&up[i]);
        __m256 f = _mm256_mul_ps(g, u);
        _mm256_storeu_ps(&fused[i], f);
    }
    for (; i < ffn_dim; i++) {
        fused[i] = gate[i] * up[i];
    }
    
    // Step 4: Down projection (MT + AVX2)
    gemv_avx2_mt(w_down, fused.data(), output, hidden_dim, ffn_dim, num_threads);
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
                            void (*func)(const float*, const float*, const float*, 
                                        const float*, float*, int, int),
                            const float* input,
                            const float* w_gate, const float* w_up, const float* w_down,
                            float* output,
                            int hidden_dim, int ffn_dim, int iterations) {
    // Warmup
    func(input, w_gate, w_up, w_down, output, hidden_dim, ffn_dim);
    
    // Benchmark
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        func(input, w_gate, w_up, w_down, output, hidden_dim, ffn_dim);
    }
    auto end = Clock::now();
    
    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    double avg_ms = total_ms / iterations;
    
    BenchmarkResult result;
    result.time_ms = avg_ms;
    result.throughput_tokens_per_sec = 1000.0 / avg_ms;
    
    return result;
}

BenchmarkResult benchmark_mt(const char* name,
                              void (*func)(const float*, const float*, const float*, 
                                         const float*, float*, int, int, int),
                              const float* input,
                              const float* w_gate, const float* w_up, const float* w_down,
                              float* output,
                              int hidden_dim, int ffn_dim, int num_threads, int iterations) {
    // Warmup
    func(input, w_gate, w_up, w_down, output, hidden_dim, ffn_dim, num_threads);
    
    // Benchmark
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        func(input, w_gate, w_up, w_down, output, hidden_dim, ffn_dim, num_threads);
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
    cout << "🔬 RawrXD Phase 18: FFN/SWiGLU Optimization\n";
    cout << "=============================================\n\n";
    
    cout << "Configuration:\n";
    cout << "  Hidden dim: " << HIDDEN_DIM << "\n";
    cout << "  FFN dim: " << FFN_DIM << "\n";
    cout << "  Iterations: " << NUM_ITERATIONS << "\n";
    cout << "  Threads: " << NUM_THREADS << "\n\n";
    
    // Allocate memory
    cout << "[1/5] Allocating memory...\n";
    vector<float> input(HIDDEN_DIM);
    vector<float> w_gate(FFN_DIM * HIDDEN_DIM);
    vector<float> w_up(FFN_DIM * HIDDEN_DIM);
    vector<float> w_down(HIDDEN_DIM * FFN_DIM);
    vector<float> output_baseline(HIDDEN_DIM);
    vector<float> output_avx2(HIDDEN_DIM);
    vector<float> output_mt(HIDDEN_DIM);
    
    // Initialize with deterministic values
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = sinf(i * 0.01f) * 0.5f;
    }
    for (int i = 0; i < FFN_DIM * HIDDEN_DIM; i++) {
        w_gate[i] = sinf(i * 0.001f) * 0.01f;
        w_up[i] = cosf(i * 0.001f) * 0.01f;
    }
    for (int i = 0; i < HIDDEN_DIM * FFN_DIM; i++) {
        w_down[i] = sinf(i * 0.0005f) * 0.01f;
    }
    cout << "  ✓ Memory allocated and initialized\n\n";
    
    // Step 1: Generate reference output
    cout << "[2/5] Generating reference output (baseline)...\n";
    ffn_baseline(input.data(), w_gate.data(), w_up.data(), w_down.data(),
                 output_baseline.data(), HIDDEN_DIM, FFN_DIM);
    cout << "  ✓ Reference output generated\n";
    cout << "    Sample: ";
    for (int i = 0; i < min(5, HIDDEN_DIM); i++) {
        cout << fixed << setprecision(4) << output_baseline[i] << " ";
    }
    cout << "\n\n";
    
    // Step 2: Generate AVX2 output
    cout << "[3/5] Generating AVX2 output...\n";
    ffn_avx2(input.data(), w_gate.data(), w_up.data(), w_down.data(),
             output_avx2.data(), HIDDEN_DIM, FFN_DIM);
    cout << "  ✓ AVX2 output generated\n";
    cout << "    Sample: ";
    for (int i = 0; i < min(5, HIDDEN_DIM); i++) {
        cout << fixed << setprecision(4) << output_avx2[i] << " ";
    }
    cout << "\n\n";
    
    // Step 3: Validate correctness
    cout << "[4/5] Validating correctness...\n";
    ValidationResult validation_avx2 = validate_outputs(output_baseline.data(), output_avx2.data(), 
                                                        HIDDEN_DIM, 0.999);
    
    cout << "  AVX2 Validation:\n";
    cout << "    Max absolute error:  " << fixed << setprecision(6) << validation_avx2.max_absolute_error << "\n";
    cout << "    Mean absolute error: " << fixed << setprecision(6) << validation_avx2.mean_absolute_error << "\n";
    cout << "    Max relative error:  " << fixed << setprecision(6) << validation_avx2.max_relative_error << "\n";
    cout << "    Status: " << (validation_avx2.passed ? "✅ PASSED" : "❌ FAILED") << "\n\n";
    
    // Step 4: Benchmark
    cout << "[5/5] Benchmarking...\n\n";
    
    BenchmarkResult baseline_result = benchmark("Baseline", ffn_baseline,
                                                input.data(), w_gate.data(), w_up.data(), w_down.data(),
                                                output_baseline.data(), HIDDEN_DIM, FFN_DIM, NUM_ITERATIONS);
    
    BenchmarkResult avx2_result = benchmark("AVX2 SIMD", ffn_avx2,
                                              input.data(), w_gate.data(), w_up.data(), w_down.data(),
                                              output_avx2.data(), HIDDEN_DIM, FFN_DIM, NUM_ITERATIONS);
    
    string mt_name = "AVX2 + " + to_string(NUM_THREADS) + " threads";
    BenchmarkResult mt_result = benchmark_mt(mt_name.c_str(), ffn_avx2_mt,
                                             input.data(), w_gate.data(), w_up.data(), w_down.data(),
                                             output_mt.data(), HIDDEN_DIM, FFN_DIM, NUM_THREADS, NUM_ITERATIONS);
    
    // Validate multithreaded result
    ValidationResult validation_mt = validate_outputs(output_baseline.data(), output_mt.data(), 
                                                      HIDDEN_DIM, 0.999);
    
    // Calculate speedups
    double speedup_avx2 = baseline_result.time_ms / avx2_result.time_ms;
    double speedup_mt = baseline_result.time_ms / mt_result.time_ms;
    
    // Results table
    cout << "═══════════════════════════════════════════════════════════\n";
    cout << "BENCHMARK RESULTS\n";
    cout << "═══════════════════════════════════════════════════════════\n\n";
    
    cout << left << setw(25) << "Implementation";
    cout << right << setw(15) << "Time (ms)";
    cout << setw(15) << "Throughput";
    cout << setw(12) << "Speedup" << "\n";
    cout << string(67, '-') << "\n";
    
    cout << left << setw(25) << "Baseline (scalar)";
    cout << right << fixed << setprecision(2);
    cout << setw(15) << baseline_result.time_ms;
    cout << setw(14) << fixed << setprecision(2) << baseline_result.throughput_tokens_per_sec << " tok/s";
    cout << setw(12) << "1.00x" << "\n";
    
    cout << left << setw(25) << "AVX2 SIMD";
    cout << right << fixed << setprecision(2);
    cout << setw(15) << avx2_result.time_ms;
    cout << setw(14) << fixed << setprecision(2) << avx2_result.throughput_tokens_per_sec << " tok/s";
    cout << setw(11) << fixed << setprecision(2) << speedup_avx2 << "x" << "\n";
    
    string mt_display_name = "AVX2 + " + to_string(NUM_THREADS) + " threads";
    cout << left << setw(25) << mt_display_name;
    cout << right << fixed << setprecision(2);
    cout << setw(15) << mt_result.time_ms;
    cout << setw(14) << fixed << setprecision(2) << mt_result.throughput_tokens_per_sec << " tok/s";
    cout << setw(11) << fixed << setprecision(2) << speedup_mt << "x" << "\n";
    
    cout << "\n" << string(67, '=') << "\n";
    
    // Summary
    cout << "\nSUMMARY\n";
    cout << "=======\n";
    cout << "Baseline latency:    " << fixed << setprecision(2) << baseline_result.time_ms << " ms/token\n";
    cout << "AVX2 SIMD latency:   " << fixed << setprecision(2) << avx2_result.time_ms << " ms/token\n";
    cout << "Multithread latency: " << fixed << setprecision(2) << mt_result.time_ms << " ms/token\n";
    cout << "AVX2 Speedup:        " << fixed << setprecision(2) << speedup_avx2 << "x\n";
    cout << "Multithread Speedup: " << fixed << setprecision(2) << speedup_mt << "x\n";
    cout << "AVX2 Correctness:    " << (validation_avx2.passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    cout << "MT Correctness:      " << (validation_mt.passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    
    if (validation_avx2.passed && validation_mt.passed && speedup_mt > 1.0) {
        cout << "\n✅ PHASE 18: OPTIMIZATION SUCCESSFUL\n";
        cout << "\nNext steps:\n";
        cout << "  - Level 4: Q4 dequantization fusion\n";
        cout << "  - Level 5: AVX-512 (if available)\n";
        return 0;
    } else {
        cout << "\n❌ Optimization did not meet criteria\n";
        return 1;
    }
}
