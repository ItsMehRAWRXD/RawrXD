/**
 * @file qkv_optimization_test.cpp
 * @brief Phase 19: QKV Projection Optimization
 *
 * Optimizes the QKV projection kernel (now dominant bottleneck post-Phase 18):
 *   QKV[9216] = W_qkv[9216×3072] × hidden[3072]
 *
 * Optimization Levels:
 *   1. Baseline measurement
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
const int QKV_DIM = 9216;  // 3072 * 3 for Q+K+V
const int NUM_ITERATIONS = 10;
const int NUM_THREADS = 8;

// ============================================================================
// BASELINE: Scalar QKV implementation
// ============================================================================
void qkv_baseline(const float* input, const float* weights,
                  float* qkv_output, int hidden_dim, int qkv_dim) {
    for (int i = 0; i < qkv_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < hidden_dim; j++) {
            sum += weights[i * hidden_dim + j] * input[j];
        }
        qkv_output[i] = sum;
    }
}

// ============================================================================
// OPTIMIZED Level 2: AVX2 SIMD
// ============================================================================
void qkv_avx2(const float* input, const float* weights,
              float* qkv_output, int hidden_dim, int qkv_dim) {
    const int SIMD_WIDTH = 8;

    for (int i = 0; i < qkv_dim; i++) {
        __m256 sum_vec = _mm256_setzero_ps();

        int j = 0;
        // Main SIMD loop
        for (; j <= hidden_dim - SIMD_WIDTH; j += SIMD_WIDTH) {
            __m256 w_vec = _mm256_loadu_ps(&weights[i * hidden_dim + j]);
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
        for (; j < hidden_dim; j++) {
            sum += weights[i * hidden_dim + j] * input[j];
        }

        qkv_output[i] = sum;
    }
}

// ============================================================================
// OPTIMIZED Level 3: Multithreaded AVX2
// ============================================================================
void qkv_avx2_worker(const float* input, const float* weights,
                     float* qkv_output, int hidden_dim,
                     int start_row, int end_row) {
    const int SIMD_WIDTH = 8;

    for (int i = start_row; i < end_row; i++) {
        __m256 sum_vec = _mm256_setzero_ps();

        int j = 0;
        for (; j <= hidden_dim - SIMD_WIDTH; j += SIMD_WIDTH) {
            __m256 w_vec = _mm256_loadu_ps(&weights[i * hidden_dim + j]);
            __m256 x_vec = _mm256_loadu_ps(&input[j]);
            __m256 prod = _mm256_mul_ps(w_vec, x_vec);
            sum_vec = _mm256_add_ps(sum_vec, prod);
        }

        float sum_array[8];
        _mm256_storeu_ps(sum_array, sum_vec);
        float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                    sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];

        for (; j < hidden_dim; j++) {
            sum += weights[i * hidden_dim + j] * input[j];
        }

        qkv_output[i] = sum;
    }
}

void qkv_avx2_mt(const float* input, const float* weights,
                 float* qkv_output, int hidden_dim, int qkv_dim, int num_threads) {
    vector<thread> threads;
    int chunk_size = qkv_dim / num_threads;

    for (int t = 0; t < num_threads; t++) {
        int start_row = t * chunk_size;
        int end_row = (t == num_threads - 1) ? qkv_dim : (t + 1) * chunk_size;
        threads.emplace_back(qkv_avx2_worker, input, weights, qkv_output,
                            hidden_dim, start_row, end_row);
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
                            const float* input, const float* weights, float* output,
                            int hidden_dim, int qkv_dim, int iterations) {
    // Warmup
    func(input, weights, output, hidden_dim, qkv_dim);

    // Benchmark
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        func(input, weights, output, hidden_dim, qkv_dim);
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
                              void (*func)(const float*, const float*, float*, int, int, int),
                              const float* input, const float* weights, float* output,
                              int hidden_dim, int qkv_dim, int num_threads, int iterations) {
    // Warmup
    func(input, weights, output, hidden_dim, qkv_dim, num_threads);

    // Benchmark
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        func(input, weights, output, hidden_dim, qkv_dim, num_threads);
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
    cout << "🔬 RawrXD Phase 19: QKV Projection Optimization\n";
    cout << "================================================\n\n";

    cout << "Configuration:\n";
    cout << "  Hidden dim: " << HIDDEN_DIM << "\n";
    cout << "  QKV dim: " << QKV_DIM << "\n";
    cout << "  Iterations: " << NUM_ITERATIONS << "\n";
    cout << "  Threads: " << NUM_THREADS << "\n\n";

    // Allocate memory
    cout << "[1/5] Allocating memory...\n";
    vector<float> input(HIDDEN_DIM);
    vector<float> weights(QKV_DIM * HIDDEN_DIM);
    vector<float> output_baseline(QKV_DIM);
    vector<float> output_avx2(QKV_DIM);
    vector<float> output_mt(QKV_DIM);

    // Initialize with deterministic values
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = sinf(i * 0.01f) * 0.5f;
    }
    for (int i = 0; i < QKV_DIM * HIDDEN_DIM; i++) {
        weights[i] = sinf(i * 0.001f) * 0.01f;
    }
    cout << "  ✓ Memory allocated and initialized\n\n";

    // Step 1: Generate reference output
    cout << "[2/5] Generating reference output (baseline)...\n";
    qkv_baseline(input.data(), weights.data(), output_baseline.data(), HIDDEN_DIM, QKV_DIM);
    cout << "  ✓ Reference output generated\n";
    cout << "    Q sample: ";
    for (int i = 0; i < min(5, HIDDEN_DIM); i++) {
        cout << fixed << setprecision(4) << output_baseline[i] << " ";
    }
    cout << "\n    K sample: ";
    for (int i = HIDDEN_DIM; i < HIDDEN_DIM + min(5, HIDDEN_DIM); i++) {
        cout << fixed << setprecision(4) << output_baseline[i] << " ";
    }
    cout << "\n    V sample: ";
    for (int i = 2 * HIDDEN_DIM; i < 2 * HIDDEN_DIM + min(5, HIDDEN_DIM); i++) {
        cout << fixed << setprecision(4) << output_baseline[i] << " ";
    }
    cout << "\n\n";

    // Step 2: Generate AVX2 output
    cout << "[3/5] Generating AVX2 output...\n";
    qkv_avx2(input.data(), weights.data(), output_avx2.data(), HIDDEN_DIM, QKV_DIM);
    cout << "  ✓ AVX2 output generated\n";
    cout << "    Q sample: ";
    for (int i = 0; i < min(5, HIDDEN_DIM); i++) {
        cout << fixed << setprecision(4) << output_avx2[i] << " ";
    }
    cout << "\n\n";

    // Step 3: Validate correctness
    cout << "[4/5] Validating correctness...\n";
    ValidationResult validation_avx2 = validate_outputs(output_baseline.data(), output_avx2.data(),
                                                        QKV_DIM, 0.999);

    cout << "  AVX2 Validation:\n";
    cout << "    Max absolute error:  " << fixed << setprecision(6) << validation_avx2.max_absolute_error << "\n";
    cout << "    Mean absolute error: " << fixed << setprecision(6) << validation_avx2.mean_absolute_error << "\n";
    cout << "    Max relative error:  " << fixed << setprecision(6) << validation_avx2.max_relative_error << "\n";
    cout << "    Status: " << (validation_avx2.passed ? "✅ PASSED" : "❌ FAILED") << "\n\n";

    // Step 4: Benchmark
    cout << "[5/5] Benchmarking...\n\n";

    BenchmarkResult baseline_result = benchmark("Baseline", qkv_baseline,
                                                input.data(), weights.data(), output_baseline.data(),
                                                HIDDEN_DIM, QKV_DIM, NUM_ITERATIONS);

    BenchmarkResult avx2_result = benchmark("AVX2 SIMD", qkv_avx2,
                                              input.data(), weights.data(), output_avx2.data(),
                                              HIDDEN_DIM, QKV_DIM, NUM_ITERATIONS);

    string mt_name = "AVX2 + " + to_string(NUM_THREADS) + " threads";
    BenchmarkResult mt_result = benchmark_mt(mt_name.c_str(), qkv_avx2_mt,
                                             input.data(), weights.data(), output_mt.data(),
                                             HIDDEN_DIM, QKV_DIM, NUM_THREADS, NUM_ITERATIONS);

    // Validate multithreaded result
    ValidationResult validation_mt = validate_outputs(output_baseline.data(), output_mt.data(),
                                                        QKV_DIM, 0.999);

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
        cout << "\n✅ PHASE 19: OPTIMIZATION SUCCESSFUL\n";
        cout << "\nNext steps:\n";
        cout << "  - Level 4: Q4 dequantization fusion\n";
        cout << "  - Level 5: AVX-512 (if available)\n";
        return 0;
    } else {
        cout << "\n❌ Optimization did not meet criteria\n";
        return 1;
    }
}
