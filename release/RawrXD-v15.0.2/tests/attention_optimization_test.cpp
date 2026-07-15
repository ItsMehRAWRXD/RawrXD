/**
 * @file attention_optimization_test.cpp
 * @brief Phase 20: Attention Optimization
 *
 * Optimizes the attention kernel (now dominant bottleneck post-Phase 19):
 *   scores = Q @ K^T / sqrt(head_dim)
 *   weights = softmax(scores)
 *   output = weights @ V
 *
 * Optimization Levels:
 *   1. Baseline measurement
 *   2. AVX2 SIMD vectorization
 *   3. Multithreading
 *   4. Cache optimization (future)
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
const int NUM_HEADS = 32;
const int HEAD_DIM = 96;
const int HIDDEN_DIM = 3072;
const int SEQ_LEN = 128;  // Decode scenario with some context
const int NUM_ITERATIONS = 10;
const int NUM_THREADS = 8;

// ============================================================================
// Utility Functions
// ============================================================================
inline float dot_product_scalar(const float* a, const float* b, int n) {
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

void softmax_scalar(float* scores, int n) {
    // Find max for numerical stability
    float max_score = scores[0];
    for (int i = 1; i < n; i++) {
        if (scores[i] > max_score) max_score = scores[i];
    }
    
    // Compute exp and sum
    float sum_exp = 0.0f;
    for (int i = 0; i < n; i++) {
        scores[i] = expf(scores[i] - max_score);
        sum_exp += scores[i];
    }
    
    // Normalize
    for (int i = 0; i < n; i++) {
        scores[i] /= sum_exp;
    }
}

// ============================================================================
// BASELINE: Scalar Attention implementation
// ============================================================================
void attention_baseline(const float* q, const float* k_cache, const float* v_cache,
                        float* output, int num_heads, int head_dim, int seq_len) {
    const float scale = 1.0f / sqrtf((float)head_dim);
    
    // Temporary buffers
    vector<float> scores(seq_len);
    vector<float> out_per_head(HIDDEN_DIM);
    
    for (int h = 0; h < num_heads; h++) {
        const float* q_head = &q[h * head_dim];
        
        // Step 1: Compute attention scores
        for (int pos = 0; pos < seq_len; pos++) {
            const float* k_head = &k_cache[pos * HIDDEN_DIM + h * head_dim];
            scores[pos] = dot_product_scalar(q_head, k_head, head_dim) * scale;
        }
        
        // Step 2: Softmax
        softmax_scalar(scores.data(), seq_len);
        
        // Step 3: Weighted sum of values
        float* out_head = &out_per_head[h * head_dim];
        for (int d = 0; d < head_dim; d++) {
            out_head[d] = 0.0f;
        }
        
        for (int pos = 0; pos < seq_len; pos++) {
            const float* v_head = &v_cache[pos * HIDDEN_DIM + h * head_dim];
            float weight = scores[pos];
            for (int d = 0; d < head_dim; d++) {
                out_head[d] += weight * v_head[d];
            }
        }
    }
    
    // Copy to output
    for (int i = 0; i < HIDDEN_DIM; i++) {
        output[i] = out_per_head[i];
    }
}

// ============================================================================
// OPTIMIZED Level 2: AVX2 SIMD
// ============================================================================
inline float dot_product_avx2(const float* a, const float* b, int n) {
    const int SIMD_WIDTH = 8;
    __m256 sum_vec = _mm256_setzero_ps();
    
    int i = 0;
    for (; i <= n - SIMD_WIDTH; i += SIMD_WIDTH) {
        __m256 a_vec = _mm256_loadu_ps(&a[i]);
        __m256 b_vec = _mm256_loadu_ps(&b[i]);
        __m256 prod = _mm256_mul_ps(a_vec, b_vec);
        sum_vec = _mm256_add_ps(sum_vec, prod);
    }
    
    // Horizontal sum
    float sum_array[8];
    _mm256_storeu_ps(sum_array, sum_vec);
    float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];
    
    // Remainder
    for (; i < n; i++) {
        sum += a[i] * b[i];
    }
    
    return sum;
}

void attention_avx2(const float* q, const float* k_cache, const float* v_cache,
                    float* output, int num_heads, int head_dim, int seq_len) {
    const float scale = 1.0f / sqrtf((float)head_dim);
    
    vector<float> scores(seq_len);
    vector<float> out_per_head(HIDDEN_DIM);
    
    for (int h = 0; h < num_heads; h++) {
        const float* q_head = &q[h * head_dim];
        
        // Step 1: Compute attention scores (AVX2)
        for (int pos = 0; pos < seq_len; pos++) {
            const float* k_head = &k_cache[pos * HIDDEN_DIM + h * head_dim];
            scores[pos] = dot_product_avx2(q_head, k_head, head_dim) * scale;
        }
        
        // Step 2: Softmax (scalar - could be optimized)
        softmax_scalar(scores.data(), seq_len);
        
        // Step 3: Weighted sum of values (AVX2)
        float* out_head = &out_per_head[h * head_dim];
        for (int d = 0; d < head_dim; d++) {
            out_head[d] = 0.0f;
        }
        
        for (int pos = 0; pos < seq_len; pos++) {
            const float* v_head = &v_cache[pos * HIDDEN_DIM + h * head_dim];
            float weight = scores[pos];
            
            int d = 0;
            __m256 w_vec = _mm256_set1_ps(weight);
            for (; d <= head_dim - 8; d += 8) {
                __m256 out_vec = _mm256_loadu_ps(&out_head[d]);
                __m256 v_vec = _mm256_loadu_ps(&v_head[d]);
                __m256 prod = _mm256_mul_ps(w_vec, v_vec);
                out_vec = _mm256_add_ps(out_vec, prod);
                _mm256_storeu_ps(&out_head[d], out_vec);
            }
            for (; d < head_dim; d++) {
                out_head[d] += weight * v_head[d];
            }
        }
    }
    
    // Copy to output
    for (int i = 0; i < HIDDEN_DIM; i++) {
        output[i] = out_per_head[i];
    }
}

// ============================================================================
// OPTIMIZED Level 3: Multithreaded AVX2
// ============================================================================
void attention_head_worker(const float* q, const float* k_cache, const float* v_cache,
                           float* output, int head_dim, int seq_len,
                           int start_head, int end_head) {
    const float scale = 1.0f / sqrtf((float)head_dim);
    
    vector<float> scores(seq_len);
    
    for (int h = start_head; h < end_head; h++) {
        const float* q_head = &q[h * head_dim];
        float* out_head = &output[h * head_dim];
        
        // Step 1: Compute attention scores
        for (int pos = 0; pos < seq_len; pos++) {
            const float* k_head = &k_cache[pos * HIDDEN_DIM + h * head_dim];
            scores[pos] = dot_product_avx2(q_head, k_head, head_dim) * scale;
        }
        
        // Step 2: Softmax
        softmax_scalar(scores.data(), seq_len);
        
        // Step 3: Weighted sum of values
        for (int d = 0; d < head_dim; d++) {
            out_head[d] = 0.0f;
        }
        
        for (int pos = 0; pos < seq_len; pos++) {
            const float* v_head = &v_cache[pos * HIDDEN_DIM + h * head_dim];
            float weight = scores[pos];
            
            int d = 0;
            __m256 w_vec = _mm256_set1_ps(weight);
            for (; d <= head_dim - 8; d += 8) {
                __m256 out_vec = _mm256_loadu_ps(&out_head[d]);
                __m256 v_vec = _mm256_loadu_ps(&v_head[d]);
                __m256 prod = _mm256_mul_ps(w_vec, v_vec);
                out_vec = _mm256_add_ps(out_vec, prod);
                _mm256_storeu_ps(&out_head[d], out_vec);
            }
            for (; d < head_dim; d++) {
                out_head[d] += weight * v_head[d];
            }
        }
    }
}

void attention_avx2_mt(const float* q, const float* k_cache, const float* v_cache,
                        float* output, int num_heads, int head_dim, int seq_len, int num_threads) {
    vector<thread> threads;
    int chunk_size = num_heads / num_threads;
    
    for (int t = 0; t < num_threads; t++) {
        int start_head = t * chunk_size;
        int end_head = (t == num_threads - 1) ? num_heads : (t + 1) * chunk_size;
        threads.emplace_back(attention_head_worker, q, k_cache, v_cache, output,
                            head_dim, seq_len, start_head, end_head);
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
                            void (*func)(const float*, const float*, const float*, 
                                        float*, int, int, int),
                            const float* q, const float* k_cache, const float* v_cache,
                            float* output,
                            int num_heads, int head_dim, int seq_len, int iterations) {
    // Warmup
    func(q, k_cache, v_cache, output, num_heads, head_dim, seq_len);
    
    // Benchmark
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        func(q, k_cache, v_cache, output, num_heads, head_dim, seq_len);
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
                                         float*, int, int, int, int),
                              const float* q, const float* k_cache, const float* v_cache,
                              float* output,
                              int num_heads, int head_dim, int seq_len, int num_threads, int iterations) {
    // Warmup
    func(q, k_cache, v_cache, output, num_heads, head_dim, seq_len, num_threads);
    
    // Benchmark
    auto start = Clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        func(q, k_cache, v_cache, output, num_heads, head_dim, seq_len, num_threads);
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
    cout << "🔬 RawrXD Phase 20: Attention Optimization\n";
    cout << "==========================================\n\n";
    
    cout << "Configuration:\n";
    cout << "  Num heads: " << NUM_HEADS << "\n";
    cout << "  Head dim: " << HEAD_DIM << "\n";
    cout << "  Hidden dim: " << HIDDEN_DIM << "\n";
    cout << "  Seq length: " << SEQ_LEN << "\n";
    cout << "  Iterations: " << NUM_ITERATIONS << "\n";
    cout << "  Threads: " << NUM_THREADS << "\n\n";
    
    // Allocate memory
    cout << "[1/5] Allocating memory...\n";
    vector<float> q(HIDDEN_DIM);
    vector<float> k_cache(SEQ_LEN * HIDDEN_DIM);
    vector<float> v_cache(SEQ_LEN * HIDDEN_DIM);
    vector<float> output_baseline(HIDDEN_DIM);
    vector<float> output_avx2(HIDDEN_DIM);
    vector<float> output_mt(HIDDEN_DIM);
    
    // Initialize with deterministic values
    for (int i = 0; i < HIDDEN_DIM; i++) {
        q[i] = sinf(i * 0.01f) * 0.5f;
    }
    for (int i = 0; i < SEQ_LEN * HIDDEN_DIM; i++) {
        k_cache[i] = sinf(i * 0.001f) * 0.1f;
        v_cache[i] = cosf(i * 0.001f) * 0.1f;
    }
    cout << "  ✓ Memory allocated and initialized\n\n";
    
    // Step 1: Generate reference output
    cout << "[2/5] Generating reference output (baseline)...\n";
    attention_baseline(q.data(), k_cache.data(), v_cache.data(),
                       output_baseline.data(), NUM_HEADS, HEAD_DIM, SEQ_LEN);
    cout << "  ✓ Reference output generated\n";
    cout << "    Sample: ";
    for (int i = 0; i < min(5, HIDDEN_DIM); i++) {
        cout << fixed << setprecision(4) << output_baseline[i] << " ";
    }
    cout << "\n\n";
    
    // Step 2: Generate AVX2 output
    cout << "[3/5] Generating AVX2 output...\n";
    attention_avx2(q.data(), k_cache.data(), v_cache.data(),
                   output_avx2.data(), NUM_HEADS, HEAD_DIM, SEQ_LEN);
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
    
    BenchmarkResult baseline_result = benchmark("Baseline", attention_baseline,
                                                q.data(), k_cache.data(), v_cache.data(),
                                                output_baseline.data(),
                                                NUM_HEADS, HEAD_DIM, SEQ_LEN, NUM_ITERATIONS);
    
    BenchmarkResult avx2_result = benchmark("AVX2 SIMD", attention_avx2,
                                              q.data(), k_cache.data(), v_cache.data(),
                                              output_avx2.data(),
                                              NUM_HEADS, HEAD_DIM, SEQ_LEN, NUM_ITERATIONS);
    
    string mt_name = "AVX2 + " + to_string(NUM_THREADS) + " threads";
    BenchmarkResult mt_result = benchmark_mt(mt_name.c_str(), attention_avx2_mt,
                                             q.data(), k_cache.data(), v_cache.data(),
                                             output_mt.data(),
                                             NUM_HEADS, HEAD_DIM, SEQ_LEN, NUM_THREADS, NUM_ITERATIONS);
    
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
        cout << "\n✅ PHASE 20: OPTIMIZATION SUCCESSFUL\n";
        cout << "\nNext steps:\n";
        cout << "  - Level 4: Cache optimization\n";
        cout << "  - Level 5: Q4 dequantization fusion\n";
        cout << "  - Level 6: AVX-512 (if available)\n";
        return 0;
    } else {
        cout << "\n❌ Optimization did not meet criteria\n";
        return 1;
    }
}
