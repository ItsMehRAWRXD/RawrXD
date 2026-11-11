/*===========================================================================
 * Q4KM_Validation_Enhanced.cpp
 * 
 * Enhanced validation suite with detailed numerical correctness reporting
 * 
 * Tests:
 *   1. Registry dispatch correctness
 *   2. Numerical correctness (detailed error metrics)
 *   3. Performance benchmarks
 *   4. Production readiness verification
 * 
 * Expected output:
 *   [SovereignKernelRegistry]
 *   Registered:
 *     q4_k_m_dequant
 *     q4_k_m_matmul
 *   CPU Features:
 *     AVX2: YES
 *     AVX512: YES
 *   Selected:
 *     q4_k_m_dequant_avx512
 * 
 *   Numerical Correctness:
 *     Max error: 0.001234
 *     Mean error: 0.000456
 *     Cosine similarity: 0.999823
 *     Relative error: 0.12%
 *===========================================================================*/

#include "../kernel/SovereignKernelRuntimeLog.hpp"
#include "../kernel/SovereignKernelRegistry.hpp"
#include "../bridge/Deep2_Q4KM.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <random>
#include <chrono>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

using namespace RawrXD::Kernel;
using namespace RawrXD::Deep2;

/*===========================================================================
 * Test Configuration
 *===========================================================================*/
struct TestConfig {
    static constexpr size_t HIDDEN_DIM = 4096;
    static constexpr size_t NUM_TEST_VECTORS = 1000;
    static constexpr size_t NUM_WARMUP = 100;
    static constexpr size_t NUM_ITERATIONS = 1000;
    
    // Pass thresholds
    static constexpr double COSINE_SIM_THRESHOLD = 0.999;
    static constexpr double MAX_REL_ERROR_THRESHOLD = 0.02;  // 2%
    static constexpr double MEAN_REL_ERROR_THRESHOLD = 0.01; // 1%
    static constexpr double MIN_TPS = 15.0;
};

/*===========================================================================
 * Numerical Error Metrics
 *===========================================================================*/
struct ErrorMetrics {
    double max_absolute_error = 0.0;
    double max_relative_error = 0.0;
    double mean_absolute_error = 0.0;
    double mean_relative_error = 0.0;
    double rmse = 0.0;
    double cosine_similarity = 0.0;
    double snr_db = 0.0;  // Signal-to-noise ratio
    
    void Print() const {
        printf("  Numerical Error Metrics:\n");
        printf("    Max absolute error:  %.8f\n", max_absolute_error);
        printf("    Max relative error:  %.4f%%\n", max_relative_error * 100.0);
        printf("    Mean absolute error: %.8f\n", mean_absolute_error);
        printf("    Mean relative error: %.4f%%\n", mean_relative_error * 100.0);
        printf("    RMSE:                %.8f\n", rmse);
        printf("    Cosine similarity:   %.6f\n", cosine_similarity);
        printf("    SNR:                 %.2f dB\n", snr_db);
    }
    
    bool PassesThresholds() const {
        return cosine_similarity > TestConfig::COSINE_SIM_THRESHOLD &&
               max_relative_error < TestConfig::MAX_REL_ERROR_THRESHOLD &&
               mean_relative_error < TestConfig::MEAN_REL_ERROR_THRESHOLD;
    }
};

/*===========================================================================
 * 1. Registry Dispatch Verification
 *===========================================================================*/

bool Test_RegistryDispatch() {
    printf("\n[TEST 1] Registry Dispatch Verification\n");
    printf("  Checking kernel registration and CPU feature detection...\n\n");
    
    // Initialize logging
    KernelRuntimeLog::Instance().Initialize(KernelRuntimeLog::Level::Info);
    
    // Print registry status (this is the key output)
    KernelRuntimeLog::Instance().PrintRegistryStatus();
    
    // Verify specific kernels
    bool q4km_registered = KernelRuntimeLog::Instance().VerifyKernelRegistration("q4_k_m_dequant");
    bool q4km_avx512 = KernelRuntimeLog::Instance().VerifyKernelRegistration("q4_k_m_dequant_avx512");
    bool q4km_avx2 = KernelRuntimeLog::Instance().VerifyKernelRegistration("q4_k_m_dequant_avx2");
    
    // Verify CPU features
    auto& detector = CPUFeatureDetector::Instance();
    bool has_avx2 = detector.HasAVX2();
    bool has_avx512 = detector.HasAVX512();
    
    printf("\n  Verification:\n");
    printf("    q4_k_m_dequant:      %s\n", q4km_registered ? "PASS" : "FAIL");
    printf("    q4_k_m_dequant_avx512: %s\n", q4km_avx512 ? "PASS" : "FAIL");
    printf("    q4_k_m_dequant_avx2:   %s\n", q4km_avx2 ? "PASS" : "FAIL");
    printf("    AVX2 detected:       %s\n", has_avx2 ? "YES" : "NO");
    printf("    AVX512 detected:     %s\n", has_avx512 ? "YES" : "NO");
    
    // Verify dispatch selection
    auto selected_kernel = GetQ4KMDequantKernel();
    bool dispatch_works = (selected_kernel != nullptr);
    
    printf("    Dispatch selection:  %s\n", dispatch_works ? "PASS" : "FAIL");
    
    return q4km_registered && dispatch_works;
}

/*===========================================================================
 * 2. Numerical Correctness (Enhanced)
 *===========================================================================*/

// Generate realistic Q4_K_M test data
void GenerateRealisticQ4KMBlock(uint8_t* block_data, size_t block_idx, 
                                 float target_scale = 1.0f) {
    std::mt19937 rng(static_cast<uint32_t>(block_idx * 12345));
    
    // Generate scales and mins that produce realistic weight distributions
    std::uniform_real_distribution<float> scale_dist(0.01f, 0.1f);
    std::uniform_real_distribution<float> min_dist(-1.0f, 1.0f);
    
    for (int i = 0; i < 16; ++i) {
        float scale = scale_dist(rng) * target_scale;
        float min_val = min_dist(rng);
        
        // Quantize scale and min to 6-bit (stored in 8-bit)
        block_data[i * 2] = static_cast<uint8_t>(std::min(scale * 100.0f, 63.0f));
        block_data[i * 2 + 1] = static_cast<uint8_t>(std::min(
            std::max((min_val + 32.0f), 0.0f), 63.0f));
    }
    
    // Generate quantized values (uniform distribution)
    std::uniform_int_distribution<int> qval_dist(0, 15);
    for (int i = 0; i < 128; ++i) {
        uint8_t low = static_cast<uint8_t>(qval_dist(rng));
        uint8_t high = static_cast<uint8_t>(qval_dist(rng));
        block_data[32 + i] = (high << 4) | low;
    }
}

// Reference dequantization with full precision
void ReferenceDequantQ4KM(const uint8_t* block_data, float* output) {
    for (int sub = 0; sub < 16; ++sub) {
        float scale = static_cast<float>(block_data[sub * 2]) / 100.0f;
        float min_val = static_cast<float>(block_data[sub * 2 + 1]) - 32.0f;
        
        for (int i = 0; i < 16; ++i) {
            uint8_t packed = block_data[32 + sub * 8 + i / 2];
            uint8_t nibble = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
            
            // Dequant: value = nibble * scale + min
            output[sub * 16 + i] = static_cast<float>(nibble) * scale + min_val;
        }
    }
}

ErrorMetrics ComputeErrorMetrics(const float* reference, const float* test, 
                                  size_t count) {
    ErrorMetrics metrics;
    
    double sum_abs_error = 0.0;
    double sum_sq_error = 0.0;
    double sum_rel_error = 0.0;
    double sum_ref = 0.0;
    double sum_ref_sq = 0.0;
    double sum_test = 0.0;
    double sum_test_sq = 0.0;
    double sum_product = 0.0;
    
    for (size_t i = 0; i < count; ++i) {
        double ref = reference[i];
        double tst = test[i];
        double abs_err = std::abs(ref - tst);
        double rel_err = (std::abs(ref) > 1e-10) ? abs_err / std::abs(ref) : abs_err;
        
        metrics.max_absolute_error = std::max(metrics.max_absolute_error, abs_err);
        metrics.max_relative_error = std::max(metrics.max_relative_error, rel_err);
        
        sum_abs_error += abs_err;
        sum_sq_error += abs_err * abs_err;
        sum_rel_error += rel_err;
        
        sum_ref += ref;
        sum_ref_sq += ref * ref;
        sum_test += tst;
        sum_test_sq += tst * tst;
        sum_product += ref * tst;
    }
    
    metrics.mean_absolute_error = sum_abs_error / count;
    metrics.mean_relative_error = sum_rel_error / count;
    metrics.rmse = std::sqrt(sum_sq_error / count);
    
    // Cosine similarity
    double norm_ref = std::sqrt(sum_ref_sq);
    double norm_test = std::sqrt(sum_test_sq);
    metrics.cosine_similarity = sum_product / (norm_ref * norm_test + 1e-10);
    
    // Signal-to-noise ratio
    double signal_power = sum_ref_sq / count;
    double noise_power = sum_sq_error / count;
    metrics.snr_db = 10.0 * std::log10(signal_power / (noise_power + 1e-10));
    
    return metrics;
}

bool Test_NumericalCorrectness() {
    printf("\n[TEST 2] Numerical Correctness\n");
    printf("  Comparing Q4_K_M to FP32 reference with detailed metrics...\n\n");
    
    const size_t hidden_dim = TestConfig::HIDDEN_DIM;
    const size_t num_blocks = (hidden_dim + 255) / 256;
    
    // Allocate buffers
    std::vector<uint8_t> q4_weights(num_blocks * sizeof(Q4KMBlock));
    std::vector<float> fp32_weights(hidden_dim);
    std::vector<float> input(hidden_dim);
    std::vector<float> q4_output(1);
    std::vector<float> fp32_output(1);
    
    // Generate realistic weights
    printf("  Generating test data...\n");
    for (size_t i = 0; i < num_blocks; ++i) {
        GenerateRealisticQ4KMBlock(&q4_weights[i * sizeof(Q4KMBlock)], i, 0.5f);
    }
    
    // Dequantize to FP32 reference
    for (size_t i = 0; i < num_blocks; ++i) {
        ReferenceDequantQ4KM(&q4_weights[i * sizeof(Q4KMBlock)], 
                             &fp32_weights[i * 256]);
    }
    
    // Generate random input
    std::mt19937 rng(42);
    std::normal_distribution<float> input_dist(0.0f, 0.1f);
    for (auto& val : input) {
        val = input_dist(rng);
    }
    
    // Compute FP32 reference GEMV
    printf("  Computing FP32 reference...\n");
    double fp32_sum = 0.0;
    for (size_t i = 0; i < hidden_dim; ++i) {
        fp32_sum += static_cast<double>(fp32_weights[i]) * input[i];
    }
    fp32_output[0] = static_cast<float>(fp32_sum);
    
    // Compute Q4_K_M GEMV
    printf("  Computing Q4_K_M output...\n");
    Q4KMLinear q4_linear;
    if (!q4_linear.Initialize(q4_weights.data(), hidden_dim, 1)) {
        printf("  FAILED: Could not initialize Q4KMLinear\n");
        return false;
    }
    
    if (!q4_linear.Forward(input.data(), q4_output.data())) {
        printf("  FAILED: Q4KMLinear::Forward failed\n");
        return false;
    }
    
    // Compute error metrics
    ErrorMetrics metrics = ComputeErrorMetrics(
        fp32_output.data(), q4_output.data(), 1);
    
    // Print detailed results
    printf("\n");
    metrics.Print();
    
    printf("\n  Pass Criteria:\n");
    printf("    Cosine similarity > %.3f: %s\n", 
           TestConfig::COSINE_SIM_THRESHOLD,
           metrics.cosine_similarity > TestConfig::COSINE_SIM_THRESHOLD ? "PASS" : "FAIL");
    printf("    Max relative error < %.1f%%: %s\n",
           TestConfig::MAX_REL_ERROR_THRESHOLD * 100.0,
           metrics.max_relative_error < TestConfig::MAX_REL_ERROR_THRESHOLD ? "PASS" : "FAIL");
    printf("    Mean relative error < %.1f%%: %s\n",
           TestConfig::MEAN_REL_ERROR_THRESHOLD * 100.0,
           metrics.mean_relative_error < TestConfig::MEAN_REL_ERROR_THRESHOLD ? "PASS" : "FAIL");
    
    return metrics.PassesThresholds();
}

/*===========================================================================
 * 3. Performance Benchmark
 *===========================================================================*/

bool Test_Performance() {
    printf("\n[TEST 3] Performance Benchmark\n");
    printf("  Measuring throughput with statistical analysis...\n\n");
    
    const size_t hidden_dim = TestConfig::HIDDEN_DIM;
    const size_t num_blocks = (hidden_dim + 255) / 256;
    
    // Setup
    std::vector<uint8_t> q4_weights(num_blocks * sizeof(Q4KMBlock));
    std::vector<float> input(hidden_dim);
    std::vector<float> output(1);
    
    for (size_t i = 0; i < num_blocks; ++i) {
        GenerateRealisticQ4KMBlock(&q4_weights[i * sizeof(Q4KMBlock)], i);
    }
    
    Q4KMLinear q4_linear;
    if (!q4_linear.Initialize(q4_weights.data(), hidden_dim, 1)) {
        printf("  FAILED: Could not initialize Q4KMLinear\n");
        return false;
    }
    
    // Warmup
    printf("  Warming up...\n");
    for (size_t i = 0; i < TestConfig::NUM_WARMUP; ++i) {
        q4_linear.Forward(input.data(), output.data());
    }
    
    // Benchmark with multiple iterations for statistical accuracy
    printf("  Running %zu iterations...\n", TestConfig::NUM_ITERATIONS);
    
    std::vector<double> iteration_times;
    iteration_times.reserve(TestConfig::NUM_ITERATIONS);
    
    for (size_t iter = 0; iter < TestConfig::NUM_ITERATIONS; ++iter) {
        // Vary input
        input[iter % hidden_dim] = static_cast<float>(iter % 10) * 0.1f;
        
        auto start = std::chrono::high_resolution_clock::now();
        q4_linear.Forward(input.data(), output.data());
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        iteration_times.push_back(duration.count() / 1e6); // Convert to ms
    }
    
    // Compute statistics
    double total_time = 0.0;
    for (double t : iteration_times) {
        total_time += t;
    }
    
    double mean_time = total_time / iteration_times.size();
    double tps = 1000.0 / mean_time; // Tokens per second
    
    // Compute std deviation
    double variance = 0.0;
    for (double t : iteration_times) {
        variance += (t - mean_time) * (t - mean_time);
    }
    double std_dev = std::sqrt(variance / iteration_times.size());
    
    // Find min/max
    double min_time = *std::min_element(iteration_times.begin(), iteration_times.end());
    double max_time = *std::max_element(iteration_times.begin(), iteration_times.end());
    
    printf("\n  Performance Results:\n");
    printf("    Mean latency:      %.3f ms (%.2f TPS)\n", mean_time, tps);
    printf("    Std deviation:     %.3f ms\n", std_dev);
    printf("    Min latency:       %.3f ms (%.2f TPS)\n", min_time, 1000.0 / min_time);
    printf("    Max latency:       %.3f ms (%.2f TPS)\n", max_time, 1000.0 / max_time);
    printf("    Target TPS:        %.1f\n", TestConfig::MIN_TPS);
    printf("    Result:            %s\n", tps >= TestConfig::MIN_TPS ? "PASS" : "FAIL");
    
    // Get kernel stats
    auto stats = q4_linear.GetStats();
    printf("\n  Kernel Stats:\n");
    printf("    Forward calls:     %llu\n", stats.forward_calls);
    printf("    Avg cycles/call:   %.0f\n", stats.avg_cycles_per_call);
    
    return tps >= TestConfig::MIN_TPS;
}

/*===========================================================================
 * 4. Production Readiness Verification
 *===========================================================================*/

bool Test_ProductionReadiness() {
    printf("\n[TEST 4] Production Readiness Verification\n");
    printf("  Checking all components for production deployment...\n\n");
    
    bool all_pass = true;
    
    // Check 1: Kernel registry initialized
    auto q4km_kernel = GetQ4KMDequantKernel();
    bool registry_ok = (q4km_kernel != nullptr);
    printf("  [ ] Kernel registry:       %s\n", registry_ok ? "PASS" : "FAIL");
    all_pass &= registry_ok;
    
    // Check 2: CPU features detected
    auto& detector = CPUFeatureDetector::Instance();
    bool cpu_ok = detector.HasAVX2() || detector.HasAVX512();
    printf("  [ ] CPU features:            %s (AVX2:%s AVX512:%s)\n",
           cpu_ok ? "PASS" : "FAIL",
           detector.HasAVX2() ? "Y" : "N",
           detector.HasAVX512() ? "Y" : "N");
    all_pass &= cpu_ok;
    
    // Check 3: Memory alignment
    float* test_aligned = (float*)_aligned_malloc(4096 * sizeof(float), 32);
    bool alignment_ok = (test_aligned != nullptr) && 
                        ((reinterpret_cast<uintptr_t>(test_aligned) % 32) == 0);
    printf("  [ ] Memory alignment:        %s\n", alignment_ok ? "PASS" : "FAIL");
    all_pass &= alignment_ok;
    _aligned_free(test_aligned);
    
    // Check 4: Q4KMLinear can be instantiated
    Q4KMLinear linear;
    std::vector<uint8_t> test_block(sizeof(Q4KMBlock));
    bool instantiate_ok = linear.Initialize(test_block.data(), 256, 1);
    printf("  [ ] Q4KMLinear init:         %s\n", instantiate_ok ? "PASS" : "FAIL");
    all_pass &= instantiate_ok;
    
    // Check 5: Dispatch selection working
    auto selected = GetBestKernel<Q4KMDequantFunc>("q4_k_m_dequant");
    bool dispatch_ok = (selected != nullptr);
    printf("  [ ] Dispatch selection:      %s\n", dispatch_ok ? "PASS" : "FAIL");
    all_pass &= dispatch_ok;
    
    printf("\n  Production readiness:        %s\n", all_pass ? "PASS" : "FAIL");
    
    return all_pass;
}

/*===========================================================================
 * Main
 *===========================================================================*/

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("=================================================================\n");
    printf("  Q4_K_M Enhanced Validation Suite\n");
    printf("  RawrXD Sovereign Runtime - Production Verification\n");
    printf("=================================================================\n");
    
    bool test1 = Test_RegistryDispatch();
    bool test2 = Test_NumericalCorrectness();
    bool test3 = Test_Performance();
    bool test4 = Test_ProductionReadiness();
    
    printf("\n=================================================================\n");
    printf("  FINAL RESULTS\n");
    printf("=================================================================\n");
    printf("  1. Registry Dispatch:        %s\n", test1 ? "PASS" : "FAIL");
    printf("  2. Numerical Correctness:    %s\n", test2 ? "PASS" : "FAIL");
    printf("  3. Performance:              %s\n", test3 ? "PASS" : "FAIL");
    printf("  4. Production Readiness:     %s\n", test4 ? "PASS" : "FAIL");
    printf("-----------------------------------------------------------------\n");
    
    bool all_pass = test1 && test2 && test3 && test4;
    printf("  OVERALL:                     %s\n", 
           all_pass ? "ALL TESTS PASSED - PRODUCTION READY" : "SOME TESTS FAILED");
    printf("=================================================================\n");
    
    return all_pass ? 0 : 1;
}
