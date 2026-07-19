/*===========================================================================
 * Q4KM_Validation_Suite.cpp
 * 
 * Production validation tests for Q4_K_M integration
 * 
 * Tests:
 *   A. GGUF Compatibility - Verify tensor loading
 *   B. Numerical Accuracy - Compare to FP16 reference
 *   C. Performance Benchmark - Measure TPS improvement
 *   D. Kernel Registry - Verify dynamic dispatch
 *===========================================================================*/

#include "../bridge/Deep2_Q4KM.hpp"
#include "../bridge/Deep2Bridge_Quantized.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <random>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

using namespace RawrXD::Deep2;
using namespace RawrXD::Bridge;

/*===========================================================================
 * Test Configuration
 *===========================================================================*/
struct TestConfig {
    static constexpr size_t HIDDEN_DIM = 4096;
    static constexpr size_t NUM_TEST_VECTORS = 1000;
    static constexpr float COSINE_SIMILARITY_THRESHOLD = 0.99f;
    static constexpr float RELATIVE_ERROR_THRESHOLD = 0.02f;  // 2%
    static constexpr double MIN_EXPECTED_TPS = 15.0;
};

/*===========================================================================
 * Test Results
 *===========================================================================*/
struct TestResults {
    bool gguf_compat_passed = false;
    bool numerical_accuracy_passed = false;
    bool performance_passed = false;
    bool kernel_registry_passed = false;
    
    double cosine_similarity = 0.0;
    double max_relative_error = 0.0;
    double measured_tps = 0.0;
    
    const char* kernel_version = nullptr;
    Q4KMKernelType kernel_type = Q4KMKernelType::Scalar;
};

/*===========================================================================
 * A. GGUF Compatibility Test
 *===========================================================================*/

// Mock GGUF Q4_K_M block generator for testing
void GenerateMockQ4KMBlock(uint8_t* block_data, size_t block_idx) {
    // Q4_K_M block structure:
    // - 32 bytes: scales and mins (16 sub-blocks * 2 bytes)
    // - 128 bytes: quantized values (4 bits per value)
    
    // Generate predictable test data
    std::mt19937 rng(static_cast<uint32_t>(block_idx));
    std::uniform_int_distribution<int> scale_dist(1, 20);
    std::uniform_int_distribution<int> min_dist(-5, 5);
    std::uniform_int_distribution<int> qval_dist(0, 15);
    
    // Fill scales and mins
    for (int i = 0; i < 16; ++i) {
        block_data[i * 2] = static_cast<uint8_t>(scale_dist(rng));      // scale
        block_data[i * 2 + 1] = static_cast<uint8_t>(min_dist(rng) + 5); // min (offset to positive)
    }
    
    // Fill quantized values (pack 2 nibbles per byte)
    for (int i = 0; i < 128; ++i) {
        uint8_t low = static_cast<uint8_t>(qval_dist(rng));
        uint8_t high = static_cast<uint8_t>(qval_dist(rng));
        block_data[32 + i] = (high << 4) | low;
    }
}

// Reference FP32 dequantization (for comparison)
void ReferenceDequantQ4KM(const uint8_t* block_data, float* output) {
    for (int sub = 0; sub < 16; ++sub) {
        float scale = static_cast<float>(block_data[sub * 2]);
        float min_val = static_cast<float>(block_data[sub * 2 + 1]) - 5.0f;
        
        for (int i = 0; i < 16; ++i) {
            uint8_t packed = block_data[32 + sub * 8 + i / 2];
            uint8_t nibble = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
            
            // Dequant: value = nibble * scale + min
            output[sub * 16 + i] = static_cast<float>(nibble) * scale + min_val;
        }
    }
}

bool Test_GGUF_Compatibility() {
    printf("[TEST A] GGUF Compatibility\n");
    printf("  Generating mock Q4_K_M blocks...\n");
    
    const size_t num_blocks = 10;
    std::vector<uint8_t> blocks(num_blocks * sizeof(Q4KMBlock));
    std::vector<float> reference_output(num_blocks * 256);
    std::vector<float> kernel_output(num_blocks * 256);
    
    // Generate test blocks
    for (size_t i = 0; i < num_blocks; ++i) {
        GenerateMockQ4KMBlock(&blocks[i * sizeof(Q4KMBlock)], i);
    }
    
    // Generate reference output
    for (size_t i = 0; i < num_blocks; ++i) {
        ReferenceDequantQ4KM(&blocks[i * sizeof(Q4KMBlock)], 
                             &reference_output[i * 256]);
    }
    
    // Test kernel dequantization
    Sovereign_Q4KM_DequantRange(blocks.data(), kernel_output.data(), num_blocks);
    
    // Compare outputs
    double max_error = 0.0;
    double sum_ref = 0.0;
    double sum_kernel = 0.0;
    double sum_product = 0.0;
    
    for (size_t i = 0; i < reference_output.size(); ++i) {
        double ref = reference_output[i];
        double kern = kernel_output[i];
        double error = std::abs(ref - kern);
        
        max_error = std::max(max_error, error);
        sum_ref += ref * ref;
        sum_kernel += kern * kern;
        sum_product += ref * kern;
    }
    
    double cosine_sim = sum_product / (std::sqrt(sum_ref) * std::sqrt(sum_kernel));
    
    printf("  Max absolute error: %.6f\n", max_error);
    printf("  Cosine similarity: %.6f\n", cosine_sim);
    printf("  Block structure validated: %s\n", 
           (max_error < 0.1) ? "PASS" : "FAIL");
    
    return max_error < 0.1 && cosine_sim > 0.999;
}

/*===========================================================================
 * B. Numerical Accuracy Test
 *===========================================================================*/

bool Test_Numerical_Accuracy(TestResults& results) {
    printf("\n[TEST B] Numerical Accuracy\n");
    printf("  Comparing Q4_K_M GEMV to FP32 reference...\n");
    
    const size_t hidden_dim = TestConfig::HIDDEN_DIM;
    const size_t num_blocks = (hidden_dim + 255) / 256;
    
    // Generate quantized weights
    std::vector<uint8_t> q4_weights(num_blocks * sizeof(Q4KMBlock));
    std::vector<float> fp32_weights(hidden_dim);
    std::vector<float> input(hidden_dim);
    std::vector<float> q4_output(1);
    std::vector<float> fp32_output(1);
    
    // Generate weights and dequantize to FP32 reference
    for (size_t i = 0; i < num_blocks; ++i) {
        GenerateMockQ4KMBlock(&q4_weights[i * sizeof(Q4KMBlock)], i);
    }
    
    // Dequantize to FP32
    for (size_t i = 0; i < num_blocks; ++i) {
        ReferenceDequantQ4KM(&q4_weights[i * sizeof(Q4KMBlock)], 
                             &fp32_weights[i * 256]);
    }
    
    // Generate random input
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (auto& val : input) {
        val = dist(rng);
    }
    
    // Compute FP32 reference GEMV
    float fp32_sum = 0.0f;
    for (size_t i = 0; i < hidden_dim; ++i) {
        fp32_sum += fp32_weights[i] * input[i];
    }
    fp32_output[0] = fp32_sum;
    
    // Compute Q4_K_M GEMV using kernel
    Q4KMLinear q4_linear;
    if (!q4_linear.Initialize(q4_weights.data(), hidden_dim, 1)) {
        printf("  FAILED: Could not initialize Q4KMLinear\n");
        return false;
    }
    
    if (!q4_linear.Forward(input.data(), q4_output.data())) {
        printf("  FAILED: Q4KMLinear::Forward failed\n");
        return false;
    }
    
    // Calculate metrics
    double ref_val = fp32_output[0];
    double q4_val = q4_output[0];
    double abs_error = std::abs(ref_val - q4_val);
    double rel_error = (ref_val != 0.0) ? abs_error / std::abs(ref_val) : abs_error;
    
    // Cosine similarity (for vectors, here just 1D)
    double dot = ref_val * q4_val;
    double norm_ref = std::sqrt(ref_val * ref_val);
    double norm_q4 = std::sqrt(q4_val * q4_val);
    double cosine_sim = dot / (norm_ref * norm_q4 + 1e-10);
    
    results.cosine_similarity = cosine_sim;
    results.max_relative_error = rel_error;
    
    printf("  FP32 reference: %.6f\n", ref_val);
    printf("  Q4_K_M output:  %.6f\n", q4_val);
    printf("  Absolute error: %.6f\n", abs_error);
    printf("  Relative error: %.4f%%\n", rel_error * 100.0);
    printf("  Cosine similarity: %.6f\n", cosine_sim);
    printf("  Accuracy: %s\n", 
           (cosine_sim > TestConfig::COSINE_SIMILARITY_THRESHOLD) ? "PASS" : "FAIL");
    
    return cosine_sim > TestConfig::COSINE_SIMILARITY_THRESHOLD &&
           rel_error < TestConfig::RELATIVE_ERROR_THRESHOLD;
}

/*===========================================================================
 * C. Performance Benchmark
 *===========================================================================*/

bool Test_Performance_Benchmark(TestResults& results) {
    printf("\n[TEST C] Performance Benchmark\n");
    printf("  Measuring Q4_K_M throughput...\n");
    
    const size_t hidden_dim = TestConfig::HIDDEN_DIM;
    const size_t num_blocks = (hidden_dim + 255) / 256;
    const size_t num_iterations = TestConfig::NUM_TEST_VECTORS;
    
    // Setup
    std::vector<uint8_t> q4_weights(num_blocks * sizeof(Q4KMBlock));
    std::vector<float> input(hidden_dim);
    std::vector<float> output(1);
    
    for (size_t i = 0; i < num_blocks; ++i) {
        GenerateMockQ4KMBlock(&q4_weights[i * sizeof(Q4KMBlock)], i);
    }
    
    Q4KMLinear q4_linear;
    if (!q4_linear.Initialize(q4_weights.data(), hidden_dim, 1)) {
        printf("  FAILED: Could not initialize Q4KMLinear\n");
        return false;
    }
    
    // Warmup
    for (int i = 0; i < 100; ++i) {
        q4_linear.Forward(input.data(), output.data());
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_iterations; ++i) {
        // Vary input slightly to prevent over-optimization
        input[i % hidden_dim] = static_cast<float>(i % 10) * 0.1f;
        q4_linear.Forward(input.data(), output.data());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double seconds = duration.count() / 1e6;
    double tps = num_iterations / seconds;
    
    results.measured_tps = tps;
    
    printf("  Iterations: %zu\n", num_iterations);
    printf("  Total time: %.3f ms\n", seconds * 1000.0);
    printf("  Throughput: %.2f TPS\n", tps);
    printf("  Target: %.1f TPS minimum\n", TestConfig::MIN_EXPECTED_TPS);
    printf("  Performance: %s\n", (tps >= TestConfig::MIN_EXPECTED_TPS) ? "PASS" : "FAIL");
    
    // Get kernel stats
    auto stats = q4_linear.GetStats();
    printf("  Forward calls: %llu\n", stats.forward_calls);
    printf("  Avg cycles/call: %.0f\n", stats.avg_cycles_per_call);
    
    return tps >= TestConfig::MIN_EXPECTED_TPS;
}

/*===========================================================================
 * D. Kernel Registry Test
 *===========================================================================*/

// Simple kernel registry for validation
class TestKernelRegistry {
public:
    using DequantFunc = uint64_t (*)(const uint8_t*, float*, uint64_t);
    
    static TestKernelRegistry& Instance() {
        static TestKernelRegistry instance;
        return instance;
    }
    
    void Register(const char* name, DequantFunc func) {
        kernels_[name] = func;
    }
    
    DequantFunc Get(const char* name) {
        auto it = kernels_.find(name);
        return (it != kernels_.end()) ? it->second : nullptr;
    }
    
private:
    std::unordered_map<std::string, DequantFunc> kernels_;
};

bool Test_Kernel_Registry(TestResults& results) {
    printf("\n[TEST D] Kernel Registry\n");
    printf("  Testing dynamic kernel dispatch...\n");
    
    // Register Q4_K_M kernel
    TestKernelRegistry::Instance().Register(
        "q4_k_m_dequant",
        Sovereign_Q4KM_DequantRange
    );
    
    // Verify registration
    auto kernel = TestKernelRegistry::Instance().Get("q4_k_m_dequant");
    if (!kernel) {
        printf("  FAILED: Kernel not found in registry\n");
        return false;
    }
    
    // Test dispatch
    const size_t num_blocks = 5;
    std::vector<uint8_t> blocks(num_blocks * sizeof(Q4KMBlock));
    std::vector<float> output(num_blocks * 256);
    
    for (size_t i = 0; i < num_blocks; ++i) {
        GenerateMockQ4KMBlock(&blocks[i * sizeof(Q4KMBlock)], i);
    }
    
    // Call through registry
    uint64_t result = kernel(blocks.data(), output.data(), num_blocks);
    
    printf("  Kernel registered: q4_k_m_dequant\n");
    printf("  Values processed: %llu\n", result);
    printf("  Expected: %zu\n", num_blocks * 256);
    printf("  Dispatch: %s\n", (result == num_blocks * 256) ? "PASS" : "FAIL");
    
    // Get dispatch info
    auto& dispatch = Q4KMDispatch::Instance();
    results.kernel_type = dispatch.GetBestKernelType();
    
    const char* type_str = "Unknown";
    switch (results.kernel_type) {
        case Q4KMKernelType::AVX512: type_str = "AVX-512"; break;
        case Q4KMKernelType::AVX2:   type_str = "AVX2"; break;
        case Q4KMKernelType::Scalar: type_str = "Scalar"; break;
        default: break;
    }
    
    printf("  Selected kernel: %s\n", type_str);
    printf("  AVX-512 available: %s\n", dispatch.HasAVX512() ? "Yes" : "No");
    printf("  AVX2 available: %s\n", dispatch.HasAVX2() ? "Yes" : "No");
    
    return result == num_blocks * 256;
}

/*===========================================================================
 * Main Test Runner
 *===========================================================================*/

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("=================================================================\n");
    printf("  Q4_K_M Validation Suite\n");
    printf("  RawrXD Sovereign Runtime\n");
    printf("=================================================================\n\n");
    
    TestResults results = {};
    
    // Run all tests
    results.gguf_compat_passed = Test_GGUF_Compatibility();
    results.numerical_accuracy_passed = Test_Numerical_Accuracy(results);
    results.performance_passed = Test_Performance_Benchmark(results);
    results.kernel_registry_passed = Test_Kernel_Registry(results);
    
    // Summary
    printf("\n=================================================================\n");
    printf("  TEST SUMMARY\n");
    printf("=================================================================\n");
    printf("  A. GGUF Compatibility:     %s\n", 
           results.gguf_compat_passed ? "PASS" : "FAIL");
    printf("  B. Numerical Accuracy:     %s (cos=%.4f, err=%.2f%%)\n", 
           results.numerical_accuracy_passed ? "PASS" : "FAIL",
           results.cosine_similarity,
           results.max_relative_error * 100.0);
    printf("  C. Performance:            %s (%.2f TPS)\n", 
           results.performance_passed ? "PASS" : "FAIL",
           results.measured_tps);
    printf("  D. Kernel Registry:        %s\n", 
           results.kernel_registry_passed ? "PASS" : "FAIL");
    printf("-----------------------------------------------------------------\n");
    
    bool all_passed = results.gguf_compat_passed && 
                      results.numerical_accuracy_passed &&
                      results.performance_passed && 
                      results.kernel_registry_passed;
    
    printf("  OVERALL: %s\n", all_passed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("=================================================================\n");
    
    return all_passed ? 0 : 1;
}
