//==============================================================================
// test_kernel_correctness.cpp
// Validate kernel numerical correctness: Scalar vs AVX2 vs AVX-512
//
// Compares optimized implementations against scalar reference
// Reports any numerical differences with detailed diagnostics
//
// Date: July 10, 2026
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <vector>
#include <string>

// Prevent Windows.h from defining min/max macros
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

extern "C" {
    #include "Sovereign_KernelDispatch.h"
}

//==============================================================================
// Test Configuration
//==============================================================================

struct TestConfig {
    float tolerance = 1e-4f;      // Maximum allowed difference
    float rel_tolerance = 1e-3f;  // Relative tolerance for large values
    size_t max_errors_to_print = 10;
    bool verbose = true;
};

struct TestResult {
    std::string name;
    bool passed;
    size_t total_elements;
    size_t error_count;
    float max_error;
    float avg_error;
    double execution_time_ms;
    std::string notes;
};

static std::vector<TestResult> g_results;
static TestConfig g_config;

//==============================================================================
// Timing Utilities
//==============================================================================

class Timer {
    LARGE_INTEGER freq, start, end;
public:
    Timer() { QueryPerformanceFrequency(&freq); }
    void Start() { QueryPerformanceCounter(&start); }
    void Stop() { QueryPerformanceCounter(&end); }
    double ElapsedMicroseconds() const {
        return ((end.QuadPart - start.QuadPart) * 1000000.0) / freq.QuadPart;
    }
    double ElapsedMilliseconds() const { return ElapsedMicroseconds() / 1000.0; }
};

//==============================================================================
// Scalar Reference Implementations
//==============================================================================

namespace Scalar {

int RMSNorm(const float* input, float* output, size_t n, float epsilon) {
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / n + epsilon);
    float inv_rms = 1.0f / rms;
    
    for (size_t i = 0; i < n; i++) {
        output[i] = input[i] * inv_rms;
    }
    return 0;
}

int LayerNorm(const float* input, float* output, size_t n, 
              const float* gamma, const float* beta, float epsilon) {
    // Mean
    float mean = 0.0f;
    for (size_t i = 0; i < n; i++) {
        mean += input[i];
    }
    mean /= n;
    
    // Variance
    float var = 0.0f;
    for (size_t i = 0; i < n; i++) {
        float diff = input[i] - mean;
        var += diff * diff;
    }
    var /= n;
    
    // Normalize
    float inv_std = 1.0f / std::sqrt(var + epsilon);
    for (size_t i = 0; i < n; i++) {
        float normalized = (input[i] - mean) * inv_std;
        output[i] = normalized * (gamma ? gamma[i] : 1.0f) + (beta ? beta[i] : 0.0f);
    }
    return 0;
}

int ResidualAdd(const float* a, const float* b, float* output,
                size_t n, float scale) {
    for (size_t i = 0; i < n; i++) {
        output[i] = a[i] + scale * b[i];
    }
    return 0;
}

int MatMulF32(const float* A, const float* B, float* C,
              size_t m, size_t n, size_t k) {
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (size_t l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
    return 0;
}

} // namespace Scalar

//==============================================================================
// Comparison Utilities
//==============================================================================

bool CompareFloats(float a, float b, float& out_error) {
    float diff = std::abs(a - b);
    
    // Absolute tolerance check
    if (diff <= g_config.tolerance) {
        out_error = diff;
        return true;
    }
    
    // Relative tolerance for large values
    float max_val = std::max(std::abs(a), std::abs(b));
    if (max_val > 1.0f && diff / max_val <= g_config.rel_tolerance) {
        out_error = diff / max_val;
        return true;
    }
    
    out_error = diff;
    return false;
}

void PrintComparisonFailure(const std::string& test_name, size_t index,
                           float expected, float actual, float error) {
    static size_t printed = 0;
    if (printed >= g_config.max_errors_to_print) return;
    
    printf("    [%s] Index %zu: expected=%.8f, actual=%.8f, error=%.8f\n",
           test_name.c_str(), index, expected, actual, error);
    printed++;
    
    if (printed == g_config.max_errors_to_print) {
        printf("    ... (suppressing further error output)\n");
    }
}

//==============================================================================
// Kernel Tests
//==============================================================================

TestResult TestRMSNorm() {
    TestResult result = {"RMSNorm", false, 0, 0, 0.0f, 0.0f, 0.0, ""};
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    if (!table.rms_norm_f32) {
        result.notes = "Kernel not available";
        return result;
    }
    
    // Test parameters
    const size_t n = 4096;  // Typical hidden size
    std::vector<float> input(n);
    std::vector<float> output_scalar(n);
    std::vector<float> output_optimized(n);
    std::vector<float> weight(n, 1.0f);  // Unit weights for simplicity
    
    // Initialize with test pattern
    for (size_t i = 0; i < n; i++) {
        input[i] = (float)(i % 100) / 100.0f + 0.1f;
    }
    
    // Compute scalar reference
    Timer timer;
    timer.Start();
    Scalar::RMSNorm(input.data(), output_scalar.data(), n, 1e-6f);
    timer.Stop();
    double scalar_time = timer.ElapsedMilliseconds();
    
    // Compute optimized version
    timer.Start();
    int ret = table.rms_norm_f32(const_cast<float*>(input.data()), 
                                  output_optimized.data(),
                                  weight.data(), n, 1e-6f);
    timer.Stop();
    double opt_time = timer.ElapsedMilliseconds();
    
    if (ret != 0) {
        result.notes = "Kernel returned error: " + std::to_string(ret);
        return result;
    }
    
    // Compare results
    result.total_elements = n;
    float max_err = 0.0f;
    float sum_err = 0.0f;
    size_t errors = 0;
    
    for (size_t i = 0; i < n; i++) {
        float err;
        if (!CompareFloats(output_scalar[i], output_optimized[i], err)) {
            errors++;
            PrintComparisonFailure("RMSNorm", i, output_scalar[i], 
                                 output_optimized[i], err);
        }
        max_err = std::max(max_err, err);
        sum_err += err;
    }
    
    result.error_count = errors;
    result.max_error = max_err;
    result.avg_error = sum_err / n;
    result.execution_time_ms = opt_time;
    result.passed = (errors == 0);
    result.notes = "Scalar: " + std::to_string(scalar_time) + "ms, " +
                   "Optimized: " + std::to_string(opt_time) + "ms";
    
    return result;
}

TestResult TestLayerNorm() {
    TestResult result = {"LayerNorm", false, 0, 0, 0.0f, 0.0f, 0.0, ""};
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    if (!table.layer_norm_f32) {
        result.notes = "Kernel not available";
        return result;
    }
    
    const size_t n = 4096;
    std::vector<float> input(n);
    std::vector<float> output_scalar(n);
    std::vector<float> output_optimized(n);
    std::vector<float> gamma(n, 1.0f);
    std::vector<float> beta(n, 0.0f);
    
    for (size_t i = 0; i < n; i++) {
        input[i] = (float)(i % 100) / 100.0f + 0.1f;
    }
    
    // Scalar reference
    Timer timer;
    timer.Start();
    Scalar::LayerNorm(input.data(), output_scalar.data(), n, 
                      gamma.data(), beta.data(), 1e-6f);
    timer.Stop();
    double scalar_time = timer.ElapsedMilliseconds();
    
    // Optimized
    timer.Start();
    int ret = table.layer_norm_f32(const_cast<float*>(input.data()),
                                     output_optimized.data(),
                                     gamma.data(), beta.data(),
                                     n, 1e-6f);
    timer.Stop();
    double opt_time = timer.ElapsedMilliseconds();
    
    if (ret != 0) {
        result.notes = "Kernel returned error: " + std::to_string(ret);
        return result;
    }
    
    // Compare
    result.total_elements = n;
    float max_err = 0.0f;
    float sum_err = 0.0f;
    size_t errors = 0;
    
    for (size_t i = 0; i < n; i++) {
        float err;
        if (!CompareFloats(output_scalar[i], output_optimized[i], err)) {
            errors++;
            PrintComparisonFailure("LayerNorm", i, output_scalar[i],
                                 output_optimized[i], err);
        }
        max_err = std::max(max_err, err);
        sum_err += err;
    }
    
    result.error_count = errors;
    result.max_error = max_err;
    result.avg_error = sum_err / n;
    result.execution_time_ms = opt_time;
    result.passed = (errors == 0);
    result.notes = "Scalar: " + std::to_string(scalar_time) + "ms, " +
                   "Optimized: " + std::to_string(opt_time) + "ms";
    
    return result;
}

TestResult TestResidualAdd() {
    TestResult result = {"ResidualAdd", false, 0, 0, 0.0f, 0.0f, 0.0, ""};
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    if (!table.residual_add_f32) {
        result.notes = "Kernel not available";
        return result;
    }
    
    const size_t n = 4096;
    std::vector<float> input(n);
    std::vector<float> residual(n);
    std::vector<float> output_scalar(n);
    std::vector<float> output_optimized(n);
    
    for (size_t i = 0; i < n; i++) {
        input[i] = (float)(i % 50) / 50.0f;
        residual[i] = (float)(i % 30) / 100.0f;
    }
    
    // Scalar reference
    Timer timer;
    timer.Start();
    Scalar::ResidualAdd(input.data(), residual.data(), output_scalar.data(),
                        n, 1.0f);
    timer.Stop();
    double scalar_time = timer.ElapsedMilliseconds();
    
    // Optimized
    timer.Start();
    int ret = table.residual_add_f32(const_cast<float*>(input.data()),
                                       const_cast<float*>(residual.data()),
                                       output_optimized.data(), n);
    timer.Stop();
    double opt_time = timer.ElapsedMilliseconds();
    
    if (ret != 0) {
        result.notes = "Kernel returned error: " + std::to_string(ret);
        return result;
    }
    
    // Compare
    result.total_elements = n;
    float max_err = 0.0f;
    float sum_err = 0.0f;
    size_t errors = 0;
    
    for (size_t i = 0; i < n; i++) {
        float err;
        if (!CompareFloats(output_scalar[i], output_optimized[i], err)) {
            errors++;
            PrintComparisonFailure("ResidualAdd", i, output_scalar[i],
                                 output_optimized[i], err);
        }
        max_err = std::max(max_err, err);
        sum_err += err;
    }
    
    result.error_count = errors;
    result.max_error = max_err;
    result.avg_error = sum_err / n;
    result.execution_time_ms = opt_time;
    result.passed = (errors == 0);
    result.notes = "Scalar: " + std::to_string(scalar_time) + "ms, " +
                   "Optimized: " + std::to_string(opt_time) + "ms";
    
    return result;
}

TestResult TestMatMul() {
    TestResult result = {"MatMul", false, 0, 0, 0.0f, 0.0f, 0.0, ""};
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    // Check which implementation is available
    auto matmul_fn = table.q4q8_matmul_intrinsics ? table.q4q8_matmul_intrinsics 
                                                  : table.q4_0_q8_0_matmul;
    if (!matmul_fn) {
        result.notes = "No MatMul kernel available";
        return result;
    }
    
    // Small test (larger tests may have precision issues with quantization)
    const size_t m = 64, n = 64, k = 64;
    std::vector<float> A(m * k);
    std::vector<float> B(k * n);
    std::vector<float> C_scalar(m * n);
    std::vector<float> C_optimized(m * n);
    
    // Initialize with small values to avoid overflow
    for (size_t i = 0; i < m * k; i++) {
        A[i] = ((float)(i % 10) - 5.0f) / 10.0f;
    }
    for (size_t i = 0; i < k * n; i++) {
        B[i] = ((float)(i % 10) - 5.0f) / 10.0f;
    }
    
    // Scalar reference
    Timer timer;
    timer.Start();
    Scalar::MatMulF32(A.data(), B.data(), C_scalar.data(), m, n, k);
    timer.Stop();
    double scalar_time = timer.ElapsedMilliseconds();
    
    // Optimized (using float data - note: real kernels expect Q4/Q8 format)
    // This is a simplified test - full quantization test would need proper format
    timer.Start();
    int ret = matmul_fn(A.data(), B.data(), C_optimized.data(), m, n, k);
    timer.Stop();
    double opt_time = timer.ElapsedMilliseconds();
    
    if (ret != 0) {
        result.notes = "Kernel returned error: " + std::to_string(ret);
        return result;
    }
    
    // Compare (with relaxed tolerance for potential quantization differences)
    result.total_elements = m * n;
    float max_err = 0.0f;
    float sum_err = 0.0f;
    size_t errors = 0;
    
    // Use larger tolerance for MatMul due to potential quantization
    float matmul_tolerance = g_config.tolerance * 10.0f;
    
    for (size_t i = 0; i < m * n; i++) {
        float diff = std::abs(C_scalar[i] - C_optimized[i]);
        if (diff > matmul_tolerance) {
            errors++;
            if (errors <= g_config.max_errors_to_print) {
                printf("    [MatMul] Index %zu: expected=%.8f, actual=%.8f, error=%.8f\n",
                       i, C_scalar[i], C_optimized[i], diff);
            }
        }
        max_err = std::max(max_err, diff);
        sum_err += diff;
    }
    
    result.error_count = errors;
    result.max_error = max_err;
    result.avg_error = sum_err / (m * n);
    result.execution_time_ms = opt_time;
    result.passed = (errors == 0);
    result.notes = "Scalar: " + std::to_string(scalar_time) + "ms, " +
                   "Optimized: " + std::to_string(opt_time) + "ms, " +
                   (table.q4q8_matmul_intrinsics ? "Intrinsics" : "MASM");
    
    return result;
}

//==============================================================================
// Main
//==============================================================================

void PrintResult(const TestResult& result) {
    const char* status = result.passed ? "PASS" : 
                        (result.notes.find("not available") != std::string::npos ? "SKIP" : "FAIL");
    
    printf("\n[%s] %s\n", status, result.name.c_str());
    
    if (!result.notes.empty()) {
        printf("  Notes: %s\n", result.notes.c_str());
    }
    
    if (result.total_elements > 0) {
        printf("  Elements: %zu, Errors: %zu (%.4f%%)\n",
               result.total_elements, result.error_count,
               100.0f * result.error_count / result.total_elements);
        printf("  Max Error: %.8f, Avg Error: %.8f\n",
               result.max_error, result.avg_error);
        printf("  Time: %.3f ms\n", result.execution_time_ms);
    }
}

int main() {
    printf("==============================================================================\n");
    printf("Sovereign Kernel Correctness Validation\n");
    printf("==============================================================================\n");
    printf("\n");
    printf("Configuration:\n");
    printf("  Tolerance: %.1e (absolute)\n", g_config.tolerance);
    printf("  Relative Tolerance: %.1e\n", g_config.rel_tolerance);
    printf("\n");
    
    // Run tests
    g_results.push_back(TestRMSNorm());
    g_results.push_back(TestLayerNorm());
    g_results.push_back(TestResidualAdd());
    g_results.push_back(TestMatMul());
    
    // Print results
    printf("\n==============================================================================");
    printf("\nDETAILED RESULTS");
    printf("\n==============================================================================");
    
    for (const auto& result : g_results) {
        PrintResult(result);
    }
    
    // Summary
    printf("\n==============================================================================");
    printf("\nSUMMARY");
    printf("\n==============================================================================\n");
    
    int passed = 0, failed = 0, skipped = 0;
    for (const auto& result : g_results) {
        if (result.notes.find("not available") != std::string::npos) {
            skipped++;
        } else if (result.passed) {
            passed++;
        } else {
            failed++;
        }
    }
    
    printf("Total:  %zu tests\n", g_results.size());
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    printf("Skipped: %d\n", skipped);
    
    printf("\n==============================================================================\n");
    
    return (failed == 0) ? 0 : 1;
}
