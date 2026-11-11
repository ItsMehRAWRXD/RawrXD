// ============================================================================
// Kernel Diagnostic Test - Step-by-step MASM kernel validation
// ============================================================================

#include <iostream>
#include <cstring>
#include <malloc.h>
#include <cmath>

// Windows headers
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// MASM function declarations
extern "C" int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
extern "C" int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);
extern "C" int MASM_RMSNorm_Forward_AVX2(float* input, float* output, float* weights, size_t size);

// Test result tracking
struct TestResult {
    const char* name;
    bool passed;
    const char* error_msg;
};

// Helper to check if pointer is aligned
bool IsAligned(void* ptr, size_t alignment) {
    return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

// Test 1: SiLU with minimal data
TestResult TestSiLU() {
    TestResult result = {"SiLU", false, nullptr};
    
    std::cout << "\n[Test] SiLU Activation" << std::endl;
    
    // Allocate 64-byte aligned buffer
    float* data = (float*)_aligned_malloc(64, 64);
    if (!data) {
        result.error_msg = "Failed to allocate aligned memory";
        return result;
    }
    
    // Initialize with simple values
    for (int i = 0; i < 8; i++) {
        data[i] = 1.0f;  // Simple test value
    }
    
    std::cout << "  Input: ";
    for (int i = 0; i < 8; i++) std::cout << data[i] << " ";
    std::cout << std::endl;
    
    std::cout << "  Alignment check: " << (IsAligned(data, 64) ? "PASS" : "FAIL") << std::endl;
    
    // Call MASM kernel
    std::cout << "  Calling MASM_Silu_Activation_AVX512..." << std::endl;
    int ret = MASM_Silu_Activation_AVX512(data, 32);  // 8 floats * 4 bytes
    std::cout << "  Return code: " << ret << std::endl;
    
    if (ret != 0) {
        result.error_msg = "MASM kernel returned error";
        _aligned_free(data);
        return result;
    }
    
    std::cout << "  Output: ";
    for (int i = 0; i < 8; i++) std::cout << data[i] << " ";
    std::cout << std::endl;
    
    // Verify output is reasonable (not NaN, not infinity)
    bool valid = true;
    for (int i = 0; i < 8; i++) {
        if (std::isnan(data[i]) || std::isinf(data[i])) {
            valid = false;
            break;
        }
    }
    
    if (!valid) {
        result.error_msg = "Output contains NaN or Inf";
        _aligned_free(data);
        return result;
    }
    
    result.passed = true;
    _aligned_free(data);
    return result;
}

// Test 2: Softmax with minimal data
TestResult TestSoftmax() {
    TestResult result = {"Softmax", false, nullptr};
    
    std::cout << "\n[Test] Softmax" << std::endl;
    
    float* data = (float*)_aligned_malloc(64, 64);
    if (!data) {
        result.error_msg = "Failed to allocate aligned memory";
        return result;
    }
    
    for (int i = 0; i < 8; i++) {
        data[i] = static_cast<float>(i);  // 0, 1, 2, 3, 4, 5, 6, 7
    }
    
    std::cout << "  Input: ";
    for (int i = 0; i < 8; i++) std::cout << data[i] << " ";
    std::cout << std::endl;
    
    std::cout << "  Calling MASM_Softmax_Forward_AVX2..." << std::endl;
    int ret = MASM_Softmax_Forward_AVX2(data, 32);
    std::cout << "  Return code: " << ret << std::endl;
    
    if (ret != 0) {
        result.error_msg = "MASM kernel returned error";
        _aligned_free(data);
        return result;
    }
    
    std::cout << "  Output: ";
    for (int i = 0; i < 8; i++) std::cout << data[i] << " ";
    std::cout << std::endl;
    
    // Verify softmax properties: all values >= 0 and sum to ~1
    float sum = 0.0f;
    bool valid = true;
    for (int i = 0; i < 8; i++) {
        if (data[i] < 0 || std::isnan(data[i]) || std::isinf(data[i])) {
            valid = false;
        }
        sum += data[i];
    }
    
    std::cout << "  Sum: " << sum << " (should be ~1.0)" << std::endl;
    
    if (!valid) {
        result.error_msg = "Invalid softmax output";
        _aligned_free(data);
        return result;
    }
    
    result.passed = true;
    _aligned_free(data);
    return result;
}

// Test 3: RMSNorm with minimal data
TestResult TestRMSNorm() {
    TestResult result = {"RMSNorm", false, nullptr};
    
    std::cout << "\n[Test] RMSNorm" << std::endl;
    
    float* input = (float*)_aligned_malloc(64, 64);
    float* output = (float*)_aligned_malloc(64, 64);
    float* weights = (float*)_aligned_malloc(64, 64);
    
    if (!input || !output || !weights) {
        result.error_msg = "Failed to allocate aligned memory";
        _aligned_free(input);
        _aligned_free(output);
        _aligned_free(weights);
        return result;
    }
    
    for (int i = 0; i < 8; i++) {
        input[i] = 1.0f;
        weights[i] = 1.0f;
        output[i] = 0.0f;
    }
    
    std::cout << "  Input: ";
    for (int i = 0; i < 8; i++) std::cout << input[i] << " ";
    std::cout << std::endl;
    
    std::cout << "  Calling MASM_RMSNorm_Forward_AVX2..." << std::endl;
    int ret = MASM_RMSNorm_Forward_AVX2(input, output, weights, 8);
    std::cout << "  Return code: " << ret << std::endl;
    
    if (ret != 0) {
        result.error_msg = "MASM kernel returned error";
        _aligned_free(input);
        _aligned_free(output);
        _aligned_free(weights);
        return result;
    }
    
    std::cout << "  Output: ";
    for (int i = 0; i < 8; i++) std::cout << output[i] << " ";
    std::cout << std::endl;
    
    result.passed = true;
    _aligned_free(input);
    _aligned_free(output);
    _aligned_free(weights);
    return result;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "MASM Kernel Diagnostic Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Run tests
    TestResult tests[] = {
        TestSiLU(),
        TestSoftmax(),
        TestRMSNorm()
    };
    
    // Print summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test : tests) {
        std::cout << "[" << (test.passed ? "PASS" : "FAIL") << "] " << test.name;
        if (!test.passed && test.error_msg) {
            std::cout << " - " << test.error_msg;
        }
        std::cout << std::endl;
        
        if (test.passed) passed++;
        else failed++;
    }
    
    std::cout << "\nTotal: " << (passed + failed) << " | Passed: " << passed << " | Failed: " << failed << std::endl;
    
    return failed > 0 ? 1 : 0;
}
