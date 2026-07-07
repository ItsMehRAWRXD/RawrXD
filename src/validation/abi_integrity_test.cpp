// ============================================================================
// abi_integrity_test.cpp - ABI Compliance Test for MASM Kernels
// ============================================================================
// 
// PURPOSE: Test MASM kernels for ABI compliance before production deployment
// 
// This test:
// 1. Creates test data with known values
// 2. Calls the ABI integrity wrapper to check register preservation
// 3. Reports any ABI violations (non-volatile register corruption)
// 4. Validates functional correctness
// 
// CRITICAL: Run this test before deploying MASM kernels to production!
// 
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <immintrin.h>
#include <intrin.h>  // For __cpuid intrinsic

#include "kernels/masm_kernels.hpp"
#include "kernels/abi_integrity_wrapper.hpp"

using namespace RawrXD::Kernels;

// ============================================================================
// Test Data Generation
// ============================================================================

void GenerateTestData(float* data, size_t count, float start = -4.0f, float end = 4.0f) {
    float step = (end - start) / (count - 1);
    for (size_t i = 0; i < count; ++i) {
        data[i] = start + i * step;
    }
}

// ============================================================================
// Functional Correctness Test
// ============================================================================

bool TestFunctionalCorrectness_Silu(float* data, size_t count) {
    std::cout << "\n=== Functional Correctness Test (SiLU) ===" << std::endl;
    
    // Save original data for comparison
    std::vector<float> original(data, data + count);
    
    // Call MASM kernel
    int result = MASM_Silu_Activation_AVX512(data, count * sizeof(float));
    
    if (result != 0) {
        std::cout << "❌ FAIL: MASM kernel returned error code " << result << std::endl;
        return false;
    }
    
    // Verify results
    bool all_correct = true;
    float max_error = 0.0f;
    
    for (size_t i = 0; i < count; ++i) {
        float x = original[i];
        
        // Expected SiLU: x * sigmoid(x)
        // For x < -2: result ≈ 0
        // For x > 2: result ≈ x
        // For -2 ≤ x ≤ 2: use polynomial approximation
        
        float expected;
        if (x < -2.0f) {
            expected = 0.0f;
        } else if (x > 2.0f) {
            expected = x;
        } else {
            // Polynomial approximation (from MASM kernel)
            float x2 = x * x;
            float x3 = x2 * x;
            float x5 = x3 * x2;
            float x7 = x5 * x2;
            float x9 = x7 * x2;
            
            float sigmoid = 0.5f + 0.25f * x - 0.0208f * x3 + 0.00206f * x5 
                          - 0.000196f * x7 + 0.000016f * x9;
            
            expected = x * sigmoid;
        }
        
        float error = std::abs(data[i] - expected);
        max_error = std::max(max_error, error);
        
        if (error > 1e-5f) {
            if (all_correct) {
                std::cout << "❌ FAIL: Functional errors detected:" << std::endl;
                all_correct = false;
            }
            
            if (i < 10) {  // Only print first 10 errors
                std::cout << "  data[" << i << "]: expected " << expected 
                          << ", got " << data[i] << ", error " << error << std::endl;
            }
        }
    }
    
    if (all_correct) {
        std::cout << "✅ PASS: All values correct (max error: " << max_error << ")" << std::endl;
    } else {
        std::cout << "❌ FAIL: Max error: " << max_error << std::endl;
    }
    
    return all_correct;
}

// ============================================================================
// ABI Compliance Test
// ============================================================================

bool TestABICompliance_Silu(float* data, size_t count) {
    std::cout << "\n=== ABI Compliance Test (SiLU) ===" << std::endl;
    
    // Call the ABI integrity test
    int result = TestABIIntegrity_Silu(data, count * sizeof(float));
    
    if (result == 0) {
        std::cout << "✅ PASS: ABI compliant (all non-volatile registers preserved)" << std::endl;
        return true;
    } else {
        std::cout << "❌ FAIL: ABI violations detected (see above for details)" << std::endl;
        return false;
    }
}

// ============================================================================
// Main Test Entry Point
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD MASM Kernel ABI Integrity Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Check CPU support for AVX2
    std::cout << "\n=== CPU Feature Check ===" << std::endl;
    
    int cpuinfo[4];
    __cpuid(cpuinfo, 0);
    std::cout << "CPUID Leaf 0: " << cpuinfo[0] << " " << cpuinfo[1] << " " 
              << cpuinfo[2] << " " << cpuinfo[3] << std::endl;
    
    __cpuid(cpuinfo, 1);
    bool has_avx = (cpuinfo[2] & (1 << 28)) != 0;
    std::cout << "AVX: " << (has_avx ? "Yes" : "No") << std::endl;
    
    // Allocate aligned test data (32-byte alignment for AVX2)
    constexpr size_t test_count = 1024;  // Test with 1024 floats
    alignas(32) float test_data[test_count];
    
    // Generate test data
    GenerateTestData(test_data, test_count, -4.0f, 4.0f);
    
    std::cout << "\nTest data: " << test_count << " floats from -4.0 to 4.0" << std::endl;
    std::cout << "Alignment: " << (reinterpret_cast<uintptr_t>(test_data) % 32) << " bytes" << std::endl;
    
    // Run tests
    bool functional_ok = TestFunctionalCorrectness_Silu(test_data, test_count);
    
    // Regenerate test data for ABI test
    GenerateTestData(test_data, test_count, -4.0f, 4.0f);
    bool abi_ok = TestABICompliance_Silu(test_data, test_count);
    
    // Final result
    std::cout << "\n========================================" << std::endl;
    std::cout << "=== FINAL RESULT ===" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (functional_ok && abi_ok) {
        std::cout << "✅ ALL TESTS PASSED" << std::endl;
        std::cout << "   - Functional correctness: PASS" << std::endl;
        std::cout << "   - ABI compliance: PASS" << std::endl;
        std::cout << "\n🎉 MASM kernel is PRODUCTION READY!" << std::endl;
        return 0;
    } else {
        std::cout << "❌ TESTS FAILED" << std::endl;
        std::cout << "   - Functional correctness: " << (functional_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "   - ABI compliance: " << (abi_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "\n⚠️  DO NOT DEPLOY - Fix issues before production!" << std::endl;
        return 1;
    }
}