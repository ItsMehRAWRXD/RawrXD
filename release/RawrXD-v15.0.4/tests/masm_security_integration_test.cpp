// ============================================================================
// MASM Security Integration Test
// Validates that AVX-512 kernels respect Fortress-Grade security boundaries
// ============================================================================

#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <chrono>

// Include the secure bridge
#include "../src/validation/kernels/masm_bridge_secure.hpp"

using namespace RawrXD::Kernels::Secure;

// ============================================================================
// Test Framework
// ============================================================================

struct TestResult {
    int passed = 0;
    int failed = 0;
    
    void record(bool success, const char* name) {
        if (success) {
            passed++;
            std::cout << "[PASS] " << name << std::endl;
        } else {
            failed++;
            std::cout << "[FAIL] " << name << std::endl;
        }
    }
    
    void summary() const {
        std::cout << "\n========================================\n";
        std::cout << "MASM Security Integration Test\n";
        std::cout << "Passed: " << passed << " | Failed: " << failed << "\n";
        std::cout << (failed == 0 ? "FORTRESS VALIDATED ✅" : "BREACH DETECTED ❌") << "\n";
        std::cout << "========================================\n";
    }
};

static TestResult g_results;

// ============================================================================
// Test 1: Null Pointer Protection
// ============================================================================
void testNullPointerProtection() {
    std::cout << "\n--- Test: Null Pointer Protection ---\n";
    
    // Test SiLU with null pointer
    {
        bool caught = false;
        try {
            SecureMASMKernelBridge::SiLU(nullptr, 1024);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "SiLU_NullPtr_Throws");
    }
    
    // Test RMSNorm with null input
    {
        bool caught = false;
        float valid[1024] = {0};
        try {
            SecureMASMKernelBridge::RMSNorm(nullptr, valid, valid, 1024);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "RMSNorm_NullInput_Throws");
    }
    
    // Test Softmax with null pointer
    {
        bool caught = false;
        try {
            SecureMASMKernelBridge::Softmax(nullptr, 1024);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "Softmax_NullPtr_Throws");
    }
}

// ============================================================================
// Test 2: Alignment Validation
// ============================================================================
void testAlignmentValidation() {
    std::cout << "\n--- Test: Alignment Validation ---\n";
    
    // Allocate unaligned buffer
    char raw_mem[2048];
    float* unaligned = reinterpret_cast<float*>(
        reinterpret_cast<uintptr_t>(raw_mem) + 4 // Force misalignment
    );
    
    // Test SiLU with misaligned pointer
    {
        bool caught = false;
        try {
            SecureMASMKernelBridge::SiLU(unaligned, 256);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "SiLU_Misaligned_Throws");
    }
    
    // Test alignment check function
    {
        float aligned[1024] __attribute__((aligned(64)));
        g_results.record(IsAligned(aligned, 64), "IsAligned_Valid");
        g_results.record(!IsAligned(unaligned, 64), "IsAligned_Invalid");
    }
}

// ============================================================================
// Test 3: Size Bounds Validation
// ============================================================================
void testSizeBoundsValidation() {
    std::cout << "\n--- Test: Size Bounds Validation ---\n";
    
    // Test zero size
    {
        float data[1024] __attribute__((aligned(64)));
        bool caught = false;
        try {
            SecureMASMKernelBridge::SiLU(data, 0);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "SiLU_ZeroSize_Throws");
    }
    
    // Test oversized (would exceed 100MB)
    {
        float data[1024] __attribute__((aligned(64)));
        bool caught = false;
        try {
            // Request more than MAX_KERNEL_ELEMENTS
            SecureMASMKernelBridge::SiLU(data, 30 * 1024 * 1024); // 30M floats > 25M limit
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "SiLU_Oversized_Throws");
    }
    
    // Test valid size
    {
        float data[1024] __attribute__((aligned(64)));
        bool valid = IsValidElementCount(1024);
        g_results.record(valid, "Size_Valid_1024");
    }
    
    // Test clamping
    {
        size_t clamped = ClampElementCount(100);
        g_results.record(clamped == 96, "Clamp_RoundsDown"); // 100 -> 96 (multiple of 8)
    }
}

// ============================================================================
// Test 4: Buffer Overlap Detection
// ============================================================================
void testBufferOverlap() {
    std::cout << "\n--- Test: Buffer Overlap Detection ---\n";
    
    // Test RMSNorm with overlapping buffers
    {
        float data[1024] __attribute__((aligned(64)));
        float weights[1024] __attribute__((aligned(64)));
        
        bool caught = false;
        try {
            // Pass same pointer for input and output
            SecureMASMKernelBridge::RMSNorm(data, data, weights, 1024);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "RMSNorm_Overlap_Throws");
    }
}

// ============================================================================
// Test 5: Integer Overflow Protection
// ============================================================================
void testIntegerOverflow() {
    std::cout << "\n--- Test: Integer Overflow Protection ---\n";
    
    // Test size_t overflow detection
    {
        float data[1024] __attribute__((aligned(64)));
        bool caught = false;
        try {
            // This would overflow size_t * sizeof(float)
            SecureMASMKernelBridge::SiLU(data, SIZE_MAX / sizeof(float) + 1);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        g_results.record(caught, "SiLU_Overflow_Throws");
    }
}

// ============================================================================
// Test 6: Security Limit Constants
// ============================================================================
void testSecurityLimits() {
    std::cout << "\n--- Test: Security Limit Constants ---\n";
    
    size_t max_elems, min_elems, alignment;
    GetSecurityLimits(max_elems, min_elems, alignment);
    
    // Verify constants match Phase 7a hardening
    g_results.record(max_elems == 100 * 1024 * 1024 / sizeof(float), "MaxElements_100MB");
    g_results.record(min_elems == 8, "MinElements_AVX2");
    g_results.record(alignment == 64, "Alignment_AVX512");
}

// ============================================================================
// Test 7: C Wrapper Security
// ============================================================================
void testCWrapperSecurity() {
    std::cout << "\n--- Test: C Wrapper Security ---\n";
    
    // Test C wrappers return error codes instead of throwing
    {
        int result = Secure_MASM_SiLU(nullptr, 1024);
        g_results.record(result != 0, "CWrapper_NullPtr_ReturnsError");
    }
    
    {
        float data[1024] __attribute__((aligned(64)));
        int result = Secure_MASM_SiLU(data, 0);
        g_results.record(result != 0, "CWrapper_ZeroSize_ReturnsError");
    }
}

// ============================================================================
// Test 8: Validation Without Dispatch
// ============================================================================
void testValidationOnly() {
    std::cout << "\n--- Test: Validation Without Dispatch ---\n";
    
    float valid[1024] __attribute__((aligned(64)));
    float unaligned[1024];
    
    // Force unalignment
    float* misaligned = reinterpret_cast<float*>(
        reinterpret_cast<uintptr_t>(unaligned) + 4
    );
    
    g_results.record(ValidateKernelInputs(valid, 1024), "Validate_Valid");
    g_results.record(!ValidateKernelInputs(nullptr, 1024), "Validate_Null");
    g_results.record(!ValidateKernelInputs(misaligned, 1024), "Validate_Misaligned");
    g_results.record(!ValidateKernelInputs(valid, 0), "Validate_ZeroSize");
    g_results.record(!ValidateKernelInputs(valid, 7), "Validate_UnderMin");
}

// ============================================================================
// Main Entry
// ============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "MASM Security Integration Test\n";
    std::cout << "Validating AVX-512 Kernel Security\n";
    std::cout << "========================================\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    testNullPointerProtection();
    testAlignmentValidation();
    testSizeBoundsValidation();
    testBufferOverlap();
    testIntegerOverflow();
    testSecurityLimits();
    testCWrapperSecurity();
    testValidationOnly();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    g_results.summary();
    std::cout << "Execution Time: " << duration.count() << "ms\n";
    
    return g_results.failed == 0 ? 0 : 1;
}
