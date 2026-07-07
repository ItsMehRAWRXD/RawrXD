// ============================================================================
// masm_kernels_simple_test.cpp
// ============================================================================
// Simple test to verify MASM kernel basic functionality
// ============================================================================

#include <iostream>
#include <cstdint>

#include "masm_kernels.hpp"

using namespace RawrXD;

int main() {
    std::cout << "============================================================================" << std::endl;
    std::cout << "MASM AVX-512 Kernels Simple Test" << std::endl;
    std::cout << "============================================================================" << std::endl;
    
    // Allocate aligned buffer (32-byte for AVX2, 64-byte for AVX-512)
    constexpr size_t COUNT = 8;  // Just 8 floats (one YMM register for AVX2)
    alignas(32) float buffer[COUNT];
    
    // Initialize with simple values
    for (size_t i = 0; i < COUNT; ++i) {
        buffer[i] = static_cast<float>(i) * 0.1f;
    }
    
    std::cout << "\nInput values:" << std::endl;
    for (size_t i = 0; i < COUNT; ++i) {
        std::cout << "  buffer[" << i << "] = " << buffer[i] << std::endl;
    }
    
    std::cout << "\nCalling MASM_Silu_Activation_AVX512..." << std::endl;
    
    // Call MASM kernel (AVX2 version processes 8 floats at a time)
    int result = MASM_Silu_Activation_AVX512(buffer, COUNT * sizeof(float));
    
    std::cout << "Return value: " << result << std::endl;
    
    if (result != 0) {
        std::cerr << "❌ MASM kernel returned error: " << result << std::endl;
        return 1;
    }
    
    std::cout << "\nOutput values:" << std::endl;
    for (size_t i = 0; i < COUNT; ++i) {
        std::cout << "  buffer[" << i << "] = " << buffer[i] << std::endl;
    }
    
    std::cout << "\n✅ Test passed!" << std::endl;
    return 0;
}