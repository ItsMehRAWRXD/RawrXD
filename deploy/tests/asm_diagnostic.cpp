// ============================================================================
// Assembly Diagnostic Test
// Verifies MASM kernels are linked and callable
// ============================================================================

#include <iostream>
#include <cstddef>
#include <malloc.h>
#include <cstring>

// Assembly functions
extern "C" {
    int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
    int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Assembly Diagnostic Test\n";
    std::cout << "========================================\n";
    
    // Test SiLU
    {
        std::cout << "\n--- Testing SiLU AVX-512 ---\n";
        
        // Allocate aligned buffer
        float* data = (float*)_aligned_malloc(64 * sizeof(float), 64);
        if (!data) {
            std::cout << "FAILED: Could not allocate aligned buffer\n";
            return 1;
        }
        
        // Initialize with test values
        for (int i = 0; i < 16; i++) {
            data[i] = 1.0f;
        }
        
        std::cout << "Input[0]: " << data[0] << "\n";
        std::cout << "Calling MASM_Silu_Activation_AVX512...\n";
        
        int result = MASM_Silu_Activation_AVX512(data, 64); // 16 floats * 4 bytes
        
        std::cout << "Return code: " << result << "\n";
        std::cout << "Output[0]: " << data[0] << "\n";
        std::cout << "Expected: ~0.731 (sigmoid(1) * 1)\n";
        
        _aligned_free(data);
        
        if (result == 0) {
            std::cout << "✅ SiLU PASSED\n";
        } else {
            std::cout << "❌ SiLU FAILED with code " << result << "\n";
        }
    }
    
    // Test Softmax
    {
        std::cout << "\n--- Testing Softmax AVX2 ---\n";
        
        float* data = (float*)_aligned_malloc(32 * sizeof(float), 32);
        if (!data) {
            std::cout << "FAILED: Could not allocate aligned buffer\n";
            return 1;
        }
        
        // Initialize with test values
        for (int i = 0; i < 8; i++) {
            data[i] = (float)i;
        }
        
        std::cout << "Input: [0, 1, 2, 3, 4, 5, 6, 7]\n";
        std::cout << "Calling MASM_Softmax_Forward_AVX2...\n";
        
        int result = MASM_Softmax_Forward_AVX2(data, 32); // 8 floats * 4 bytes
        
        std::cout << "Return code: " << result << "\n";
        std::cout << "Output: [";
        for (int i = 0; i < 8; i++) {
            std::cout << data[i];
            if (i < 7) std::cout << ", ";
        }
        std::cout << "]\n";
        
        // Check sum = 1
        float sum = 0;
        for (int i = 0; i < 8; i++) sum += data[i];
        std::cout << "Sum: " << sum << " (should be ~1.0)\n";
        
        _aligned_free(data);
        
        if (result == 0) {
            std::cout << "✅ Softmax PASSED\n";
        } else {
            std::cout << "❌ Softmax FAILED with code " << result << "\n";
        }
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Diagnostic Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
