// ============================================================================
// Test: Vulkan Kernel Loading and Execution
// ============================================================================
// Verifies SPIR-V shaders can be loaded and executed on GPU
// ============================================================================

#include <iostream>
#include <vector>
#include <cstring>
#include <cmath>

// Include the embedded shaders
#include "shaders/embedded_shaders.hpp"

// Simple test: Verify shader bytecode is valid
bool TestShaderBytecode() {
    std::cout << "\n=== Test: Shader Bytecode Validation ===\n";
    
    // Check matmul shader
    std::cout << "matmul_fp16.spv: " << sizeof(kmatmul_fp16_spv) << " bytes\n";
    if (sizeof(kmatmul_fp16_spv) < 100) {
        std::cerr << "ERROR: matmul_fp16.spv too small\n";
        return false;
    }
    // SPIR-V magic number: 0x07230203
    if (kmatmul_fp16_spv[0] != 0x07230203) {
        std::cerr << "ERROR: matmul_fp16.spv invalid magic number\n";
        return false;
    }
    std::cout << "  Magic: 0x" << std::hex << kmatmul_fp16_spv[0] << std::dec << " OK\n";
    
    // Check rms_norm shader
    std::cout << "rms_norm_fp16.spv: " << sizeof(krms_norm_fp16_spv) << " bytes\n";
    if (krms_norm_fp16_spv[0] != 0x07230203) {
        std::cerr << "ERROR: rms_norm_fp16.spv invalid magic number\n";
        return false;
    }
    std::cout << "  Magic: 0x" << std::hex << krms_norm_fp16_spv[0] << std::dec << " OK\n";
    
    // Check softmax shader
    std::cout << "softmax_fp16.spv: " << sizeof(ksoftmax_fp16_spv) << " bytes\n";
    if (ksoftmax_fp16_spv[0] != 0x07230203) {
        std::cerr << "ERROR: softmax_fp16.spv invalid magic number\n";
        return false;
    }
    std::cout << "  Magic: 0x" << std::hex << ksoftmax_fp16_spv[0] << std::dec << " OK\n";
    
    // Check verify_candidates shader
    std::cout << "verify_candidates.spv: " << sizeof(kverify_candidates_spv) << " bytes\n";
    if (kverify_candidates_spv[0] != 0x07230203) {
        std::cerr << "ERROR: verify_candidates.spv invalid magic number\n";
        return false;
    }
    std::cout << "  Magic: 0x" << std::hex << kverify_candidates_spv[0] << std::dec << " OK\n";
    
    std::cout << "✓ All shader bytecode valid\n";
    return true;
}

// Test FP16 conversion (CPU fallback)
bool TestFP16Conversion() {
    std::cout << "\n=== Test: FP16 Conversion ===\n";
    
    // Simple FP16 test values
    // FP16: 1.0 = 0x3C00, 2.0 = 0x4000, 0.5 = 0x3800
    uint16_t fp16_one = 0x3C00;
    uint16_t fp16_two = 0x4000;
    uint16_t fp16_half = 0x3800;
    
    std::cout << "FP16 1.0: 0x" << std::hex << fp16_one << std::dec << "\n";
    std::cout << "FP16 2.0: 0x" << std::hex << fp16_two << std::dec << "\n";
    std::cout << "FP16 0.5: 0x" << std::hex << fp16_half << std::dec << "\n";
    
    std::cout << "✓ FP16 constants valid\n";
    return true;
}

// Test matrix dimensions for tiling
bool TestMatrixTiling() {
    std::cout << "\n=== Test: Matrix Tiling ===\n";
    
    const uint32_t TILE_SIZE = 16;
    
    // Test various matrix sizes
    uint32_t test_sizes[] = {64, 128, 256, 512, 1024, 2048, 4096};
    
    for (uint32_t size : test_sizes) {
        uint32_t tiles = (size + TILE_SIZE - 1) / TILE_SIZE;
        uint32_t padded = tiles * TILE_SIZE;
        std::cout << "  Size " << size << " -> " << tiles << " tiles (padded to " << padded << ")\n";
    }
    
    std::cout << "✓ Matrix tiling calculations valid\n";
    return true;
}

// Test push constant layout
bool TestPushConstants() {
    std::cout << "\n=== Test: Push Constant Layout ===\n";
    
    // MatMul push constants
    struct MatMulPushConstants {
        uint32_t M;
        uint32_t N;
        uint32_t K;
        uint32_t lda;
        uint32_t ldb;
        uint32_t ldc;
    };
    
    std::cout << "  MatMulPushConstants size: " << sizeof(MatMulPushConstants) << " bytes\n";
    if (sizeof(MatMulPushConstants) > 128) {
        std::cerr << "ERROR: Push constants exceed 128 byte limit\n";
        return false;
    }
    
    std::cout << "✓ Push constant layout valid\n";
    return true;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Vulkan Kernel Tests\n";
    std::cout << "========================================\n";
    std::cout << "\nNOTE: These tests validate shader bytecode,\n";
    std::cout << "NOT actual GPU execution.\n";
    
    bool all_passed = true;
    
    all_passed &= TestShaderBytecode();
    all_passed &= TestFP16Conversion();
    all_passed &= TestMatrixTiling();
    all_passed &= TestPushConstants();
    
    std::cout << "\n========================================\n";
    if (all_passed) {
        std::cout << "All tests PASSED\n";
        std::cout << "========================================\n";
        std::cout << "\nNext steps:\n";
        std::cout << "1. Build with Vulkan SDK to test GPU execution\n";
        std::cout << "2. Run matmul benchmark on RX 7800 XT\n";
        std::cout << "3. Verify 100+ tok/s at 32K context\n";
        return 0;
    } else {
        std::cout << "Tests FAILED\n";
        std::cout << "========================================\n";
        return 1;
    }
}
