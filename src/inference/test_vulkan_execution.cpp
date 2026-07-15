// ============================================================================
// Test: Vulkan GPU Execution
// ============================================================================
// Actually runs SPIR-V shaders on the RX 7800 XT
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>
#include <chrono>

// Include the Vulkan executor
#include "vulkan_executor_impl.cpp"

using namespace RawrXD::Inference;

bool TestMatMulSmall() {
    std::cout << "\n=== Test: MatMul 4x4 ===\n";
    
    VulkanExecutor executor;
    if (!executor.Initialize()) {
        std::cerr << "Failed to initialize Vulkan executor\n";
        return false;
    }
    
    std::cout << "GPU: " << executor.GetDeviceName() << "\n";
    
    // Small test: 4x4 * 4x4 = 4x4
    const uint32_t M = 4, N = 4, K = 4;
    
    std::vector<float> A = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };
    
    std::vector<float> B = {
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1
    };
    
    std::vector<float> C(M * N);
    
    // Execute on GPU
    if (!executor.ExecuteMatMulFP16(A, B, C, M, N, K)) {
        std::cerr << "MatMul execution failed\n";
        return false;
    }
    
    // Verify result (A * I = A)
    bool passed = true;
    for (uint32_t i = 0; i < M; i++) {
        for (uint32_t j = 0; j < N; j++) {
            float expected = A[i * K + j];
            float actual = C[i * N + j];
            float diff = std::abs(expected - actual);
            if (diff > 0.1f) {  // FP16 has limited precision
                std::cout << "  Mismatch at [" << i << "," << j << "]: expected " 
                          << expected << ", got " << actual << " (diff: " << diff << ")\n";
                passed = false;
            }
        }
    }
    
    if (passed) {
        std::cout << "✓ MatMul 4x4 passed\n";
    } else {
        std::cout << "✗ MatMul 4x4 failed\n";
    }
    
    return passed;
}

bool TestMatMulMedium() {
    std::cout << "\n=== Test: MatMul 64x64 ===\n";
    
    VulkanExecutor executor;
    if (!executor.Initialize()) {
        std::cerr << "Failed to initialize Vulkan executor\n";
        return false;
    }
    
    // Medium test: 64x64 * 64x64 = 64x64
    const uint32_t M = 64, N = 64, K = 64;
    
    // Create identity matrix
    std::vector<float> A(M * K, 1.0f);  // All ones
    std::vector<float> B(K * N);
    for (uint32_t i = 0; i < N; i++) {
        B[i * N + i] = 1.0f;  // Identity
    }
    std::vector<float> C(M * N);
    
    // Execute on GPU
    auto start = std::chrono::high_resolution_clock::now();
    if (!executor.ExecuteMatMulFP16(A, B, C, M, N, K)) {
        std::cerr << "MatMul execution failed\n";
        return false;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "  Execution time: " << duration.count() << " μs\n";
    
    // Verify result (all ones * identity = all ones)
    bool passed = true;
    for (uint32_t i = 0; i < M * N && passed; i++) {
        if (std::abs(C[i] - 1.0f) > 0.1f) {
            std::cout << "  Mismatch at index " << i << ": expected 1.0, got " << C[i] << "\n";
            passed = false;
        }
    }
    
    if (passed) {
        std::cout << "✓ MatMul 64x64 passed\n";
    } else {
        std::cout << "✗ MatMul 64x64 failed\n";
    }
    
    return passed;
}

bool TestMatMulLarge() {
    std::cout << "\n=== Test: MatMul 512x512 (Benchmark) ===\n";
    
    VulkanExecutor executor;
    if (!executor.Initialize()) {
        std::cerr << "Failed to initialize Vulkan executor\n";
        return false;
    }
    
    // Large test: 512x512 * 512x512 = 512x512
    const uint32_t M = 512, N = 512, K = 512;
    
    std::vector<float> A(M * K, 0.5f);
    std::vector<float> B(K * N, 0.5f);
    std::vector<float> C(M * N);
    
    // Execute on GPU
    auto start = std::chrono::high_resolution_clock::now();
    if (!executor.ExecuteMatMulFP16(A, B, C, M, N, K)) {
        std::cerr << "MatMul execution failed\n";
        return false;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    float seconds = duration.count() / 1000000.0f;
    float gflops = (2.0f * M * N * K) / (seconds * 1e9);
    
    std::cout << "  Execution time: " << duration.count() << " μs (" << seconds << " s)\n";
    std::cout << "  Performance: " << gflops << " GFLOPS\n";
    
    // Verify a few elements (0.5 * 0.5 * 512 = 128.0)
    bool passed = true;
    for (uint32_t i = 0; i < 10 && passed; i++) {
        float expected = 128.0f;
        float actual = C[i];
        if (std::abs(actual - expected) > 10.0f) {  // FP16 has error
            std::cout << "  Mismatch at index " << i << ": expected ~128, got " << actual << "\n";
            passed = false;
        }
    }
    
    if (passed) {
        std::cout << "✓ MatMul 512x512 passed\n";
    } else {
        std::cout << "✗ MatMul 512x512 failed\n";
    }
    
    return passed;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Vulkan GPU Execution Tests\n";
    std::cout << "========================================\n";
    std::cout << "\nWARNING: These tests execute actual GPU kernels.\n";
    std::cout << "Requires RX 7800 XT with Vulkan support.\n\n";
    
    bool all_passed = true;
    
    all_passed &= TestMatMulSmall();
    all_passed &= TestMatMulMedium();
    all_passed &= TestMatMulLarge();
    
    std::cout << "\n========================================\n";
    if (all_passed) {
        std::cout << "All GPU execution tests PASSED\n";
        std::cout << "========================================\n";
        std::cout << "\nGPU kernels are working!\n";
        std::cout << "Next: Integrate with inference pipeline\n";
        return 0;
    } else {
        std::cout << "Some tests FAILED\n";
        std::cout << "========================================\n";
        return 1;
    }
}
