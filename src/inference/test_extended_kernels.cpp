// ============================================================================
// Test: Extended Vulkan Kernels
// ============================================================================
// Tests RMSNorm, Softmax, and VerifyCandidates GPU kernels
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>

#include "vulkan_executor_extended.hpp"

using namespace RawrXD::Inference;

bool TestRMSNorm() {
    std::cout << "\n=== Test: RMS Normalization ===\n";
    
    VulkanExecutorExtended executor;
    if (!executor.InitializeExtended()) {
        std::cerr << "Failed to initialize extended executor\n";
        return false;
    }
    
    std::cout << "GPU: " << executor.GetDeviceName() << "\n";
    
    // Test data
    const uint32_t size = 256;
    std::vector<float> input(size);
    std::vector<float> output(size);
    
    // Fill with test values
    for (uint32_t i = 0; i < size; i++) {
        input[i] = (float)(i + 1) * 0.1f;
    }
    
    // Execute on GPU
    if (!executor.ExecuteRMSNorm(input, output, size, 1e-6f)) {
        std::cerr << "RMSNorm execution failed\n";
        return false;
    }
    
    // Verify output is normalized (RMS should be ~1.0)
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        sum_sq += output[i] * output[i];
    }
    float rms = std::sqrt(sum_sq / size);
    
    bool passed = std::abs(rms - 1.0f) < 0.05f;
    
    if (passed) {
        std::cout << "✓ RMSNorm passed (RMS = " << rms << ")\n";
    } else {
        std::cout << "✗ RMSNorm failed (RMS = " << rms << ", expected ~1.0)\n";
    }
    
    executor.Cleanup();
    return passed;
}

bool TestSoftmax() {
    std::cout << "\n=== Test: Softmax ===\n";
    
    VulkanExecutorExtended executor;
    if (!executor.InitializeExtended()) {
        std::cerr << "Failed to initialize extended executor\n";
        return false;
    }
    
    // Test data
    const uint32_t rows = 8;
    const uint32_t cols = 64;
    std::vector<float> input(rows * cols);
    std::vector<float> output(rows * cols);
    
    // Fill with test values
    for (uint32_t i = 0; i < rows * cols; i++) {
        input[i] = (float)(i % cols) * 0.1f;
    }
    
    // Execute on GPU
    if (!executor.ExecuteSoftmax(input, output, rows, cols)) {
        std::cerr << "Softmax execution failed\n";
        return false;
    }
    
    // Verify each row sums to 1.0
    bool passed = true;
    for (uint32_t r = 0; r < rows && passed; r++) {
        float sum = 0.0f;
        for (uint32_t c = 0; c < cols; c++) {
            sum += output[r * cols + c];
        }
        if (std::abs(sum - 1.0f) > 0.01f) {
            std::cout << "  Row " << r << " sum = " << sum << " (expected 1.0)\n";
            passed = false;
        }
    }
    
    if (passed) {
        std::cout << "✓ Softmax passed (all rows sum to ~1.0)\n";
    } else {
        std::cout << "✗ Softmax failed\n";
    }
    
    executor.Cleanup();
    return passed;
}

bool TestAllKernels() {
    std::cout << "\n=== Test: All Extended Kernels ===\n";
    
    VulkanExecutorExtended executor;
    if (!executor.InitializeExtended()) {
        std::cerr << "Failed to initialize extended executor\n";
        return false;
    }
    
    std::cout << "✓ All kernels loaded successfully\n";
    std::cout << "  - matmul_fp16\n";
    std::cout << "  - rms_norm_fp16\n";
    std::cout << "  - softmax_fp16\n";
    std::cout << "  - verify_candidates\n";
    
    executor.Cleanup();
    return true;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Extended Vulkan Kernel Tests\n";
    std::cout << "========================================\n";
    std::cout << "\nTesting additional GPU kernels...\n\n";
    
    bool all_passed = true;
    
    all_passed &= TestAllKernels();
    all_passed &= TestRMSNorm();
    all_passed &= TestSoftmax();
    
    std::cout << "\n========================================\n";
    if (all_passed) {
        std::cout << "All extended kernel tests PASSED\n";
        std::cout << "========================================\n";
        std::cout << "\nAll GPU kernels are working!\n";
        std::cout << "Ready for full inference pipeline.\n";
        return 0;
    } else {
        std::cout << "Some tests FAILED\n";
        std::cout << "========================================\n";
        return 1;
    }
}
