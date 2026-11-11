// ============================================================================
// Test: GPU Inference Pipeline
// ============================================================================
// Tests the full inference pipeline with GPU acceleration
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>

#include "gpu_inference_pipeline.cpp"

using namespace RawrXD::Inference;

bool TestGPUInitialization() {
    std::cout << "\n=== Test: GPU Initialization ===\n";
    
    if (!InitializeGPUInference()) {
        std::cerr << "Failed to initialize GPU inference\n";
        return false;
    }
    
    std::cout << "✓ GPU inference initialized\n";
    std::cout << "  GPU: " << g_gpu_ctx.executor.GetDeviceName() << "\n";
    
    ShutdownGPUInference();
    std::cout << "✓ GPU inference shutdown\n";
    
    return true;
}

bool TestGPUMatMul() {
    std::cout << "\n=== Test: GPU MatMul ===\n";
    
    if (!InitializeGPUInference()) {
        std::cerr << "Failed to initialize GPU inference\n";
        return false;
    }
    
    // Test 64x64 MatMul
    const uint32_t dim = 64;
    std::vector<float> A(dim * dim, 0.5f);
    std::vector<float> B(dim * dim, 0.5f);
    std::vector<float> C(dim * dim);
    
    if (!GPU_MatMul(A.data(), B.data(), C.data(), dim, dim, dim)) {
        std::cerr << "GPU MatMul failed\n";
        return false;
    }
    
    // Verify result (0.5 * 0.5 * 64 = 16.0)
    bool passed = true;
    for (uint32_t i = 0; i < 10 && passed; i++) {
        float expected = 16.0f;
        float actual = C[i];
        if (std::abs(actual - expected) > 2.0f) {
            std::cout << "  Mismatch at " << i << ": expected " << expected 
                      << ", got " << actual << "\n";
            passed = false;
        }
    }
    
    if (passed) {
        std::cout << "✓ GPU MatMul passed\n";
    } else {
        std::cout << "✗ GPU MatMul failed\n";
    }
    
    ShutdownGPUInference();
    return passed;
}

bool TestRMSNorm() {
    std::cout << "\n=== Test: RMS Normalization ===\n";
    
    const uint32_t size = 64;
    std::vector<float> input(size);
    std::vector<float> output(size);
    
    // Fill with test values
    for (uint32_t i = 0; i < size; i++) {
        input[i] = (float)(i + 1);
    }
    
    if (!GPU_RMSNorm(input.data(), output.data(), size, 1e-6f)) {
        std::cerr << "RMS norm failed\n";
        return false;
    }
    
    // Verify output is normalized
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        sum_sq += output[i] * output[i];
    }
    float rms = std::sqrt(sum_sq / size);
    
    bool passed = std::abs(rms - 1.0f) < 0.01f;
    
    if (passed) {
        std::cout << "✓ RMS norm passed (RMS = " << rms << ")\n";
    } else {
        std::cout << "✗ RMS norm failed (RMS = " << rms << ", expected ~1.0)\n";
    }
    
    return passed;
}

bool TestSoftmax() {
    std::cout << "\n=== Test: Softmax ===\n";
    
    const uint32_t rows = 8;
    const uint32_t cols = 64;
    std::vector<float> input(rows * cols);
    std::vector<float> output(rows * cols);
    
    // Fill with test values
    for (uint32_t i = 0; i < rows * cols; i++) {
        input[i] = (float)(i % cols) * 0.1f;
    }
    
    if (!GPU_Softmax(input.data(), output.data(), rows, cols)) {
        std::cerr << "Softmax failed\n";
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
        std::cout << "✓ Softmax passed\n";
    } else {
        std::cout << "✗ Softmax failed\n";
    }
    
    return passed;
}

bool TestBenchmark() {
    std::cout << "\n=== Test: Token Generation Benchmark ===\n";
    
    if (!InitializeGPUInference()) {
        std::cerr << "Failed to initialize GPU inference\n";
        return false;
    }
    
    // Run benchmark with 50 tokens
    float tps = BenchmarkTokenGeneration(50);
    
    ShutdownGPUInference();
    
    if (tps > 0.0f) {
        std::cout << "✓ Benchmark completed\n";
        std::cout << "  TPS: " << tps << "\n";
        return true;
    } else {
        std::cout << "✗ Benchmark failed\n";
        return false;
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "GPU Inference Pipeline Tests\n";
    std::cout << "========================================\n";
    std::cout << "\nTesting GPU-accelerated inference...\n\n";
    
    bool all_passed = true;
    
    all_passed &= TestGPUInitialization();
    all_passed &= TestGPUMatMul();
    all_passed &= TestRMSNorm();
    all_passed &= TestSoftmax();
    all_passed &= TestBenchmark();
    
    std::cout << "\n========================================\n";
    if (all_passed) {
        std::cout << "All inference pipeline tests PASSED\n";
        std::cout << "========================================\n";
        std::cout << "\nGPU inference pipeline is working!\n";
        std::cout << "Ready for 32K context inference.\n";
        return 0;
    } else {
        std::cout << "Some tests FAILED\n";
        std::cout << "========================================\n";
        return 1;
    }
}
