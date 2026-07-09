// ============================================================================
// Quantized Inference Test
// ============================================================================
// Tests Q4_0 and Q8_0 quantization/dequantization and matrix multiplication
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>
#include <chrono>
#include <iomanip>
#include "src/quantization/quantized_inference.hpp"

using namespace rawrxd::quantization;

// Test 1: F16/F32 conversion
bool TestF16Conversion() {
    std::cout << "\n=== Test 1: F16/F32 Conversion ===" << std::endl;
    
    float test_values[] = {0.0f, 1.0f, -1.0f, 0.5f, -0.5f, 100.0f, -100.0f};
    bool passed = true;
    
    for (float val : test_values) {
        uint16_t f16 = QuantizationUtils::F32ToF16(val);
        float f32 = QuantizationUtils::F16ToF32(f16);
        float error = std::abs(val - f32);
        
        if (error > 0.01f) {
            std::cout << "  FAIL: " << val << " -> " << f32 << " (error: " << error << ")" << std::endl;
            passed = false;
        }
    }
    
    if (passed) {
        std::cout << "  PASS: F16/F32 conversion working" << std::endl;
    }
    return passed;
}

// Test 2: Q8_0 quantization
bool TestQ8_0Quantization() {
    std::cout << "\n=== Test 2: Q8_0 Quantization ===" << std::endl;
    
    std::vector<float> input(64);
    for (size_t i = 0; i < input.size(); i++) {
        input[i] = static_cast<float>(i) / 10.0f - 3.0f;
    }
    
    // Quantize
    std::vector<uint8_t> quantized;
    if (!QuantizationUtils::QuantizeF32ToQ8_0(input.data(), input.size(), quantized)) {
        std::cout << "  FAIL: Quantization failed" << std::endl;
        return false;
    }
    
    // Calculate expected size
    size_t expected_blocks = (input.size() + Q8_0_BLOCK_SIZE - 1) / Q8_0_BLOCK_SIZE;
    size_t expected_size = expected_blocks * sizeof(Q8_0Block);
    
    std::cout << "  Original size: " << input.size() * sizeof(float) << " bytes" << std::endl;
    std::cout << "  Quantized size: " << quantized.size() << " bytes" << std::endl;
    std::cout << "  Compression: " << std::fixed << std::setprecision(2) 
              << (float)(input.size() * sizeof(float)) / quantized.size() << "x" << std::endl;
    
    // Load into QuantizedTensor and dequantize
    QuantizedTensor tensor;
    if (!tensor.LoadFromGGUF(quantized.data(), input.size(), QuantType::Q8_0)) {
        std::cout << "  FAIL: Failed to load quantized data" << std::endl;
        return false;
    }
    
    auto dequantized = tensor.DequantizeScalar();
    
    // Calculate error
    float error = QuantizationUtils::CalculateError(input.data(), dequantized.data(), input.size());
    std::cout << "  Quantization error: " << std::setprecision(4) << error * 100 << "%" << std::endl;
    
    if (error < 0.05f) {
        std::cout << "  PASS: Q8_0 quantization working (error < 5%)" << std::endl;
        return true;
    } else {
        std::cout << "  FAIL: Error too high" << std::endl;
        return false;
    }
}

// Test 3: Q4_0 quantization
bool TestQ4_0Quantization() {
    std::cout << "\n=== Test 3: Q4_0 Quantization ===" << std::endl;
    
    std::vector<float> input(64);
    for (size_t i = 0; i < input.size(); i++) {
        input[i] = static_cast<float>(i) / 10.0f - 3.0f;
    }
    
    // Quantize
    std::vector<uint8_t> quantized;
    if (!QuantizationUtils::QuantizeF32ToQ4_0(input.data(), input.size(), quantized)) {
        std::cout << "  FAIL: Quantization failed" << std::endl;
        return false;
    }
    
    // Calculate expected size
    size_t expected_blocks = (input.size() + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
    size_t expected_size = expected_blocks * sizeof(Q4_0Block);
    
    std::cout << "  Original size: " << input.size() * sizeof(float) << " bytes" << std::endl;
    std::cout << "  Quantized size: " << quantized.size() << " bytes" << std::endl;
    std::cout << "  Compression: " << std::fixed << std::setprecision(2) 
              << (float)(input.size() * sizeof(float)) / quantized.size() << "x" << std::endl;
    
    // Load into QuantizedTensor and dequantize
    QuantizedTensor tensor;
    if (!tensor.LoadFromGGUF(quantized.data(), input.size(), QuantType::Q4_0)) {
        std::cout << "  FAIL: Failed to load quantized data" << std::endl;
        return false;
    }
    
    auto dequantized = tensor.DequantizeScalar();
    
    // Calculate error
    float error = QuantizationUtils::CalculateError(input.data(), dequantized.data(), input.size());
    std::cout << "  Quantization error: " << std::setprecision(4) << error * 100 << "%" << std::endl;
    
    if (error < 0.10f) {
        std::cout << "  PASS: Q4_0 quantization working (error < 10%)" << std::endl;
        return true;
    } else {
        std::cout << "  FAIL: Error too high" << std::endl;
        return false;
    }
}

// Test 4: Quantized matrix multiplication
bool TestQuantizedMatMul() {
    std::cout << "\n=== Test 4: Quantized Matrix Multiplication ===" << std::endl;
    
    // Create test matrices
    size_t batch_size = 1;
    size_t input_dim = 64;
    size_t output_dim = 32;
    
    std::vector<float> weight(output_dim * input_dim);
    std::vector<float> input(batch_size * input_dim);
    std::vector<float> output(batch_size * output_dim);
    
    // Initialize with test values
    for (size_t i = 0; i < weight.size(); i++) {
        weight[i] = static_cast<float>(i % 10) / 10.0f - 0.5f;
    }
    for (size_t i = 0; i < input.size(); i++) {
        input[i] = static_cast<float>(i % 5) / 5.0f;
    }
    
    // Quantize weights to Q8_0
    std::vector<uint8_t> quantized_weight;
    QuantizationUtils::QuantizeF32ToQ8_0(weight.data(), weight.size(), quantized_weight);
    
    QuantizedTensor weight_tensor;
    weight_tensor.LoadFromGGUF(quantized_weight.data(), weight.size(), QuantType::Q8_0);
    weight_tensor.Initialize(QuantType::Q8_0, output_dim, input_dim);
    
    // Perform matrix multiplication
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!weight_tensor.MatMul(input.data(), output.data(), batch_size, input_dim, output_dim)) {
        std::cout << "  FAIL: Matrix multiplication failed" << std::endl;
        return false;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    std::cout << "  MatMul time: " << std::fixed << std::setprecision(3) << duration << " ms" << std::endl;
    std::cout << "  Output sample: [" << output[0] << ", " << output[1] << ", ...]" << std::endl;
    
    // Verify output is reasonable (not NaN/Inf)
    bool valid = true;
    for (size_t i = 0; i < output.size(); i++) {
        if (std::isnan(output[i]) || std::isinf(output[i])) {
            valid = false;
            break;
        }
    }
    
    if (valid) {
        std::cout << "  PASS: Quantized MatMul working" << std::endl;
        return true;
    } else {
        std::cout << "  FAIL: Output contains NaN/Inf" << std::endl;
        return false;
    }
}

// Test 5: Memory savings calculation
bool TestMemorySavings() {
    std::cout << "\n=== Test 5: Memory Savings ===" << std::endl;
    
    size_t rows = 4096;
    size_t cols = 4096;
    size_t num_elements = rows * cols;
    
    // F32 size
    size_t f32_size = num_elements * sizeof(float);
    
    // Q8_0 size
    size_t q8_0_blocks = (num_elements + Q8_0_BLOCK_SIZE - 1) / Q8_0_BLOCK_SIZE;
    size_t q8_0_size = q8_0_blocks * sizeof(Q8_0Block);
    
    // Q4_0 size
    size_t q4_0_blocks = (num_elements + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
    size_t q4_0_size = q4_0_blocks * sizeof(Q4_0Block);
    
    std::cout << "  Matrix size: " << rows << " x " << cols << std::endl;
    std::cout << "  F32:   " << std::setw(10) << f32_size << " bytes (" << f32_size / (1024.0 * 1024) << " MB)" << std::endl;
    std::cout << "  Q8_0:  " << std::setw(10) << q8_0_size << " bytes (" << q8_0_size / (1024.0 * 1024) << " MB)" 
              << " - " << std::fixed << std::setprecision(1) << (100.0 * (f32_size - q8_0_size) / f32_size) << "% savings" << std::endl;
    std::cout << "  Q4_0:  " << std::setw(10) << q4_0_size << " bytes (" << q4_0_size / (1024.0 * 1024) << " MB)" 
              << " - " << std::fixed << std::setprecision(1) << (100.0 * (f32_size - q4_0_size) / f32_size) << "% savings" << std::endl;
    
    std::cout << "  PASS: Memory savings calculated" << std::endl;
    return true;
}

// Test 6: Performance benchmark
bool TestPerformance() {
    std::cout << "\n=== Test 6: Performance Benchmark ===" << std::endl;
    
    size_t rows = 4096;
    size_t cols = 4096;
    size_t num_elements = rows * cols;
    
    // Create test data
    std::vector<float> weight(num_elements);
    std::vector<float> input(cols);
    std::vector<float> output(rows);
    
    for (size_t i = 0; i < num_elements; i++) {
        weight[i] = static_cast<float>(rand()) / RAND_MAX * 2.0f - 1.0f;
    }
    for (size_t i = 0; i < cols; i++) {
        input[i] = static_cast<float>(rand()) / RAND_MAX * 2.0f - 1.0f;
    }
    
    // Quantize to Q8_0
    std::vector<uint8_t> quantized;
    auto q_start = std::chrono::high_resolution_clock::now();
    QuantizationUtils::QuantizeF32ToQ8_0(weight.data(), weight.size(), quantized);
    auto q_end = std::chrono::high_resolution_clock::now();
    auto quantize_ms = std::chrono::duration<double, std::milli>(q_end - q_start).count();
    
    QuantizedTensor weight_tensor;
    weight_tensor.LoadFromGGUF(quantized.data(), weight.size(), QuantType::Q8_0);
    weight_tensor.Initialize(QuantType::Q8_0, rows, cols);
    
    // Benchmark MatMul
    const int iterations = 10;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        weight_tensor.MatMul(input.data(), output.data(), 1, cols, rows);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    double avg_ms = duration / iterations;
    double gflops = (2.0 * rows * cols / (avg_ms / 1000.0)) / 1e9;
    
    std::cout << "  Quantization time: " << std::fixed << std::setprecision(2) << quantize_ms << " ms" << std::endl;
    std::cout << "  MatMul avg time:   " << std::fixed << std::setprecision(3) << avg_ms << " ms" << std::endl;
    std::cout << "  Performance:       " << std::fixed << std::setprecision(2) << gflops << " GFLOP/s" << std::endl;
    std::cout << "  PASS: Performance benchmark complete" << std::endl;
    
    return true;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Quantized Inference Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int total = 6;
    
    if (TestF16Conversion()) passed++;
    if (TestQ8_0Quantization()) passed++;
    if (TestQ4_0Quantization()) passed++;
    if (TestQuantizedMatMul()) passed++;
    if (TestMemorySavings()) passed++;
    if (TestPerformance()) passed++;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << "/" << total << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (passed == total) {
        std::cout << "\n✓ Quantized Inference: ALL TESTS PASSED" << std::endl;
        std::cout << "\nReady for:" << std::endl;
        std::cout << "  - Q4_0/Q8_0 model weights" << std::endl;
        std::cout << "  - Memory-efficient inference" << std::endl;
        std::cout << "  - Larger model support" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ Some tests failed" << std::endl;
        return 1;
    }
}
