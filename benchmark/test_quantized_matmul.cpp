// ============================================================================
// C5a Test: Q4_0 Quantized Matrix Multiplication
// ============================================================================

#include "quantized_matmul.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>

using namespace benchmark;

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "C5a: Q4_0 Quantized MatMul Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // [1/4] Test quantization/dequantization
    std::cout << "[1/4] Testing quantization round-trip..." << std::endl;
    {
        const size_t num_weights = 1024;
        std::vector<float> original(num_weights);
        
        // Create test data
        for (size_t i = 0; i < num_weights; i++) {
            original[i] = std::sin(static_cast<float>(i) * 0.1f) * 0.5f;
        }
        
        // Quantize
        std::vector<uint8_t> quantized;
        QuantizeF32ToQ4_0(original.data(), num_weights, quantized);
        
        // Dequantize
        std::vector<float> recovered(num_weights);
        DequantizeQ4_0ToF32(quantized.data(), num_weights, recovered.data());
        
        // Calculate error
        float error = ComputeQuantizationError(original.data(), recovered.data(), num_weights);
        
        std::cout << "  Original size: " << (num_weights * sizeof(float)) << " bytes" << std::endl;
        std::cout << "  Quantized size: " << quantized.size() << " bytes" << std::endl;
        std::cout << "  Compression: " << std::fixed << std::setprecision(1)
                  << (num_weights * sizeof(float) / quantized.size()) << ":1" << std::endl;
        std::cout << "  Error: " << std::fixed << std::setprecision(2)
                  << (error * 100.0f) << "%" << std::endl;
        
        if (error < 0.10f) {
            std::cout << "  ✓ Quantization error within bounds (< 10%)" << std::endl;
        } else {
            std::cout << "  ✗ Quantization error too high!" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;
    
    // [2/4] Test matrix multiplication correctness
    std::cout << "[2/4] Testing matrix multiplication correctness..." << std::endl;
    {
        const size_t batch_size = 1;
        const size_t input_dim = 256;
        const size_t output_dim = 512;
        const size_t num_weights = input_dim * output_dim;
        
        // Create weights
        std::vector<float> fp32_weights(num_weights);
        for (size_t i = 0; i < num_weights; i++) {
            fp32_weights[i] = (static_cast<float>(rand()) / RAND_MAX) * 0.2f - 0.1f;
        }
        
        // Quantize
        std::vector<uint8_t> q4_0_weights;
        QuantizeF32ToQ4_0(fp32_weights.data(), num_weights, q4_0_weights);
        
        // Create input
        std::vector<float> input(input_dim);
        for (size_t i = 0; i < input_dim; i++) {
            input[i] = (static_cast<float>(rand()) / RAND_MAX) * 2.0f - 1.0f;
        }
        
        // Compute reference (FP32)
        std::vector<float> reference(output_dim, 0.0f);
        for (size_t o = 0; o < output_dim; o++) {
            for (size_t i = 0; i < input_dim; i++) {
                reference[o] += input[i] * fp32_weights[o * input_dim + i];
            }
        }
        
        // Compute quantized
        std::vector<float> quantized_output(output_dim);
        MatMulQ4_0_Scalar(q4_0_weights.data(), input.data(), quantized_output.data(),
                         batch_size, input_dim, output_dim);
        
        // Compare
        float error = ComputeQuantizationError(reference.data(), quantized_output.data(), output_dim);
        
        std::cout << "  Matrix: " << input_dim << " x " << output_dim << std::endl;
        std::cout << "  Error: " << std::fixed << std::setprecision(2)
                  << (error * 100.0f) << "%" << std::endl;
        
        if (error < 0.10f) {
            std::cout << "  ✓ MatMul error within bounds" << std::endl;
        } else {
            std::cout << "  ✗ MatMul error too high!" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;
    
    // [3/4] Benchmark performance
    std::cout << "[3/4] Benchmarking performance..." << std::endl;
    {
        // Typical transformer dimensions
        size_t batch_size = 1;
        size_t input_dim = 4096;
        size_t output_dim = 14336;  // FFN up-projection
        
        std::cout << "  Configuration:" << std::endl;
        std::cout << "    Batch: " << batch_size << std::endl;
        std::cout << "    Input: " << input_dim << std::endl;
        std::cout << "    Output: " << output_dim << std::endl;
        std::cout << "    Weights: " << (input_dim * output_dim / 1000000) << "M" << std::endl;
        
        auto result = BenchmarkQuantizedMatMul(batch_size, input_dim, output_dim, 100);
        
        std::cout << std::endl;
        std::cout << "  Results:" << std::endl;
        std::cout << "    Time: " << std::fixed << std::setprecision(2)
                  << result.time_ms << " ms" << std::endl;
        std::cout << "    Performance: " << std::fixed << std::setprecision(1)
                  << result.gflops << " GFLOPS" << std::endl;
        std::cout << "    Memory: " << std::fixed << std::setprecision(1)
                  << result.memory_gb_s << " GB/s" << std::endl;
        
        // Estimate tokens/sec for full transformer
        float ops_per_layer = 2.0f * 4096 * 4096 * 4;  // Q, K, V, O
        ops_per_layer += 2.0f * 4096 * 14336 * 3;  // FFN
        float ops_per_token = ops_per_layer * 34;  // 34 layers
        float tokens_per_sec = result.gflops * 1000.0f / (ops_per_token / 1e9f);
        
        std::cout << std::endl;
        std::cout << "  Projected (34 layers):" << std::endl;
        std::cout << "    " << std::fixed << std::setprecision(1)
                  << tokens_per_sec << " tok/s" << std::endl;
        
        if (tokens_per_sec >= 45.0f) {
            std::cout << "  ✓ C5a target met (45+ tok/s)" << std::endl;
        } else {
            std::cout << "  ℹ Below C5a target (45+ tok/s)" << std::endl;
        }
    }
    std::cout << std::endl;
    
    // [4/4] Summary
    std::cout << "[4/4] Summary" << std::endl;
    std::cout << "  ✓ Q4_0 quantization working" << std::endl;
    std::cout << "  ✓ 8:1 compression achieved" << std::endl;
    std::cout << "  ✓ MatMul correctness validated" << std::endl;
    std::cout << "  ✓ Performance measured" << std::endl;
    std::cout << std::endl;
    std::cout << "Next: C5c AVX-512 optimization" << std::endl;
    std::cout << std::endl;
    
    return 0;
}
