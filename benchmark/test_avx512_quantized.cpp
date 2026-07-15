// ============================================================================
// C5c Test: AVX-512 Quantized Matrix Multiplication
// ============================================================================

#include "quantized_matmul_avx512.hpp"
#include <iostream>
#include <iomanip>

using namespace benchmark;

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "C5c: AVX-512 Quantized MatMul Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // [1/3] Validate correctness
    std::cout << "[1/3] Validating AVX-512 correctness..." << std::endl;
    {
        if (ValidateAVX512Correctness(256, 512)) {
            std::cout << "  ✓ AVX-512 produces correct results" << std::endl;
        } else {
            std::cout << "  ✗ AVX-512 validation failed" << std::endl;
            return 1;
        }
    }
    std::cout << std::endl;
    
    // [2/3] Benchmark performance
    std::cout << "[2/3] Benchmarking AVX-512 performance..." << std::endl;
    {
        size_t batch_size = 1;
        size_t input_dim = 4096;
        size_t output_dim = 14336;
        
        std::cout << "  Configuration:" << std::endl;
        std::cout << "    Batch: " << batch_size << std::endl;
        std::cout << "    Input: " << input_dim << std::endl;
        std::cout << "    Output: " << output_dim << std::endl;
        std::cout << "    Weights: " << (input_dim * output_dim / 1000000) << "M" << std::endl;
        
        auto metrics = BenchmarkAVX512MatMul(batch_size, input_dim, output_dim, 100);
        
        std::cout << std::endl;
        std::cout << "  Results:" << std::endl;
        std::cout << "    Time: " << std::fixed << std::setprecision(2)
                  << metrics.total_time_ms << " ms" << std::endl;
        std::cout << "    Performance: " << std::fixed << std::setprecision(1)
                  << metrics.gflops << " GFLOPS" << std::endl;
        std::cout << "    Memory: " << std::fixed << std::setprecision(1)
                  << metrics.memory_bandwidth_gb_s << " GB/s" << std::endl;
        
        // Estimate tokens/sec for full transformer
        float ops_per_layer = 2.0f * 4096 * 4096 * 4;
        ops_per_layer += 2.0f * 4096 * 14336 * 3;
        float ops_per_token = ops_per_layer * 34;
        float tokens_per_sec = metrics.gflops * 1000.0f / (ops_per_token / 1e9f);
        
        std::cout << std::endl;
        std::cout << "  Projected (34 layers):" << std::endl;
        std::cout << "    " << std::fixed << std::setprecision(1)
                  << tokens_per_sec << " tok/s" << std::endl;
        
        if (tokens_per_sec >= 200.0f) {
            std::cout << "  ✓ C5c target met (200+ tok/s)" << std::endl;
        } else {
            std::cout << "  ℹ Below C5c target (200+ tok/s)" << std::endl;
        }
    }
    std::cout << std::endl;
    
    // [3/3] Summary
    std::cout << "[3/3] Summary" << std::endl;
    std::cout << "  ✓ AVX-512 correctness validated" << std::endl;
    std::cout << "  ✓ Performance measured" << std::endl;
    std::cout << std::endl;
    std::cout << "Next: C5d Speculative Decoding" << std::endl;
    std::cout << std::endl;
    
    return 0;
}
