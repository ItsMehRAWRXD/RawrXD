// ============================================================================
// Test: AVX-512 Q4_0 MatMul Benchmark
// Measures actual GFLOPS, not projections
// ============================================================================

#include "quantized_matmul_avx512.hpp"
#include "quantized_matmul.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstdlib>

using namespace benchmark;

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "AVX-512 Q4_0 MatMul Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Feature detection
    std::cout << "CPU Features:" << std::endl;
    std::cout << "  AVX-512F:  " << (HasAVX512F() ? "YES" : "NO") << std::endl;
    std::cout << "  AVX-512DQ: " << (HasAVX512DQ() ? "YES" : "NO") << std::endl;
    std::cout << "  AVX-512VL: " << (HasAVX512VL() ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    if (!HasAVX512F()) {
        std::cout << "ERROR: AVX-512 not available on this CPU" << std::endl;
        return 1;
    }
    
    // Test configurations
    struct TestConfig {
        size_t batch;
        size_t input_dim;
        size_t output_dim;
        const char* name;
    };
    
    TestConfig configs[] = {
        {1, 4096, 14336, "30B FFN Up-proj"},
        {1, 14336, 4096, "30B FFN Down-proj"},
        {1, 4096, 4096, "30B QKV/O-proj"},
        {1, 6144, 16384, "30B Large FFN"},
    };
    
    std::cout << "Running benchmarks..." << std::endl;
    std::cout << std::endl;
    
    for (const auto& config : configs) {
        std::cout << "----------------------------------------" << std::endl;
        std::cout << "Config: " << config.name << std::endl;
        std::cout << "  Shape: [" << config.batch << ", " << config.input_dim 
                  << "] × [" << config.input_dim << ", " << config.output_dim << "]" << std::endl;
        std::cout << std::endl;
        
        // Run benchmark
        auto metrics = BenchmarkAVX512MatMul(config.batch, config.input_dim, config.output_dim, 100);
        
        std::cout << "Results:" << std::endl;
        std::cout << "  Time: " << std::fixed << std::setprecision(2) 
                  << metrics.total_time_ms << " ms" << std::endl;
        std::cout << "  GFLOPS: " << std::setprecision(2) << metrics.gflops << std::endl;
        std::cout << "  Memory BW: " << std::setprecision(2) 
                  << metrics.memory_bandwidth_gb_s << " GB/s" << std::endl;
        std::cout << std::endl;
        
        // Compare to scalar
        std::cout << "Comparison:" << std::endl;
        std::cout << "  Scalar reference: ~2.7 GFLOPS" << std::endl;
        std::cout << "  AVX-512 measured: " << std::setprecision(2) << metrics.gflops << " GFLOPS";
        if (metrics.gflops > 0) {
            float speedup = metrics.gflops / 2.7f;
            std::cout << " (" << std::setprecision(1) << speedup << "×)";
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }
    
    std::cout << "========================================" << std::endl;
    std::cout << "Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "This benchmark measures actual GFLOPS achieved by" << std::endl;
    std::cout << "the AVX-512 Q4_0 MatMul kernel, not projections." << std::endl;
    std::cout << std::endl;
    std::cout << "Next steps:" << std::endl;
    std::cout << "  1. Compare to theoretical peak (100-150 GFLOPS expected)" << std::endl;
    std::cout << "  2. Profile memory bandwidth vs compute bound" << std::endl;
    std::cout << "  3. Add multi-threading (OpenMP)" << std::endl;
    std::cout << "  4. Measure end-to-end transformer layer" << std::endl;
    
    return 0;
}
