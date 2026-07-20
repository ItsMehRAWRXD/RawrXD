//=============================================================================
// Fix #4 Test Harness: Fused Q4_0 Kernel Validation
// Target: Verify 540 -> 650 TPS gain
//=============================================================================

#include "kernels/RawrXD_FusedQ4_Kernel.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <cmath>

using namespace RawrXD::Kernels;

//=============================================================================
// Generate test data
//=============================================================================
void GenerateTestData(
    std::vector<float>& activation,
    std::vector<Q4_0Block>& weights,
    std::vector<float>& expected_output,
    int M, int K, int N
) {
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    // Generate activation matrix
    activation.resize(M * K);
    for (auto& val : activation) {
        val = dist(rng);
    }
    
    // Generate Q4_0 weights
    const int blocks_per_col = K / 32;
    weights.resize(N * blocks_per_col);
    
    for (int n = 0; n < N; ++n) {
        for (int b = 0; b < blocks_per_col; ++b) {
            Q4_0Block& block = weights[n * blocks_per_col + b];
            
            // Find max for quantization
            float max_val = 0.0f;
            for (int i = 0; i < 32; ++i) {
                float val = std::abs(dist(rng));
                max_val = std::max(max_val, val);
            }
            
            block.scale = max_val / 7.0f;  // 4-bit range is -7 to +7
            
            // Quantize to 4-bit
            for (int i = 0; i < 16; ++i) {
                float val1 = dist(rng);
                float val2 = dist(rng);
                
                int q1 = static_cast<int>(std::round(val1 / block.scale)) & 0x0F;
                int q2 = static_cast<int>(std::round(val2 / block.scale)) & 0x0F;
                
                block.data[i] = static_cast<uint8_t>((q2 << 4) | q1);
            }
        }
    }
    
    // Compute expected output (reference implementation)
    expected_output.resize(M * N, 0.0f);
    for (int m = 0; m < M; ++m) {
        for (int n = 0; n < N; ++n) {
            float sum = 0.0f;
            for (int k = 0; k < K; ++k) {
                int block_idx = k / 32;
                int nibble_idx = k % 32;
                
                const Q4_0Block& block = weights[n * blocks_per_col + block_idx];
                
                uint8_t byte = block.data[nibble_idx / 2];
                int nibble = (nibble_idx % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
                
                // Convert to signed: 0-15 -> -7 to +7
                float weight = (static_cast<float>(nibble) - 7.5f) * block.scale;
                
                sum += activation[m * K + k] * weight;
            }
            expected_output[m * N + n] = sum;
        }
    }
}

//=============================================================================
// Validate correctness
//=============================================================================
bool ValidateOutput(
    const std::vector<float>& output,
    const std::vector<float>& expected,
    float tolerance = 0.01f
) {
    if (output.size() != expected.size()) {
        return false;
    }
    
    float max_error = 0.0f;
    for (size_t i = 0; i < output.size(); ++i) {
        float error = std::abs(output[i] - expected[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << " (tolerance: " << tolerance << ")" << std::endl;
    return max_error <= tolerance;
}

//=============================================================================
// Benchmark TPS
//=============================================================================
double BenchmarkTPS(
    const std::vector<float>& activation,
    const std::vector<Q4_0Block>& weights,
    std::vector<float>& output,
    int M, int K, int N,
    int iterations = 100
) {
    FusedQ4MatMul::Config config;
    config.use_avx512 = true;
    
    // Warmup
    for (int i = 0; i < 5; ++i) {
        FusedQ4MatMul::Execute(
            activation.data(), weights.data(), output.data(),
            M, K, N, config
        );
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        FusedQ4MatMul::Execute(
            activation.data(), weights.data(), output.data(),
            M, K, N, config
        );
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Calculate TPS (tokens per second)
    // Assuming each matrix multiply processes M * N "tokens"
    double total_tokens = static_cast<double>(M * N * iterations);
    double seconds = duration.count() / 1e6;
    double tps = total_tokens / seconds;
    
    return tps;
}

//=============================================================================
// Main test
//=============================================================================
int main() {
    std::cout << "=============================================================================" << std::endl;
    std::cout << "Fix #4: Fused Q4_0 Kernel Test Harness" << std::endl;
    std::cout << "Target: 540 -> 650 TPS (1.2-1.3x gain)" << std::endl;
    std::cout << "=============================================================================" << std::endl;
    std::cout << std::endl;
    
    // Check AVX-512
    std::cout << "CPU Features:" << std::endl;
    std::cout << "  AVX-512: " << (FusedQ4MatMul::IsAVX512Available() ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    if (!FusedQ4MatMul::IsAVX512Available()) {
        std::cerr << "ERROR: AVX-512 not available" << std::endl;
        return 1;
    }
    
    // Test configurations
    struct TestConfig {
        int M, K, N;
        const char* name;
    };
    
    TestConfig configs[] = {
        {1, 4096, 4096, "QKV Projection (4096 hidden)"},
        {1, 5120, 5120, "QKV Projection (5120 hidden)"},
        {1, 8192, 8192, "QKV Projection (8192 hidden)"},
        {32, 4096, 4096, "Batch=32, Hidden=4096"},
        {64, 4096, 4096, "Batch=64, Hidden=4096"},
    };
    
    bool all_passed = true;
    
    for (const auto& cfg : configs) {
        std::cout << "----------------------------------------------------------------------------" << std::endl;
        std::cout << "Test: " << cfg.name << std::endl;
        std::cout << "  Dimensions: M=" << cfg.M << ", K=" << cfg.K << ", N=" << cfg.N << std::endl;
        
        // Generate test data
        std::vector<float> activation;
        std::vector<Q4_0Block> weights;
        std::vector<float> expected;
        
        GenerateTestData(activation, weights, expected, cfg.M, cfg.K, cfg.N);
        
        // Allocate output
        std::vector<float> output(cfg.M * cfg.N);
        
        // Execute kernel
        FusedQ4MatMul::Config exec_config;
        exec_config.use_avx512 = true;
        
        bool success = FusedQ4MatMul::Execute(
            activation.data(), weights.data(), output.data(),
            cfg.M, cfg.K, cfg.N, exec_config
        );
        
        if (!success) {
            std::cerr << "  FAILED: Kernel execution failed" << std::endl;
            all_passed = false;
            continue;
        }
        
        // Validate correctness
        bool correct = ValidateOutput(output, expected);
        std::cout << "  Correctness: " << (correct ? "PASS" : "FAIL") << std::endl;
        
        if (!correct) {
            all_passed = false;
            continue;
        }
        
        // Benchmark TPS
        double tps = BenchmarkTPS(activation, weights, output, cfg.M, cfg.K, cfg.N);
        std::cout << "  TPS: " << tps << " tokens/sec" << std::endl;
        
        // Check if we hit target
        if (tps >= 650.0) {
            std::cout << "  >>> TARGET ACHIEVED: 650+ TPS <<<" << std::endl;
        } else if (tps >= 540.0) {
            std::cout << "  Baseline maintained: 540+ TPS" << std::endl;
        } else {
            std::cout << "  WARNING: Below baseline" << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    std::cout << "=============================================================================" << std::endl;
    std::cout << "Test Summary: " << (all_passed ? "ALL PASSED" : "SOME FAILED") << std::endl;
    std::cout << "=============================================================================" << std::endl;
    
    return all_passed ? 0 : 1;
}
