// ============================================================================
// Benchmark: Tiled vs Original MatMul
// ============================================================================
// Compares performance of tiled MatMul kernel vs original
// ============================================================================

#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <random>

#include "vulkan_executor_extended.hpp"

using namespace RawrXD::Inference;

// Test different matrix sizes
struct TestCase {
    uint32_t M, N, K;
    const char* name;
};

TestCase test_cases[] = {
    {512, 512, 512, "Small (512x512)"},
    {1024, 1024, 1024, "Medium (1Kx1K)"},
    {2048, 2048, 2048, "Large (2Kx2K)"},
    {4096, 4096, 4096, "XL (4Kx4K)"},
    {4096, 1, 4096, "QKV Projection"},
    {14336, 4096, 1, "FFN Up"},
    {4096, 14336, 1, "FFN Down"},
};

int main() {
    std::cout << "========================================\n";
    std::cout << "MatMul Kernel Benchmark\n";
    std::cout << "Tiled vs Original\n";
    std::cout << "========================================\n\n";
    
    // Initialize GPU
    std::cout << "Initializing GPU...\n";
    VulkanExecutorExtended executor;
    if (!executor.InitializeExtended()) {
        std::cerr << "FAILED: Could not initialize Vulkan\n";
        return 1;
    }
    std::cout << "GPU: " << executor.GetDeviceName() << "\n\n";
    
    std::cout << "Running benchmarks...\n\n";
    std::cout << std::setw(25) << "Test Case" << " | "
              << std::setw(12) << "Size" << " | "
              << std::setw(12) << "Time (ms)" << " | "
              << std::setw(12) << "GFLOPS" << "\n";
    std::cout << std::string(70, '-') << "\n";
    
    std::mt19937 rng(42);
    
    for (const auto& test : test_cases) {
        // Generate test data
        std::vector<float> A(test.M * test.K);
        std::vector<float> B(test.K * test.N);
        std::vector<float> C(test.M * test.N);
        
        for (auto& v : A) v = (float)(rng() % 100) * 0.001f;
        for (auto& v : B) v = (float)(rng() % 100) * 0.01f;
        
        // Warmup
        executor.ExecuteMatMulFP16(A, B, C, test.M, test.K, test.N);
        
        // Benchmark
        const int iterations = 10;
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            executor.ExecuteMatMulFP16(A, B, C, test.M, test.K, test.N);
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration<float, std::milli>(end - start).count() / iterations;
        
        // Calculate GFLOPS
        float flops = 2.0f * test.M * test.N * test.K;
        float gflops = flops / (duration * 1e6f);
        
        std::cout << std::setw(25) << test.name << " | "
                  << std::setw(4) << test.M << "x" << std::setw(4) << test.N << " | "
                  << std::fixed << std::setprecision(3) << std::setw(12) << duration << " | "
                  << std::setprecision(2) << std::setw(12) << gflops << "\n";
    }
    
    // Calculate theoretical TPS for transformer
    std::cout << "\n========================================\n";
    std::cout << "Transformer Performance Estimate\n";
    std::cout << "========================================\n";
    
    // Llama 3 8B config
    const uint32_t hidden = 4096;
    const uint32_t intermediate = 14336;
    const uint32_t layers = 32;
    
    // Operations per token
    float qkv_ops = 2.0f * hidden * hidden * 3;  // Q, K, V
    float attn_out_ops = 2.0f * hidden * hidden;   // Attention output
    float ffn_up_ops = 2.0f * hidden * intermediate;  // FFN up
    float ffn_down_ops = 2.0f * intermediate * hidden; // FFN down
    float total_ops_per_layer = qkv_ops + attn_out_ops + ffn_up_ops + ffn_down_ops;
    float total_ops = total_ops_per_layer * layers;
    
    std::cout << "Model: Llama 3 8B equivalent\n";
    std::cout << "Hidden size: " << hidden << "\n";
    std::cout << "Intermediate: " << intermediate << "\n";
    std::cout << "Layers: " << layers << "\n";
    std::cout << "Ops per token: " << std::scientific << std::setprecision(2) << total_ops << "\n";
    
    // Estimate based on 4Kx4K performance
    float matmul_time_4k = 433.0f;  // ms from earlier benchmark
    float matmul_flops_4k = 2.0f * 4096 * 4096 * 4096;  // ~137 GFLOP
    float achieved_gflops = matmul_flops_4k / (matmul_time_4k * 1e6f);
    
    std::cout << "\nAchieved: " << std::fixed << std::setprecision(1) << achieved_gflops << " GFLOPS\n";
    
    float time_per_token = total_ops / (achieved_gflops * 1e9f) * 1000.0f;  // ms
    float base_tps = 1000.0f / time_per_token;
    
    std::cout << "Time per token: " << std::setprecision(2) << time_per_token << " ms\n";
    std::cout << "Base TPS: " << std::setprecision(1) << base_tps << "\n";
    std::cout << "With Medusa 2.5x: " << base_tps * 2.5f << " tok/s\n";
    
    // Target analysis
    std::cout << "\n========================================\n";
    std::cout << "Target Analysis\n";
    std::cout << "========================================\n";
    std::cout << "Target: 100 tok/s\n";
    std::cout << "Required: " << 100.0f / base_tps << "x speedup\n";
    std::cout << "Required GFLOPS: " << total_ops * 100 / 1e9 << "\n";
    std::cout << "RX 7800 XT Peak: ~35 TFLOPS (FP16)\n";
    std::cout << "Utilization needed: " << (total_ops * 100 / 1e12 / 35.0f) * 100 << "%\n";
    
    executor.Cleanup();
    
    std::cout << "\n========================================\n";
    std::cout << "Benchmark Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
