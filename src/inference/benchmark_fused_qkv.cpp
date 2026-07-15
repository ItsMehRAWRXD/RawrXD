// ============================================================================
// Benchmark: Fused QKV Projection
// ============================================================================
// Compares fused QKV vs separate MatMuls
// Target: 2-3x speedup
// ============================================================================

#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <random>

#include "vulkan_executor_extended.hpp"
#include "fused_kernels.hpp"

using namespace RawrXD::Inference;

struct BenchmarkResult {
    std::string name;
    float time_ms = 0.0f;
    float speedup = 1.0f;
    bool passed = false;
};

int main() {
    std::cout << "========================================\n";
    std::cout << "Fused QKV Projection Benchmark\n";
    std::cout << "Phase 3: Kernel Fusion Validation\n";
    std::cout << "========================================\n\n";

    // Configuration
    const uint32_t batch_size = 1;
    const uint32_t seq_len = 512;
    const uint32_t hidden_size = 4096;
    const uint32_t num_iterations = 10;
    const uint32_t warmup = 2;

    std::cout << "Configuration:\n";
    std::cout << "  Batch: " << batch_size << "\n";
    std::cout << "  Seq: " << seq_len << "\n";
    std::cout << "  Hidden: " << hidden_size << "\n";
    std::cout << "  Iterations: " << num_iterations << "\n\n";

    // Initialize GPU
    std::cout << "Initializing GPU...\n";
    VulkanExecutorExtended executor;
    if (!executor.InitializeExtended()) {
        std::cerr << "FAILED: Could not initialize Vulkan\n";
        return 1;
    }
    std::cout << "  GPU: " << executor.GetDeviceName() << "\n\n";

    // Generate test data
    std::mt19937 rng(42);
    std::vector<float> input(batch_size * seq_len * hidden_size);
    std::vector<float> weight_q(hidden_size * hidden_size);
    std::vector<float> weight_k(hidden_size * hidden_size);
    std::vector<float> weight_v(hidden_size * hidden_size);

    for (auto& v : input) v = (float)(rng() % 100) * 0.01f;
    for (auto& v : weight_q) v = (float)(rng() % 100) * 0.001f;
    for (auto& v : weight_k) v = (float)(rng() % 100) * 0.001f;
    for (auto& v : weight_v) v = (float)(rng() % 100) * 0.001f;

    std::vector<float> output_q, output_k, output_v;
    std::vector<float> output_q_fused, output_k_fused, output_v_fused;

    // Test 1: Separate MatMuls (baseline)
    std::cout << "=== Test 1: Separate MatMuls (Baseline) ===\n";
    
    // Warmup
    for (uint32_t i = 0; i < warmup; i++) {
        executor.ExecuteMatMulFP16(input, weight_q, output_q, batch_size * seq_len, hidden_size, hidden_size);
        executor.ExecuteMatMulFP16(input, weight_k, output_k, batch_size * seq_len, hidden_size, hidden_size);
        executor.ExecuteMatMulFP16(input, weight_v, output_v, batch_size * seq_len, hidden_size, hidden_size);
    }

    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < num_iterations; i++) {
        executor.ExecuteMatMulFP16(input, weight_q, output_q, batch_size * seq_len, hidden_size, hidden_size);
        executor.ExecuteMatMulFP16(input, weight_k, output_k, batch_size * seq_len, hidden_size, hidden_size);
        executor.ExecuteMatMulFP16(input, weight_v, output_v, batch_size * seq_len, hidden_size, hidden_size);
    }
    auto end = std::chrono::high_resolution_clock::now();

    float time_separate = std::chrono::duration<float, std::milli>(end - start).count() / num_iterations;
    std::cout << "  Time: " << std::fixed << std::setprecision(2) << time_separate << " ms\n";
    std::cout << "  Per projection: " << time_separate / 3 << " ms\n\n";

    // Test 2: Fused QKV
    std::cout << "=== Test 2: Fused QKV Projection ===\n";
    
    // Warmup
    for (uint32_t i = 0; i < warmup; i++) {
        ExecuteFusedQKVProjection(executor, input, weight_q, weight_k, weight_v,
                                    output_q_fused, output_k_fused, output_v_fused,
                                    batch_size, seq_len, hidden_size);
    }

    // Benchmark
    start = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < num_iterations; i++) {
        ExecuteFusedQKVProjection(executor, input, weight_q, weight_k, weight_v,
                                    output_q_fused, output_k_fused, output_v_fused,
                                    batch_size, seq_len, hidden_size);
    }
    end = std::chrono::high_resolution_clock::now();

    float time_fused = std::chrono::duration<float, std::milli>(end - start).count() / num_iterations;
    float speedup = time_separate / time_fused;

    std::cout << "  Time: " << std::fixed << std::setprecision(2) << time_fused << " ms\n";
    std::cout << "  Speedup: " << std::setprecision(2) << speedup << "x\n\n";

    // Summary
    std::cout << "========================================\n";
    std::cout << "Results Summary\n";
    std::cout << "========================================\n";
    std::cout << std::left << std::setw(30) << "Method" 
              << std::setw(15) << "Time (ms)" 
              << std::setw(15) << "Speedup" << "\n";
    std::cout << std::string(60, '-') << "\n";
    std::cout << std::setw(30) << "Separate MatMuls"
              << std::fixed << std::setprecision(2)
              << std::setw(15) << time_separate
              << std::setw(15) << "1.00x" << "\n";
    std::cout << std::setw(30) << "Fused QKV"
              << std::setw(15) << time_fused
              << std::setw(15) << speedup << "x";
    
    if (speedup >= 2.0f) {
        std::cout << " ✓ PASS\n";
    } else if (speedup >= 1.5f) {
        std::cout << " ⚠ PARTIAL\n";
    } else {
        std::cout << " ✗ FAIL\n";
    }

    std::cout << "\n========================================\n";
    if (speedup >= 2.0f) {
        std::cout << "✓ Phase 3 Target Met (2x+ speedup)\n";
        std::cout << "Ready to proceed to fused attention\n";
    } else {
        std::cout << "⚠ Below target (need 2x+ speedup)\n";
        std::cout << "Review shader optimization\n";
    }
    std::cout << "========================================\n";

    executor.Cleanup();
    return (speedup >= 2.0f) ? 0 : 1;
}
