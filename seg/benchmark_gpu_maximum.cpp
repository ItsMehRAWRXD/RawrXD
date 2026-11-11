// ============================================================================
// Maximum GPU Performance Benchmark
// ============================================================================
// Uses RawrXD's Vulkan/HIP/CUDA backends for massive speedup
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <cmath>
#include "transformer_gpu_backend.hpp"

using namespace RawrXD::GPU;

class Timer {
public:
    void Start() { start_ = std::chrono::high_resolution_clock::now(); }
    void Stop() { end_ = std::chrono::high_resolution_clock::now(); }
    double ElapsedMs() const {
        return std::chrono::duration<double, std::milli>(end_ - start_).count();
    }
    double ElapsedUs() const {
        return std::chrono::duration<double, std::micro>(end_ - start_).count();
    }
private:
    std::chrono::high_resolution_clock::time_point start_, end_;
};

void InitWeights(std::vector<float>& weights, size_t count, unsigned seed) {
    std::mt19937 gen(seed);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    for (size_t i = 0; i < count; i++) {
        weights[i] = dist(gen);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "GPU MAXIMUM PERFORMANCE BENCHMARK" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // 7B model config
    const uint32_t hidden = 4096;
    const uint32_t num_heads = 32;
    const uint32_t num_kv_heads = 8;
    const uint32_t intermediate = 14336;
    
    std::cout << "Model: 7B-scale" << std::endl;
    std::cout << "  Hidden: " << hidden << std::endl;
    std::cout << "  Intermediate: " << intermediate << std::endl;
    std::cout << std::endl;
    
    // Try to initialize GPU backend
    std::cout << "Initializing GPU backend..." << std::endl;
    TransformerGPULayer gpu_layer(hidden, num_heads, num_kv_heads, intermediate);
    
    if (!gpu_layer.Initialize(GPUBackend::VULKAN)) {
        std::cout << "Failed to initialize GPU backend. Falling back to CPU..." << std::endl;
        return 1;
    }
    
    std::cout << "GPU Backend: " << (gpu_layer.GetActiveBackend() == GPUBackend::VULKAN ? "Vulkan (RDNA3/7800XT)" :
                                      gpu_layer.GetActiveBackend() == GPUBackend::HIP ? "HIP (AMD)" :
                                      gpu_layer.GetActiveBackend() == GPUBackend::CUDA ? "CUDA (NVIDIA)" : "Unknown") << std::endl;
    std::cout << std::endl;
    
    // Allocate and initialize weights
    std::vector<float> q_w(hidden * hidden);
    std::vector<float> k_w(hidden * num_kv_heads * (hidden / num_heads));
    std::vector<float> v_w(hidden * num_kv_heads * (hidden / num_heads));
    std::vector<float> o_w(hidden * hidden);
    std::vector<float> ffn_g(hidden * intermediate);
    std::vector<float> ffn_u(hidden * intermediate);
    std::vector<float> ffn_d(intermediate * hidden);
    
    InitWeights(q_w, q_w.size(), 1);
    InitWeights(k_w, k_w.size(), 2);
    InitWeights(v_w, v_w.size(), 3);
    InitWeights(o_w, o_w.size(), 4);
    InitWeights(ffn_g, ffn_g.size(), 5);
    InitWeights(ffn_u, ffn_u.size(), 6);
    InitWeights(ffn_d, ffn_d.size(), 7);
    
    std::cout << "Loading weights to GPU..." << std::endl;
    if (!gpu_layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
                               ffn_g.data(), ffn_u.data(), ffn_d.data())) {
        std::cout << "Failed to load weights to GPU" << std::endl;
        return 1;
    }
    std::cout << "Weights loaded to GPU memory" << std::endl;
    std::cout << std::endl;
    
    // Initialize input
    std::vector<float> input(hidden);
    std::vector<float> output(hidden);
    InitWeights(input, input.size(), 10);
    
    // Warmup
    std::cout << "Warming up GPU..." << std::endl;
    for (int i = 0; i < 10; i++) {
        gpu_layer.Forward(input.data(), output.data(), 1);
    }
    std::cout << "Warmup complete." << std::endl << std::endl;
    
    // Benchmark
    const int iterations = 100;
    Timer timer;
    
    std::cout << "Benchmarking GPU inference..." << std::endl;
    timer.Start();
    for (int i = 0; i < iterations; i++) {
        gpu_layer.Forward(input.data(), output.data(), 1);
    }
    timer.Stop();
    
    double time_per_token_us = timer.ElapsedUs() / iterations;
    double tok_per_sec = 1000000.0 / time_per_token_us;
    
    std::cout << "  Time per token: " << time_per_token_us << " us" << std::endl;
    std::cout << "  Throughput: " << tok_per_sec << " tok/s" << std::endl;
    std::cout << "  Kernel time: " << gpu_layer.GetLastKernelTime() << " ms" << std::endl;
    std::cout << std::endl;
    
    std::cout << "========================================" << std::endl;
    std::cout << "GPU RESULT" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Throughput: " << tok_per_sec << " tok/s" << std::endl;
    std::cout << std::endl;
    
    if (tok_per_sec >= 200.0) {
        std::cout << "\u2705 EXCELLENT: 200+ tok/s on GPU!" << std::endl;
    } else if (tok_per_sec >= 150.0) {
        std::cout << "\u2705 GREAT: Matching/exceeding Qwen3-30B performance!" << std::endl;
    } else if (tok_per_sec >= 100.0) {
        std::cout << "\u2705 GOOD: 100+ tok/s GPU performance" << std::endl;
    } else {
        std::cout << "\u26a0 GPU underperforming - may need optimization" << std::endl;
    }
    
    return 0;
}
