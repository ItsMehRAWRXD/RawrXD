// ============================================================================
// INT8 vs FP32 Benchmark
// ============================================================================
// Compares quantized INT8 performance against FP32 baseline
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <cmath>
#include "int8_gemm.hpp"
#include "quantized_matmul_fast.hpp"

using namespace SEG;

// High-resolution timer
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

// Initialize weights with random values
void InitWeights(std::vector<float>& weights, size_t count, unsigned seed) {
    std::mt19937 gen(seed);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    for (size_t i = 0; i < count; i++) {
        weights[i] = dist(gen);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "INT8 vs FP32 GEMM Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // FFN dimensions
    const size_t hidden = 4096;
    const size_t intermediate = 14336;
    
    std::cout << "Matrix Dimensions:" << std::endl;
    std::cout << "  Input: [1, " << hidden << "]" << std::endl;
    std::cout << "  Weights: [" << intermediate << ", " << hidden << "]" << std::endl;
    std::cout << "  Output: [1, " << intermediate << "]" << std::endl;
    std::cout << std::endl;
    
    // Allocate and initialize
    std::vector<float> input(hidden);
    std::vector<float> weights(intermediate * hidden);
    std::vector<float> output_fp32(intermediate);
    std::vector<float> output_int8(intermediate);
    
    InitWeights(input, input.size(), 1);
    InitWeights(weights, weights.size(), 2);
    
    // Convert to INT8
    std::cout << "Converting weights to INT8..." << std::endl;
    Q8Matrix q8_weights = ConvertWeightsToQ8(weights.data(), intermediate, hidden);
    std::cout << "  Original size: " << (weights.size() * sizeof(float)) / (1024.0 * 1024.0) << " MB" << std::endl;
    std::cout << "  Quantized size: " << (intermediate * (hidden / 128) * sizeof(Q8_128_Block)) / (1024.0 * 1024.0) << " MB" << std::endl;
    std::cout << "  Compression ratio: " << (weights.size() * sizeof(float)) / (intermediate * (hidden / 128) * sizeof(Q8_128_Block)) << "x" << std::endl;
    std::cout << std::endl;
    
    // Warmup
    std::cout << "Warming up..." << std::endl;
    for (int i = 0; i < 10; i++) {
        FastVecMatMul(input.data(), weights.data(), output_fp32.data(), intermediate, hidden);
        Int8VecMatMul(input.data(), q8_weights, output_int8.data());
    }
    std::cout << "Warmup complete." << std::endl << std::endl;
    
    // Benchmark FP32
    const int iterations = 100;
    Timer timer;
    
    std::cout << "Benchmarking FP32..." << std::endl;
    timer.Start();
    for (int i = 0; i < iterations; i++) {
        FastVecMatMul(input.data(), weights.data(), output_fp32.data(), intermediate, hidden);
    }
    timer.Stop();
    
    double fp32_time_ms = timer.ElapsedMs();
    double fp32_time_per_op_us = timer.ElapsedUs() / iterations;
    double fp32_ops_per_sec = 1000000.0 / fp32_time_per_op_us;
    
    std::cout << "  Total time: " << fp32_time_ms << " ms" << std::endl;
    std::cout << "  Time per operation: " << fp32_time_per_op_us << " us" << std::endl;
    std::cout << "  Operations/sec: " << fp32_ops_per_sec << std::endl;
    std::cout << std::endl;
    
    // Benchmark INT8
    std::cout << "Benchmarking INT8..." << std::endl;
    timer.Start();
    for (int i = 0; i < iterations; i++) {
        Int8VecMatMul(input.data(), q8_weights, output_int8.data());
    }
    timer.Stop();
    
    double int8_time_ms = timer.ElapsedMs();
    double int8_time_per_op_us = timer.ElapsedUs() / iterations;
    double int8_ops_per_sec = 1000000.0 / int8_time_per_op_us;
    double speedup = fp32_time_ms / int8_time_ms;
    
    std::cout << "  Total time: " << int8_time_ms << " ms" << std::endl;
    std::cout << "  Time per operation: " << int8_time_per_op_us << " us" << std::endl;
    std::cout << "  Operations/sec: " << int8_ops_per_sec << std::endl;
    std::cout << "  Speedup: " << speedup << "x" << std::endl;
    std::cout << std::endl;
    
    // Verify accuracy
    std::cout << "Verifying accuracy..." << std::endl;
    double max_error = 0.0;
    double sum_error = 0.0;
    for (size_t i = 0; i < intermediate; i++) {
        double error = std::abs(output_fp32[i] - output_int8[i]);
        max_error = std::max(max_error, error);
        sum_error += error;
    }
    double avg_error = sum_error / intermediate;
    
    std::cout << "  Max error: " << max_error << std::endl;
    std::cout << "  Average error: " << avg_error << std::endl;
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "FP32: " << fp32_ops_per_sec << " ops/sec" << std::endl;
    std::cout << "INT8: " << int8_ops_per_sec << " ops/sec" << std::endl;
    std::cout << "Speedup: " << speedup << "x" << std::endl;
    std::cout << "Memory reduction: 4x" << std::endl;
    std::cout << std::endl;
    
    // Cleanup
    FreeQ8Matrix(q8_weights);
    
    return 0;
}
