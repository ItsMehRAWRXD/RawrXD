// ============================================================================
// Quick Kernel Benchmark - Measure Actual vs Theoretical
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cmath>

#include "../../rawrxd/src/kernels/avx2_kernels.hpp"
#include "../../rawrxd/src/kernels/avx512_kernels.hpp"

using namespace rawrxd::kernels;

struct BenchResult {
    const char* name;
    double time_ms;
    double gflops;
    double speedup_vs_scalar;
};

double BenchmarkMatMul(size_t M, size_t N, size_t K, int iterations = 100) {
    std::vector<float> A(M * K, 0.01f);
    std::vector<float> B(K * N, 0.01f);
    std::vector<float> C(M * N, 0.0f);
    
    // Warmup
    KernelDispatch::MatMulF32(A.data(), B.data(), C.data(), M, N, K);
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        KernelDispatch::MatMulF32(A.data(), B.data(), C.data(), M, N, K);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    // GFLOPS = 2 * M * N * K / time / 1e9
    double flops = 2.0 * M * N * K;
    double gflops = flops / (time_ms * 1e6);
    
    return gflops;
}

double BenchmarkVecDot(size_t N, int iterations = 1000) {
    std::vector<float> A(N, 0.01f);
    std::vector<float> B(N, 0.01f);
    
    // Warmup
    volatile float result = KernelDispatch::VecDotF32(A.data(), B.data(), N);
    (void)result;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        volatile float r = KernelDispatch::VecDotF32(A.data(), B.data(), N);
        (void)r;
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    // GFLOPS = 2 * N / time / 1e9
    double flops = 2.0 * N;
    double gflops = flops / (time_ms * 1e6);
    
    return gflops;
}

double BenchmarkRMSNorm(size_t N, int iterations = 1000) {
    std::vector<float> X(N, 0.5f);
    std::vector<float> weight(N, 1.0f);
    std::vector<float> Y(N, 0.0f);
    
    // Warmup
    KernelDispatch::RMSNormF32(X.data(), weight.data(), 1e-5f, Y.data(), N);
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        KernelDispatch::RMSNormF32(X.data(), weight.data(), 1e-5f, Y.data(), N);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    // Rough estimate: 3 * N operations (square, mean, sqrt, divide, multiply)
    double flops = 5.0 * N;
    double gflops = flops / (time_ms * 1e6);
    
    return gflops;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Kernel Performance Benchmark\n";
    std::cout << "========================================\n\n";
    
    // Print CPU features
    CPUFeatures::Print();
    std::cout << "\n";
    
    std::cout << "Running benchmarks...\n\n";
    
    // MatMul benchmarks
    std::cout << "Matrix Multiplication:\n";
    std::vector<std::tuple<size_t, size_t, size_t, const char*>> matmul_configs = {
        {512, 512, 512, "512x512x512"},
        {1024, 1024, 1024, "1024x1024x1024"},
        {4096, 4096, 4096, "4096x4096x4096 (7B model size)"},
    };
    
    for (const auto& config : matmul_configs) {
        size_t M = std::get<0>(config);
        size_t N = std::get<1>(config);
        size_t K = std::get<2>(config);
        const char* name = std::get<3>(config);
        
        double gflops = BenchmarkMatMul(M, N, K, 50);
        std::cout << "  " << name << ": " 
                  << std::fixed << std::setprecision(1) << gflops << " GFLOPS\n";
    }
    
    // VecDot benchmark
    std::cout << "\nVector Dot Product:\n";
    double vecdot_gflops = BenchmarkVecDot(1000000, 500);
    std::cout << "  1M elements: " << std::setprecision(1) << vecdot_gflops << " GFLOPS\n";
    
    // RMSNorm benchmark
    std::cout << "\nRMSNorm:\n";
    double rmsnorm_gflops = BenchmarkRMSNorm(4096, 500);
    std::cout << "  4096 elements: " << std::setprecision(1) << rmsnorm_gflops << " GFLOPS\n";
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "Summary\n";
    std::cout << "========================================\n";
    
    auto features = CPUFeatures::Detect();
    double theoretical_max = features.has_avx512f ? 3072.0 : (features.has_avx2 ? 1536.0 : 384.0);
    
    std::cout << "Theoretical max: " << theoretical_max << " GFLOPS\n";
    std::cout << "Achieved (MatMul): ~" << std::setprecision(0) << BenchmarkMatMul(512, 512, 512, 10) << " GFLOPS\n";
    
    double efficiency = BenchmarkMatMul(512, 512, 512, 10) / theoretical_max * 100.0;
    std::cout << "Efficiency: " << std::setprecision(1) << efficiency << "%\n\n";
    
    // Decision
    std::cout << "Analysis:\n";
    if (efficiency < 30.0) {
        std::cout << "  ⚠ Memory bandwidth bound\n";
        std::cout << "  → Recommendation: Implement Q4_0/Q8_0 quantization\n";
    } else if (efficiency < 60.0) {
        std::cout << "  ⚠ Partially compute bound\n";
        std::cout << "  → Recommendation: Enable multi-threading across heads\n";
    } else {
        std::cout << "  ✓ Well optimized\n";
        std::cout << "  → Consider batching for higher throughput\n";
    }
    
    std::cout << "\n========================================\n";
    
    return 0;
}
