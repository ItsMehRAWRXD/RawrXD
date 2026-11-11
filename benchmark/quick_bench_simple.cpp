// ============================================================================
// Quick Kernel Benchmark - Simple Version
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>

#include "../../rawrxd/src/kernels/avx2_kernels.hpp"
#include "../../rawrxd/src/kernels/avx512_kernels.hpp"

using namespace rawrxd::kernels;

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Quick Kernel Benchmark\n";
    std::cout << "========================================\n\n";
    
    CPUFeatures::Print();
    std::cout << "\n";
    
    // Simple MatMul test
    const size_t M = 512, N = 512, K = 512;
    std::vector<float> A(M * K, 0.01f);
    std::vector<float> B(K * N, 0.01f);
    std::vector<float> C(M * N, 0.0f);
    
    std::cout << "Testing MatMul (512x512x512)...\n";
    
    // Single iteration timing
    auto start = std::chrono::high_resolution_clock::now();
    KernelDispatch::MatMulF32(A.data(), B.data(), C.data(), M, N, K);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0;
    
    // Calculate GFLOPS
    double flops = 2.0 * M * N * K;
    double gflops = flops / (time_ms * 1e6);
    
    std::cout << "  Time: " << std::fixed << std::setprecision(2) << time_ms << " ms\n";
    std::cout << "  Performance: " << std::setprecision(1) << gflops << " GFLOPS\n\n";
    
    // Calculate efficiency
    auto features = CPUFeatures::Detect();
    double theoretical_max = features.has_avx512f ? 3072.0 : (features.has_avx2 ? 1536.0 : 384.0);
    double efficiency = gflops / theoretical_max * 100.0;
    
    std::cout << "Analysis:\n";
    std::cout << "  Theoretical max: " << theoretical_max << " GFLOPS\n";
    std::cout << "  Achieved: " << gflops << " GFLOPS\n";
    std::cout << "  Efficiency: " << std::setprecision(1) << efficiency << "%\n\n";
    
    if (efficiency < 30.0) {
        std::cout << "  => Memory bandwidth bound\n";
        std::cout << "  => Recommendation: Q4_0/Q8_0 quantization\n";
    } else if (efficiency < 60.0) {
        std::cout << "  => Partially compute bound\n";
        std::cout << "  => Recommendation: Multi-threading\n";
    } else {
        std::cout << "  => Well optimized\n";
        std::cout << "  => Consider batching\n";
    }
    
    std::cout << "\n========================================\n";
    
    return 0;
}
