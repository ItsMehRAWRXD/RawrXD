// Quick benchmark - simple version
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cmath>
#include <immintrin.h>

struct CPUInfo {
    bool has_avx512 = false;
    bool has_avx2 = false;
    int cores = 0;
    
    static CPUInfo Detect() {
        CPUInfo info;
        info.cores = std::thread::hardware_concurrency();
        
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        info.has_avx2 = (cpuInfo[2] & (1 << 28)) != 0;
        
        __cpuid(cpuInfo, 7);
        info.has_avx512 = (cpuInfo[1] & (1 << 16)) != 0;
        
        return info;
    }
};

void MatMul_AVX512(const float* A, const float* B, float* C, size_t M, size_t N, size_t K) {
    for (size_t i = 0; i < M; ++i) {
        for (size_t j = 0; j < N; j += 16) {
            __m512 c_vec = _mm512_setzero_ps();
            for (size_t k = 0; k < K; ++k) {
                __m512 a_vec = _mm512_set1_ps(A[i * K + k]);
                __m512 b_vec = _mm512_loadu_ps(&B[k * N + j]);
                c_vec = _mm512_fmadd_ps(a_vec, b_vec, c_vec);
            }
            _mm512_storeu_ps(&C[i * N + j], c_vec);
        }
    }
}

void MatMul_AVX2(const float* A, const float* B, float* C, size_t M, size_t N, size_t K) {
    for (size_t i = 0; i < M; ++i) {
        for (size_t j = 0; j < N; j += 8) {
            __m256 c_vec = _mm256_setzero_ps();
            for (size_t k = 0; k < K; ++k) {
                __m256 a_vec = _mm256_set1_ps(A[i * K + k]);
                __m256 b_vec = _mm256_loadu_ps(&B[k * N + j]);
                c_vec = _mm256_fmadd_ps(a_vec, b_vec, c_vec);
            }
            _mm256_storeu_ps(&C[i * N + j], c_vec);
        }
    }
}

double BenchmarkMatMul(size_t M, size_t N, size_t K, bool use_avx512) {
    std::vector<float> A(M * K, 0.01f);
    std::vector<float> B(K * N, 0.01f);
    std::vector<float> C(M * N, 0.0f);
    
    // Warmup
    if (use_avx512) {
        MatMul_AVX512(A.data(), B.data(), C.data(), M, N, K);
    } else {
        MatMul_AVX2(A.data(), B.data(), C.data(), M, N, K);
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    const int iterations = 5;
    
    for (int iter = 0; iter < iterations; ++iter) {
        if (use_avx512) {
            MatMul_AVX512(A.data(), B.data(), C.data(), M, N, K);
        } else {
            MatMul_AVX2(A.data(), B.data(), C.data(), M, N, K);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    double flops = 2.0 * M * N * K;
    double gflops = flops / (time_ms * 1e6);
    
    return gflops;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Quick Benchmark\n";
    std::cout << "========================================\n\n";
    
    CPUInfo cpu = CPUInfo::Detect();
    std::cout << "CPU Features:\n";
    std::cout << "  Cores: " << cpu.cores << "\n";
    std::cout << "  AVX512: " << (cpu.has_avx512 ? "Yes" : "No") << "\n";
    std::cout << "  AVX2: " << (cpu.has_avx2 ? "Yes" : "No") << "\n\n";
    
    double theoretical_max = cpu.has_avx512 ? 3072.0 : (cpu.has_avx2 ? 1536.0 : 384.0);
    std::cout << "Theoretical Max: " << theoretical_max << " GFLOPS\n\n";
    
    std::cout << "Running MatMul benchmarks...\n";
    
    struct Config { size_t M, N, K; const char* name; };
    Config configs[] = {
        {512, 512, 512, "512x512x512"},
        {1024, 1024, 1024, "1024x1024x1024"},
        {4096, 4096, 4096, "4096x4096x4096"}
    };
    
    double best_gflops = 0.0;
    
    for (const auto& cfg : configs) {
        double gflops = BenchmarkMatMul(cfg.M, cfg.N, cfg.K, cpu.has_avx512);
        double efficiency = (gflops / theoretical_max) * 100.0;
        
        std::cout << "  " << cfg.name << ": " 
                  << std::fixed << std::setprecision(1) << gflops << " GFLOPS"
                  << " (" << std::setprecision(1) << efficiency << "% efficiency)\n";
        
        if (gflops > best_gflops) best_gflops = gflops;
    }
    
    double overall_efficiency = (best_gflops / theoretical_max) * 100.0;
    
    std::cout << "\n========================================\n";
    std::cout << "Analysis\n";
    std::cout << "========================================\n";
    std::cout << "Best achieved: " << std::setprecision(1) << best_gflops << " GFLOPS\n";
    std::cout << "Efficiency: " << std::setprecision(1) << overall_efficiency << "%\n\n";
    
    if (overall_efficiency < 30.0) {
        std::cout << "=> Memory bandwidth bound\n";
        std::cout << "=> Recommendation: Implement Q4_0/Q8_0 quantization\n";
        std::cout << "=> Expected gain: 2-4x speedup\n";
    } else if (overall_efficiency < 60.0) {
        std::cout << "=> Partially compute bound\n";
        std::cout << "=> Recommendation: Enable multi-threading across heads\n";
        std::cout << "=> Expected gain: 1.5-2x speedup\n";
    } else {
        std::cout << "=> Well optimized\n";
        std::cout << "=> Recommendation: Consider batching for higher throughput\n";
    }
    
    std::cout << "\n========================================\n";
    
    return 0;
}
