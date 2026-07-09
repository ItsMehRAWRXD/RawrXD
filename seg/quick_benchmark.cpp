// Quick benchmark that writes results to file
#include <stdio>
#include <chrono>
#include <vector>
#include <immintrin.h>

// Simple CPU detection
struct CPUInfo {
    bool has_avx512 = false;
    bool has_avx2 = false;
    int cores = 0;
};

CPUInfo DetectCPU() {
    CPUInfo info;
    info.cores = 16; // Assume 16 cores based on previous detection
    
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    info.has_avx2 = (cpuInfo[2] & (1 << 28)) != 0;
    
    __cpuid(cpuInfo, 7);
    info.has_avx512 = (cpuInfo[1] & (1 << 16)) != 0;
    
    return info;
}

// AVX512 MatMul
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

// AVX2 MatMul
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

// Scalar MatMul
void MatMul_Scalar(const float* A, const float* B, float* C, size_t M, size_t N, size_t K) {
    for (size_t i = 0; i < M; ++i) {
        for (size_t j = 0; j < N; ++j) {
            float sum = 0.0f;
            for (size_t k = 0; k < K; ++k) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
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
    
    // Timed run
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
    FILE* f = fopen("d:\\__benchmark_results.txt", "w");
    if (!f) {
        printf("Failed to open output file\n");
        return 1;
    }
    
    fprintf(f, "========================================\n");
    fprintf(f, "RawrXD Quick Benchmark Results\n");
    fprintf(f, "========================================\n\n");
    
    CPUInfo cpu = DetectCPU();
    fprintf(f, "CPU Features:\n");
    fprintf(f, "  Cores: %d\n", cpu.cores);
    fprintf(f, "  AVX512: %s\n", cpu.has_avx512 ? "Yes" : "No");
    fprintf(f, "  AVX2: %s\n\n", cpu.has_avx2 ? "Yes" : "No");
    
    double theoretical_max = cpu.has_avx512 ? 3072.0 : (cpu.has_avx2 ? 1536.0 : 384.0);
    fprintf(f, "Theoretical Max: %.0f GFLOPS\n\n", theoretical_max);
    
    fprintf(f, "Running MatMul benchmarks...\n");
    
    struct Config {
        size_t M, N, K;
        const char* name;
    };
    
    Config configs[] = {
        {512, 512, 512, "512x512x512"},
        {1024, 1024, 1024, "1024x1024x1024"},
        {4096, 4096, 4096, "4096x4096x4096"}
    };
    
    double best_gflops = 0.0;
    
    for (const auto& cfg : configs) {
        double gflops = BenchmarkMatMul(cfg.M, cfg.N, cfg.K, cpu.has_avx512);
        double efficiency = (gflops / theoretical_max) * 100.0;
        
        fprintf(f, "  %s: %.1f GFLOPS (%.1f%% efficiency)\n", 
                cfg.name, gflops, efficiency);
        
        if (gflops > best_gflops) best_gflops = gflops;
    }
    
    double overall_efficiency = (best_gflops / theoretical_max) * 100.0;
    
    fprintf(f, "\n========================================\n");
    fprintf(f, "Analysis\n");
    fprintf(f, "========================================\n");
    fprintf(f, "Best achieved: %.1f GFLOPS\n", best_gflops);
    fprintf(f, "Efficiency: %.1f%%\n\n", overall_efficiency);
    
    if (overall_efficiency < 30.0) {
        fprintf(f, "=> Memory bandwidth bound\n");
        fprintf(f, "=> Recommendation: Implement Q4_0/Q8_0 quantization\n");
        fprintf(f, "=> Expected gain: 2-4x speedup\n");
    } else if (overall_efficiency < 60.0) {
        fprintf(f, "=> Partially compute bound\n");
        fprintf(f, "=> Recommendation: Enable multi-threading across heads\n");
        fprintf(f, "=> Expected gain: 1.5-2x speedup\n");
    } else {
        fprintf(f, "=> Well optimized\n");
        fprintf(f, "=> Recommendation: Consider batching for higher throughput\n");
    }
    
    fprintf(f, "\n========================================\n");
    
    fclose(f);
    printf("Benchmark complete. Results written to d:\\__benchmark_results.txt\n");
    
    return 0;
}
