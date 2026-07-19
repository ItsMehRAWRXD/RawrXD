// ============================================================================
// deep2_kernel_bench.cpp - Deep2 Kernel Microbenchmark
// Measures actual kernel throughput without architectural overhead
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>
#include <random>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

// Deep2 kernel declarations
extern "C" {
    void Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n);
    void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n);
    void Deep2_RMSNorm(const float* x, float* out, size_t n, float eps);
}

// Aligned allocation
float* AlignedAlloc(size_t count) {
#ifdef _WIN32
    return (float*)_aligned_malloc(count * sizeof(float), 32);
#else
    return (float*)aligned_alloc(32, count * sizeof(float));
#endif
}

void AlignedFree(float* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

// High-resolution timer
double GetTimeMs() {
    using namespace std::chrono;
    return duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count() / 1000.0;
}

// Benchmark result
struct BenchResult {
    const char* name;
    double timeMs;
    double cyclesPerElement;
    double throughputGBps;
    size_t totalElements;
    size_t iterations;
};

// Run kernel benchmark
template<typename KernelFunc>
BenchResult RunKernelBenchmark(const char* name, KernelFunc kernel, 
                                size_t elements, size_t iterations,
                                float* a, float* b, float* out) {
    // Warmup
    for (size_t i = 0; i < 10; i++) {
        kernel(a, b, out, elements);
    }
    
    // Benchmark
    double start = GetTimeMs();
    for (size_t i = 0; i < iterations; i++) {
        kernel(a, b, out, elements);
    }
    double end = GetTimeMs();
    
    double timeMs = end - start;
    size_t totalElements = elements * iterations;
    double totalBytes = totalElements * sizeof(float);
    
    // Estimate cycles (assuming 3.5 GHz)
    double cpuFreq = 3.5e9;
    double cycles = (timeMs / 1000.0) * cpuFreq;
    double cyclesPerElement = cycles / totalElements;
    double throughputGBps = (totalBytes / (1024.0 * 1024.0 * 1024.0)) / (timeMs / 1000.0);
    
    return {name, timeMs, cyclesPerElement, throughputGBps, totalElements, iterations};
}

int main() {
    printf("=================================================================\n");
    printf("Deep2 Kernel Microbenchmark\n");
    printf("=================================================================\n\n");
    
    // Configuration - process 1B elements total
    const size_t elements = 1024 * 1024 * 64;  // 64M elements
    const size_t iterations = 16;  // 16 iterations = 1B elements total
    
    printf("Configuration:\n");
    printf("  Elements per call: %zu (%.1f MB)\n", elements, elements * sizeof(float) / (1024.0 * 1024.0));
    printf("  Iterations: %zu\n", iterations);
    printf("  Total elements: %zu (%.1f GB)\n\n", 
           elements * iterations, 
           elements * iterations * sizeof(float) / (1024.0 * 1024.0 * 1024.0));
    
    // Allocate aligned memory
    printf("Allocating memory...\n");
    float* a = AlignedAlloc(elements);
    float* b = AlignedAlloc(elements);
    float* out = AlignedAlloc(elements);
    
    if (!a || !b || !out) {
        printf("ERROR: Failed to allocate memory\n");
        return 1;
    }
    
    // Initialize with deterministic data
    printf("Initializing data...\n");
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (size_t i = 0; i < elements; i++) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    printf("Running benchmarks...\n\n");
    
    // Benchmark VecDotProduct
    printf("[1/3] VecDotProduct...\n");
    auto resultVecDot = RunKernelBenchmark(
        "VecDotProduct",
        [](const float* a, const float* b, float* out, size_t n) {
            Deep2_VecDotProduct(a, b, out, n);
        },
        elements, iterations, a, b, out
    );
    
    // Benchmark SwiGLU
    printf("[2/3] SwiGLU...\n");
    auto resultSwiGLU = RunKernelBenchmark(
        "SwiGLU",
        [](const float* a, const float* b, float* out, size_t n) {
            Deep2_SwiGLU(a, b, out, n);
        },
        elements, iterations, a, b, out
    );
    
    // Benchmark RMSNorm
    printf("[3/3] RMSNorm...\n");
    auto resultRMSNorm = RunKernelBenchmark(
        "RMSNorm",
        [](const float* a, const float* b, float* out, size_t n) {
            Deep2_RMSNorm(a, out, n, 1e-6f);
        },
        elements, iterations, a, b, out
    );
    
    // Print results
    printf("\n=================================================================\n");
    printf("RESULTS\n");
    printf("=================================================================\n\n");
    
    auto printResult = [](const BenchResult& r) {
        printf("%s:\n", r.name);
        printf("  Time:             %.2f ms\n", r.timeMs);
        printf("  Cycles/Element:   %.2f\n", r.cyclesPerElement);
        printf("  Throughput:       %.2f GB/s\n", r.throughputGBps);
        printf("  Total Elements:   %zu\n", r.totalElements);
        printf("\n");
    };
    
    printResult(resultVecDot);
    printResult(resultSwiGLU);
    printResult(resultRMSNorm);
    
    // Calculate projected TPS
    printf("=================================================================\n");
    printf("PROJECTED INFERENCE PERFORMANCE\n");
    printf("=================================================================\n\n");
    
    // Assume 40GB model, 2 bytes per parameter (Q4), 2 reads per token
    double modelSizeGB = 40.0;
    double bytesPerToken = modelSizeGB * 0.5;  // Q4 = 0.5 bytes per param
    double memoryBandwidth = resultVecDot.throughputGBps;  // Use VecDot as proxy
    
    double projectedTPS = memoryBandwidth / bytesPerToken * 1000.0;
    
    printf("Model Size:         %.1f GB\n", modelSizeGB);
    printf("Quantization:       Q4 (0.5 bytes/param)\n");
    printf("Memory Bandwidth:   %.2f GB/s\n", memoryBandwidth);
    printf("Bytes/Token:        %.1f\n", bytesPerToken);
    printf("\n");
    printf("Projected TPS:      %.1f tokens/sec\n", projectedTPS);
    printf("Latency/Token:      %.2f ms\n", 1000.0 / projectedTPS);
    printf("\n");
    
    // Cleanup
    AlignedFree(a);
    AlignedFree(b);
    AlignedFree(out);
    
    // Export to CSV
    FILE* csv = fopen("deep2_kernel_benchmark.csv", "w");
    if (csv) {
        fprintf(csv, "Kernel,Time_ms,Cycles_Per_Element,Throughput_GBps,Total_Elements\n");
        fprintf(csv, "%s,%.2f,%.2f,%.2f,%zu\n", 
                resultVecDot.name, resultVecDot.timeMs, resultVecDot.cyclesPerElement,
                resultVecDot.throughputGBps, resultVecDot.totalElements);
        fprintf(csv, "%s,%.2f,%.2f,%.2f,%zu\n", 
                resultSwiGLU.name, resultSwiGLU.timeMs, resultSwiGLU.cyclesPerElement,
                resultSwiGLU.throughputGBps, resultSwiGLU.totalElements);
        fprintf(csv, "%s,%.2f,%.2f,%.2f,%zu\n", 
                resultRMSNorm.name, resultRMSNorm.timeMs, resultRMSNorm.cyclesPerElement,
                resultRMSNorm.throughputGBps, resultRMSNorm.totalElements);
        fprintf(csv, "\nProjected_TPS,%.1f,,,\n", projectedTPS);
        fclose(csv);
        printf("Results exported to: deep2_kernel_benchmark.csv\n");
    }
    
    printf("\n=================================================================\n");
    
    return 0;
}
