// ============================================================================
// benchmark_avx512_intrinsics.cpp — Optimized AVX-512 Intrinsics Benchmark
// ============================================================================
//
// Compile with maximum optimization:
//   cl /O2 /arch:AVX512 /EHsc /W3 /Oi /GL /D_CRT_SECURE_NO_WARNINGS `
//      /Fobenchmark_avx512_intrinsics.obj `
//      benchmark_avx512_intrinsics.cpp
//
// Link:
//   link /LTCG /OUT:Benchmark_AVX512.exe `
//      benchmark_avx512_intrinsics.obj `
//      aperture_q4_0_avx512_intrinsics.obj `
//      aperture_q8_0_avx512_intrinsics.obj `
//      aperture_cpu_features.obj `
//      aperture_q4_0_reference.obj `
//      kernel32.lib
//
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

// Function declarations
extern "C" {
    int64_t Aperture_Q4_0_Dequant_AVX512_Intrinsics(float* dest, const uint8_t* src, uint64_t blockCount);
    int64_t Aperture_Q8_0_Dequant_AVX512_Intrinsics(float* dest, const uint8_t* src, uint64_t blockCount);
    void Aperture_InitDispatch(void);
    int Aperture_IsAVX512Available(void);
}

// High-resolution timer
static LARGE_INTEGER freq;
static LARGE_INTEGER start_time;

void timer_init() {
    QueryPerformanceFrequency(&freq);
}

void timer_start() {
    QueryPerformanceCounter(&start_time);
}

double timer_elapsed_ms() {
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start_time.QuadPart) * 1000.0 / freq.QuadPart;
}

// Generate test data
void generate_q4_0_test_data(uint8_t* src, uint64_t blockCount) {
    for (uint64_t b = 0; b < blockCount; ++b) {
        uint8_t* block = src + b * 18;
        // Scale = 1.0 (float16 = 0x3C00)
        block[0] = 0x00;
        block[1] = 0x3C;
        // Random weights
        for (int i = 2; i < 18; ++i) {
            block[i] = (uint8_t)((i * 7 + b * 13) % 256);
        }
    }
}

void generate_q8_0_test_data(uint8_t* src, uint64_t blockCount) {
    for (uint64_t b = 0; b < blockCount; ++b) {
        uint8_t* block = src + b * 34;
        // Scale = 1.0 (float16 = 0x3C00)
        block[0] = 0x00;
        block[1] = 0x3C;
        // Random int8 weights
        for (int i = 2; i < 34; ++i) {
            block[i] = (uint8_t)((i * 5 + b * 11) % 256);
        }
    }
}

// Benchmark Q4_0
void benchmark_q4_0(const char* name, uint64_t blockCount, int iterations) {
    size_t srcSize = blockCount * 18;
    size_t dstSize = blockCount * 32 * sizeof(float);
    
    uint8_t* src = (uint8_t*)malloc(srcSize);
    float* dst = (float*)malloc(dstSize);
    
    if (!src || !dst) {
        printf("[ERROR] Memory allocation failed\n");
        return;
    }
    
    generate_q4_0_test_data(src, blockCount);
    
    // Warmup
    Aperture_Q4_0_Dequant_AVX512_Intrinsics(dst, src, blockCount);
    
    // Benchmark
    timer_start();
    for (int i = 0; i < iterations; ++i) {
        Aperture_Q4_0_Dequant_AVX512_Intrinsics(dst, src, blockCount);
    }
    double elapsed_ms = timer_elapsed_ms();
    
    uint64_t totalWeights = blockCount * 32 * iterations;
    double weightsPerSec = (double)totalWeights / (elapsed_ms / 1000.0);
    double msPerIteration = elapsed_ms / iterations;
    
    printf("[%s] Blocks: %llu, Iterations: %d\n", name, blockCount, iterations);
    printf("  Time: %.3f ms total, %.3f ms/iter\n", elapsed_ms, msPerIteration);
    printf("  Throughput: %.2fM weights/sec\n", weightsPerSec / 1000000.0);
    printf("  Speedup vs baseline: %.1fx\n", weightsPerSec / 1260000.0); // Baseline: 1.26M
    printf("\n");
    
    free(src);
    free(dst);
}

// Benchmark Q8_0
void benchmark_q8_0(const char* name, uint64_t blockCount, int iterations) {
    size_t srcSize = blockCount * 34;
    size_t dstSize = blockCount * 32 * sizeof(float);
    
    uint8_t* src = (uint8_t*)malloc(srcSize);
    float* dst = (float*)malloc(dstSize);
    
    if (!src || !dst) {
        printf("[ERROR] Memory allocation failed\n");
        return;
    }
    
    generate_q8_0_test_data(src, blockCount);
    
    // Warmup
    Aperture_Q8_0_Dequant_AVX512_Intrinsics(dst, src, blockCount);
    
    // Benchmark
    timer_start();
    for (int i = 0; i < iterations; ++i) {
        Aperture_Q8_0_Dequant_AVX512_Intrinsics(dst, src, blockCount);
    }
    double elapsed_ms = timer_elapsed_ms();
    
    uint64_t totalWeights = blockCount * 32 * iterations;
    double weightsPerSec = (double)totalWeights / (elapsed_ms / 1000.0);
    double msPerIteration = elapsed_ms / iterations;
    
    printf("[%s] Blocks: %llu, Iterations: %d\n", name, blockCount, iterations);
    printf("  Time: %.3f ms total, %.3f ms/iter\n", elapsed_ms, msPerIteration);
    printf("  Throughput: %.2fM weights/sec\n", weightsPerSec / 1000000.0);
    printf("  Speedup vs baseline: %.1fx\n", weightsPerSec / 1260000.0);
    printf("\n");
    
    free(src);
    free(dst);
}

int main() {
    printf("========================================\n");
    printf("AVX-512 Intrinsics Benchmark\n");
    printf("========================================\n\n");
    
    timer_init();
    Aperture_InitDispatch();
    
    if (!Aperture_IsAVX512Available()) {
        printf("[ERROR] AVX-512 not available on this CPU\n");
        return 1;
    }
    
    printf("[INFO] AVX-512 detected and enabled\n\n");
    
    // Q4_0 Benchmarks
    printf("--- Q4_0 Dequantization ---\n\n");
    benchmark_q4_0("Small", 64, 1000);      // 2K weights
    benchmark_q4_0("Medium", 512, 100);    // 16K weights
    benchmark_q4_0("Large", 4096, 10);      // 128K weights
    benchmark_q4_0("XLarge", 32768, 5);     // 1M weights
    
    // Q8_0 Benchmarks
    printf("--- Q8_0 Dequantization ---\n\n");
    benchmark_q8_0("Small", 64, 1000);
    benchmark_q8_0("Medium", 512, 100);
    benchmark_q8_0("Large", 4096, 10);
    benchmark_q8_0("XLarge", 32768, 5);
    
    printf("========================================\n");
    printf("Benchmark Complete\n");
    printf("========================================\n");
    
    return 0;
}
