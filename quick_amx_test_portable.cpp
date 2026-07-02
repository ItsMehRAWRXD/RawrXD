// =============================================================================
// quick_amx_test_portable.cpp
// Portable AMX/INT8 validation test - No Windows SDK required
// Compile: cl.exe /O2 /arch:AVX512 /EHsc quick_amx_test_portable.cpp
// Or: g++ -O3 -march=native -o quick_amx_test_portable.exe quick_amx_test_portable.cpp
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    #include <intrin.h>
    #define aligned_alloc(align, size) _aligned_malloc(size, align)
    #define aligned_free(ptr) _aligned_free(ptr)
#else
    #include <x86intrin.h>
    #include <cpuid.h>
    #define aligned_alloc(align, size) aligned_alloc(align, size)
    #define aligned_free(ptr) free(ptr)
#endif

// =============================================================================
// CPU Feature Detection
// =============================================================================

struct CPUFeatures {
    int hasAVX512F;
    int hasAVX512_VNNI;
    int hasAMX_TILE;
    int hasAMX_BF16;
    int hasAMX_INT8;
};

void detectCPUFeatures(CPUFeatures* features) {
    memset(features, 0, sizeof(CPUFeatures));
    
    int cpuInfo[4] = {0};
    
    // Check max CPUID leaf
    #ifdef _WIN32
    __cpuid(cpuInfo, 0);
    #else
    __cpuid(0, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    #endif
    
    int maxLeaf = cpuInfo[0];
    
    if (maxLeaf >= 7) {
        // Get extended features
        #ifdef _WIN32
        __cpuidex(cpuInfo, 7, 0);
        #else
        __cpuid_count(7, 0, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
        #endif
        
        // Check AVX-512
        features->hasAVX512F = (cpuInfo[1] >> 16) & 1;
        features->hasAVX512_VNNI = (cpuInfo[2] >> 11) & 1;
        
        // Check AMX (EDX)
        features->hasAMX_TILE = (cpuInfo[3] >> 24) & 1;
        features->hasAMX_BF16 = (cpuInfo[3] >> 22) & 1;
        features->hasAMX_INT8 = (cpuInfo[3] >> 25) & 1;
    }
}

// =============================================================================
// Simple INT8 Matrix Multiplication (Reference)
// =============================================================================

void matmul_int8_ref(const int8_t* A, const int8_t* B, int32_t* C,
                     int M, int N, int K) {
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            int32_t sum = 0;
            for (int k = 0; k < K; k++) {
                sum += (int32_t)A[i * K + k] * (int32_t)B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

// =============================================================================
// Simple FP32 Matrix Multiplication (Reference)
// =============================================================================

void matmul_fp32_ref(const float* A, const float* B, float* C,
                     int M, int N, int K) {
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

// =============================================================================
// Quantization Helpers
// =============================================================================

void quantize_fp32_to_int8(const float* src, int8_t* dst, int size, float scale) {
    for (int i = 0; i < size; i++) {
        float val = src[i] / scale;
        // Clamp to int8 range
        if (val > 127.0f) val = 127.0f;
        if (val < -128.0f) val = -128.0f;
        dst[i] = (int8_t)roundf(val);
    }
}

void dequantize_int32_to_fp32(const int32_t* src, float* dst, int size, float scale) {
    for (int i = 0; i < size; i++) {
        dst[i] = (float)src[i] * scale * scale;
    }
}

// =============================================================================
// Performance Timer
// =============================================================================

#ifdef _WIN32
typedef LARGE_INTEGER timer_t;
void timer_start(timer_t* t) { QueryPerformanceCounter(t); }
double timer_elapsed_ms(timer_t* start) {
    LARGE_INTEGER end, freq;
    QueryPerformanceCounter(&end);
    QueryPerformanceFrequency(&freq);
    return (double)(end.QuadPart - start->QuadPart) * 1000.0 / freq.QuadPart;
}
#else
typedef struct timespec timer_t;
void timer_start(timer_t* t) { clock_gettime(CLOCK_MONOTONIC, t); }
double timer_elapsed_ms(timer_t* start) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - start->tv_sec) * 1000.0 + (end.tv_nsec - start->tv_nsec) / 1e6;
}
#endif

// =============================================================================
// Main Test
// =============================================================================

int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Quick AMX/INT8 Validation Test                                  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    // Detect CPU features
    CPUFeatures features;
    detectCPUFeatures(&features);
    
    printf("CPU Feature Detection:\n");
    printf("  AVX-512F:     %s\n", features.hasAVX512F ? "YES" : "NO");
    printf("  AVX-512-VNNI: %s\n", features.hasAVX512_VNNI ? "YES" : "NO");
    printf("  AMX-TILE:     %s\n", features.hasAMX_TILE ? "YES" : "NO");
    printf("  AMX-BF16:     %s\n", features.hasAMX_BF16 ? "YES" : "NO");
    printf("  AMX-INT8:     %s\n", features.hasAMX_INT8 ? "YES" : "NO");
    printf("\n");
    
    // Test configuration
    const int M = 512;   // Rows of A
    const int N = 512;   // Cols of B
    const int K = 512;   // Inner dimension
    const int ITERATIONS = 10;
    
    printf("Test Configuration:\n");
    printf("  Matrix A: %d x %d\n", M, K);
    printf("  Matrix B: %d x %d\n", K, N);
    printf("  Matrix C: %d x %d\n", M, N);
    printf("  Iterations: %d\n\n", ITERATIONS);
    
    // Allocate memory
    float* A_fp32 = (float*)aligned_alloc(64, M * K * sizeof(float));
    float* B_fp32 = (float*)aligned_alloc(64, K * N * sizeof(float));
    float* C_fp32 = (float*)aligned_alloc(64, M * N * sizeof(float));
    
    int8_t* A_int8 = (int8_t*)aligned_alloc(64, M * K * sizeof(int8_t));
    int8_t* B_int8 = (int8_t*)aligned_alloc(64, K * N * sizeof(int8_t));
    int32_t* C_int32 = (int32_t*)aligned_alloc(64, M * N * sizeof(int32_t));
    float* C_dequant = (float*)aligned_alloc(64, M * N * sizeof(float));
    
    if (!A_fp32 || !B_fp32 || !C_fp32 || !A_int8 || !B_int8 || !C_int32 || !C_dequant) {
        printf("ERROR: Memory allocation failed\n");
        return 1;
    }
    
    // Initialize with random data
    srand(42);
    float scale = 0.1f;
    
    for (int i = 0; i < M * K; i++) {
        A_fp32[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
    }
    for (int i = 0; i < K * N; i++) {
        B_fp32[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
    }
    
    // Quantize to INT8
    printf("Quantizing to INT8...\n");
    quantize_fp32_to_int8(A_fp32, A_int8, M * K, scale);
    quantize_fp32_to_int8(B_fp32, B_int8, K * N, scale);
    
    // Warmup
    printf("Warming up...\n");
    matmul_fp32_ref(A_fp32, B_fp32, C_fp32, M, N, K);
    matmul_int8_ref(A_int8, B_int8, C_int32, M, N, K);
    
    // Benchmark FP32
    printf("\nBenchmarking FP32...\n");
    timer_t timer;
    double fp32_total = 0;
    
    for (int iter = 0; iter < ITERATIONS; iter++) {
        timer_start(&timer);
        matmul_fp32_ref(A_fp32, B_fp32, C_fp32, M, N, K);
        fp32_total += timer_elapsed_ms(&timer);
    }
    
    double fp32_avg = fp32_total / ITERATIONS;
    double fp32_gflops = (2.0 * M * N * K) / (fp32_avg * 1e-3) / 1e9;
    
    // Benchmark INT8
    printf("Benchmarking INT8...\n");
    double int8_total = 0;
    
    for (int iter = 0; iter < ITERATIONS; iter++) {
        timer_start(&timer);
        matmul_int8_ref(A_int8, B_int8, C_int32, M, N, K);
        int8_total += timer_elapsed_ms(&timer);
    }
    
    double int8_avg = int8_total / ITERATIONS;
    double int8_gflops = (2.0 * M * N * K) / (int8_avg * 1e-3) / 1e9;
    
    // Dequantize INT8 result for comparison
    dequantize_int32_to_fp32(C_int32, C_dequant, M * N, scale);
    
    // Calculate error
    double max_error = 0;
    double sum_error = 0;
    
    for (int i = 0; i < M * N; i++) {
        double error = fabs(C_fp32[i] - C_dequant[i]);
        if (error > max_error) max_error = error;
        sum_error += error;
    }
    double mean_error = sum_error / (M * N);
    
    // Results
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Results                                                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("FP32 Performance:\n");
    printf("  Average Time: %.3f ms\n", fp32_avg);
    printf("  Throughput:   %.2f GFLOPS\n", fp32_gflops);
    printf("\n");
    
    printf("INT8 Performance:\n");
    printf("  Average Time: %.3f ms\n", int8_avg);
    printf("  Throughput:   %.2f GFLOPS\n", int8_gflops);
    printf("\n");
    
    printf("Speedup: %.2fx\n", fp32_avg / int8_avg);
    printf("\n");
    
    printf("Quantization Error:\n");
    printf("  Mean Error: %.6f\n", mean_error);
    printf("  Max Error:  %.6f\n", max_error);
    printf("\n");
    
    // Validation
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    if (mean_error < 0.1) {
        printf("║  VALIDATION: PASS - Quantization error within tolerance        ║\n");
    } else {
        printf("║  VALIDATION: FAIL - Quantization error too high                ║\n");
    }
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Cleanup
    aligned_free(A_fp32);
    aligned_free(B_fp32);
    aligned_free(C_fp32);
    aligned_free(A_int8);
    aligned_free(B_int8);
    aligned_free(C_int32);
    aligned_free(C_dequant);
    
    return 0;
}
