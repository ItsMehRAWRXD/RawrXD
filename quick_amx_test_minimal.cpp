// =============================================================================
// quick_amx_test_minimal.cpp
// Minimal AMX/INT8 validation - Pure C++, no platform headers
// Compile: cl.exe /O2 /arch:AVX512 /EHsc quick_amx_test_minimal.cpp
// Or: g++ -O3 -march=native -o quick_amx_test.exe quick_amx_test_minimal.cpp
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

// =============================================================================
// CPU Feature Detection (CPUID)
// =============================================================================

#ifdef _MSC_VER
    #include <intrin.h>
    #define cpuid(info, x) __cpuidex(info, x, 0)
#else
    #include <cpuid.h>
    #define cpuid(info, x) __cpuid_count(x, 0, info[0], info[1], info[2], info[3])
#endif

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
    cpuid(cpuInfo, 0);
    int maxLeaf = cpuInfo[0];
    
    if (maxLeaf >= 7) {
        // Get extended features
        cpuid(cpuInfo, 7);
        
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

// Calculate optimal scale factor based on tensor range
float calculate_scale(const float* src, int size) {
    float max_val = 0.0f;
    for (int i = 0; i < size; i++) {
        float abs_val = fabsf(src[i]);
        if (abs_val > max_val) max_val = abs_val;
    }
    // Use 127.0f (not 128.0f) to avoid overflow on negative values
    return (max_val > 0.0f) ? (max_val / 127.0f) : 1.0f;
}

void quantize_fp32_to_int8(const float* src, int8_t* dst, int size, float scale) {
    for (int i = 0; i < size; i++) {
        float val = src[i] / scale;
        // Clamp to int8 range [-128, 127]
        if (val > 127.0f) val = 127.0f;
        if (val < -128.0f) val = -128.0f;
        dst[i] = (int8_t)(val > 0 ? val + 0.5f : val - 0.5f);
    }
}

void dequantize_int32_to_fp32(const int32_t* src, float* dst, int size, float scale_A, float scale_B) {
    float combined_scale = scale_A * scale_B;
    for (int i = 0; i < size; i++) {
        dst[i] = (float)src[i] * combined_scale;
    }
}

// =============================================================================
// Performance Timer (clock())
// =============================================================================

double get_time_ms() {
    return (double)clock() * 1000.0 / CLOCKS_PER_SEC;
}

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
    float* A_fp32 = (float*)malloc(M * K * sizeof(float));
    float* B_fp32 = (float*)malloc(K * N * sizeof(float));
    float* C_fp32 = (float*)malloc(M * N * sizeof(float));
    
    int8_t* A_int8 = (int8_t*)malloc(M * K * sizeof(int8_t));
    int8_t* B_int8 = (int8_t*)malloc(K * N * sizeof(int8_t));
    int32_t* C_int32 = (int32_t*)malloc(M * N * sizeof(int32_t));
    float* C_dequant = (float*)malloc(M * N * sizeof(float));
    
    if (!A_fp32 || !B_fp32 || !C_fp32 || !A_int8 || !B_int8 || !C_int32 || !C_dequant) {
        printf("ERROR: Memory allocation failed\n");
        return 1;
    }
    
    // Initialize with random data
    srand(42);
    
    for (int i = 0; i < M * K; i++) {
        A_fp32[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
    }
    for (int i = 0; i < K * N; i++) {
        B_fp32[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
    }
    
    // Calculate optimal scale factors for each tensor
    printf("Calculating optimal scale factors...\n");
    float scale_A = calculate_scale(A_fp32, M * K);
    float scale_B = calculate_scale(B_fp32, K * N);
    
    // Use geometric mean of scales for symmetric quantization
    float scale = sqrtf(scale_A * scale_B);
    printf("  Scale A: %.6f\n", scale_A);
    printf("  Scale B: %.6f\n", scale_B);
    printf("  Combined scale: %.6f\n\n", scale);
    
    // Quantize to INT8
    printf("Quantizing to INT8...\n");
    quantize_fp32_to_int8(A_fp32, A_int8, M * K, scale_A);
    quantize_fp32_to_int8(B_fp32, B_int8, K * N, scale_B);
    
    // Warmup
    printf("Warming up...\n");
    matmul_fp32_ref(A_fp32, B_fp32, C_fp32, M, N, K);
    matmul_int8_ref(A_int8, B_int8, C_int32, M, N, K);
    
    // Benchmark FP32
    printf("\nBenchmarking FP32...\n");
    double fp32_total = 0;
    
    for (int iter = 0; iter < ITERATIONS; iter++) {
        double start = get_time_ms();
        matmul_fp32_ref(A_fp32, B_fp32, C_fp32, M, N, K);
        fp32_total += get_time_ms() - start;
    }
    
    double fp32_avg = fp32_total / ITERATIONS;
    double fp32_gflops = (2.0 * M * N * K) / (fp32_avg * 1e-3) / 1e9;
    
    // Benchmark INT8
    printf("Benchmarking INT8...\n");
    double int8_total = 0;
    
    for (int iter = 0; iter < ITERATIONS; iter++) {
        double start = get_time_ms();
        matmul_int8_ref(A_int8, B_int8, C_int32, M, N, K);
        int8_total += get_time_ms() - start;
    }
    
    double int8_avg = int8_total / ITERATIONS;
    double int8_gflops = (2.0 * M * N * K) / (int8_avg * 1e-3) / 1e9;
    
    // Dequantize INT8 result for comparison
    dequantize_int32_to_fp32(C_int32, C_dequant, M * N, scale_A, scale_B);
    
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
    free(A_fp32);
    free(B_fp32);
    free(C_fp32);
    free(A_int8);
    free(B_int8);
    free(C_int32);
    free(C_dequant);
    
    return 0;
}
