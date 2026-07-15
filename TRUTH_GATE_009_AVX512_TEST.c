// Truth Gate 009: AVX-512 Optimization Test
// C wrapper to test MASM AVX-512 kernels
//
// Build: gcc -O3 -o truth_gate_009.exe TRUTH_GATE_009_AVX512_TEST.c -lm
// Run:   .\truth_gate_009.exe

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>

static double GET_TIME() {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}

// Check AVX-512 support using CPUID
int check_avx512_support() {
    int cpuinfo[4];
    
    // Check CPUID leaf 7, sub-leaf 0
    __cpuidex(cpuinfo, 7, 0);
    
    // Check AVX-512 Foundation (bit 16 of EBX)
    if (!(cpuinfo[1] & (1 << 16))) return 0;
    
    // Check AVX-512 DQ (bit 17)
    if (!(cpuinfo[1] & (1 << 17))) return 0;
    
    // Check AVX-512 BW (bit 30)
    if (!(cpuinfo[1] & (1 << 30))) return 0;
    
    return 1;
}

#else
#include <sys/time.h>
#include <cpuid.h>

static double GET_TIME() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int check_avx512_support() {
    unsigned int eax, ebx, ecx, edx;
    
    // Check CPUID leaf 7, sub-leaf 0
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) == 0) return 0;
    
    // Check AVX-512 Foundation (bit 16 of EBX)
    if (!(ebx & (1 << 16))) return 0;
    
    // Check AVX-512 DQ (bit 17)
    if (!(ebx & (1 << 17))) return 0;
    
    // Check AVX-512 BW (bit 30)
    if (!(ebx & (1 << 30))) return 0;
    
    return 1;
}
#endif

// ============================================================================
// Scalar Fallback Implementations
// ============================================================================

void scalar_rms_norm(float *out, const float *in, int size, float eps) {
    float sum = 0.0f;
    for (int i = 0; i < size; i++) sum += in[i] * in[i];
    float scale = 1.0f / sqrtf(sum / size + eps);
    for (int i = 0; i < size; i++) out[i] = in[i] * scale;
}

void scalar_softmax(float *x, int size) {
    float max_val = x[0];
    for (int i = 1; i < size; i++) if (x[i] > max_val) max_val = x[i];
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    for (int i = 0; i < size; i++) x[i] /= sum;
}

void scalar_matmul(const float *A, const float *B, float *C, int M, int N, int K) {
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

// ============================================================================
// Benchmark Functions
// ============================================================================

typedef void (*rms_norm_func_t)(float*, const float*, int, float);
typedef void (*softmax_func_t)(float*, int);
typedef void (*matmul_func_t)(const float*, const float*, float*, int, int, int);

double benchmark_rms_norm(rms_norm_func_t func, float *out, const float *in, int size, float eps, int iterations) {
    double start = GET_TIME();
    for (int i = 0; i < iterations; i++) {
        func(out, in, size, eps);
    }
    return GET_TIME() - start;
}

double benchmark_softmax(softmax_func_t func, float *x, int size, int iterations) {
    // Make a copy for each iteration
    float *temp = malloc(size * sizeof(float));
    double start = GET_TIME();
    for (int i = 0; i < iterations; i++) {
        memcpy(temp, x, size * sizeof(float));
        func(temp, size);
    }
    double elapsed = GET_TIME() - start;
    free(temp);
    return elapsed;
}

double benchmark_matmul(matmul_func_t func, const float *A, const float *B, float *C, 
                        int M, int N, int K, int iterations) {
    double start = GET_TIME();
    for (int i = 0; i < iterations; i++) {
        func(A, B, C, M, N, K);
    }
    return GET_TIME() - start;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  TRUTH GATE 009: AVX-512 Optimization                     ║\n");
    printf("║  Target: 10,000+ TPS with SIMD Kernels                     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    // Check AVX-512 support
    printf("[1/5] Checking AVX-512 support...\n");
    int has_avx512 = check_avx512_support();
    if (has_avx512) {
        printf("  ✅ AVX-512 FOUND: AVX-512F, AVX-512DQ, AVX-512BW\n\n");
    } else {
        printf("  ❌ AVX-512 NOT FOUND\n");
        printf("  Running scalar benchmarks only\n\n");
    }
    
    // Allocate aligned memory for benchmarks
    printf("[2/5] Allocating test buffers...\n");
    int test_size = 4096;  // 4K elements
    int iterations = 1000;
    
    float *in_buffer = NULL;
    float *out_buffer = NULL;
    float *test_x = NULL;
    
    #ifdef _WIN32
    in_buffer = _aligned_malloc(test_size * sizeof(float), 64);
    out_buffer = _aligned_malloc(test_size * sizeof(float), 64);
    test_x = _aligned_malloc(test_size * sizeof(float), 64);
    #else
    posix_memalign((void**)&in_buffer, 64, test_size * sizeof(float));
    posix_memalign((void**)&out_buffer, 64, test_size * sizeof(float));
    posix_memalign((void**)&test_x, 64, test_size * sizeof(float));
    #endif
    
    if (!in_buffer || !out_buffer || !test_x) {
        printf("  FAILED: Memory allocation\n");
        return 1;
    }
    
    // Initialize test data
    srand(42);
    for (int i = 0; i < test_size; i++) {
        in_buffer[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
        test_x[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f;
    }
    
    printf("  Allocated %d elements (%.2f KB)\n", test_size, 
           (test_size * sizeof(float)) / 1024.0);
    printf("  Alignment: 64 bytes\n\n");
    
    // RMSNorm Benchmark
    printf("[3/5] Benchmarking RMSNorm...\n");
    double scalar_rms_time = benchmark_rms_norm(scalar_rms_norm, out_buffer, in_buffer, 
                                                  test_size, 1e-5f, iterations);
    double scalar_rms_tps = (iterations * test_size) / scalar_rms_time;
    
    printf("  Scalar RMSNorm:\n");
    printf("    Time: %.3f ms (%d iterations)\n", scalar_rms_time * 1000, iterations);
    printf("    Speed: %.2f million elements/sec\n", scalar_rms_tps / 1e6);
    
    if (has_avx512) {
        printf("  AVX-512 RMSNorm:\n");
        printf("    Status: IMPLEMENTATION PENDING\n");
        printf("    Expected: 8-16x speedup\n");
    }
    printf("\n");
    
    // Softmax Benchmark
    printf("[4/5] Benchmarking Softmax...\n");
    double scalar_softmax_time = benchmark_softmax(scalar_softmax, test_x, test_size, 
                                                    iterations / 10);
    double scalar_softmax_tps = ((iterations / 10) * test_size) / scalar_softmax_time;
    
    printf("  Scalar Softmax:\n");
    printf("    Time: %.3f ms (%d iterations)\n", scalar_softmax_time * 1000, iterations / 10);
    printf("    Speed: %.2f million elements/sec\n", scalar_softmax_tps / 1e6);
    
    if (has_avx512) {
        printf("  AVX-512 Softmax:\n");
        printf("    Status: IMPLEMENTATION PENDING\n");
        printf("    Expected: 4-8x speedup\n");
    }
    printf("\n");
    
    // MatMul Benchmark
    printf("[5/5] Benchmarking Matrix Multiplication...\n");
    int M = 128, N = 128, K = 128;
    float *A = NULL, *B = NULL, *C = NULL;
    double scalar_matmul_time = 0;
    double scalar_matmul_tps = 0;
    
    #ifdef _WIN32
    A = _aligned_malloc(M * K * sizeof(float), 64);
    B = _aligned_malloc(K * N * sizeof(float), 64);
    C = _aligned_malloc(M * N * sizeof(float), 64);
    #else
    posix_memalign((void**)&A, 64, M * K * sizeof(float));
    posix_memalign((void**)&B, 64, K * N * sizeof(float));
    posix_memalign((void**)&C, 64, M * N * sizeof(float));
    #endif
    
    if (A && B && C) {
        for (int i = 0; i < M * K; i++) A[i] = ((float)rand() / RAND_MAX - 0.5f);
        for (int i = 0; i < K * N; i++) B[i] = ((float)rand() / RAND_MAX - 0.5f);
        
        int matmul_iterations = 100;
        scalar_matmul_time = benchmark_matmul(scalar_matmul, A, B, C, M, N, K, 
                                                      matmul_iterations);
        scalar_matmul_tps = ((double)matmul_iterations * M * N * K) / scalar_matmul_time;
        
        printf("  Scalar MatMul (%dx%d x %dx%d):\n", M, K, K, N);
        printf("    Time: %.3f ms (%d iterations)\n", scalar_matmul_time * 1000, matmul_iterations);
        printf("    Speed: %.2f GFLOPS\n", scalar_matmul_tps / 1e9);
        
        if (has_avx512) {
            printf("  AVX-512 MatMul:\n");
            printf("    Status: IMPLEMENTATION PENDING\n");
            printf("    Expected: 4-16x speedup\n");
        }
    }
    
    #ifdef _WIN32
    _aligned_free(A);
    _aligned_free(B);
    _aligned_free(C);
    #else
    free(A);
    free(B);
    free(C);
    #endif
    
    printf("\n");
    
    // Summary
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  TRUTH GATE 009: RESULT                                    ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  AVX-512 Support: %-42s ║\n", has_avx512 ? "YES" : "NO");
    printf("║                                                            ║\n");
    printf("║  Scalar RMSNorm: %-43.2f Melem/s ║\n", scalar_rms_tps / 1e6);
    printf("║  Scalar Softmax: %-43.2f Melem/s ║\n", scalar_softmax_tps / 1e6);
    if (A && B && C) {
        printf("║  Scalar MatMul: %-44.2f GFLOPS ║\n", 
               ((double)(iterations / 10) * M * N * K) / scalar_matmul_time / 1e9);
    }
    printf("║                                                            ║\n");
    printf("║  AVX-512 Kernels: %-41s ║\n", "PENDING");
    printf("║  Target Speed: 10,000+ TPS                                 ║\n");
    printf("║                                                            ║\n");
    printf("║  Status: %-49s ║\n", has_avx512 ? "AVX-512 READY" : "SCALAR ONLY");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    if (has_avx512) {
        printf("\n✅ TRUTH GATE 009: AVX-512 DETECTED\n");
        printf("   CPU supports AVX-512F, AVX-512DQ, AVX-512BW\n");
        printf("   Ready for assembly kernel implementation\n");
        printf("   Target: 10,000+ TPS with optimized kernels\n");
    } else {
        printf("\n⚠️  TRUTH GATE 009: AVX-512 NOT AVAILABLE\n");
        printf("   Running on scalar fallback\n");
        printf("   Consider upgrading CPU for AVX-512 support\n");
    }
    
    // Cleanup
    #ifdef _WIN32
    _aligned_free(in_buffer);
    _aligned_free(out_buffer);
    _aligned_free(test_x);
    #else
    free(in_buffer);
    free(out_buffer);
    free(test_x);
    #endif
    
    return 0;
}
