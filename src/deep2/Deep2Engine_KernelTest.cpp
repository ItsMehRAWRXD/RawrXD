// ============================================================================
// Deep2Engine_KernelTest.cpp - Self-contained kernel validation
// Tests core Deep2Engine kernels without external dependencies
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <cstdint>
#include <immintrin.h>

// ============================================================================
// Kernel Implementations (from Deep2Engine.cpp)
// ============================================================================

// CPU feature detection - GCC/MSVC compatible
#if defined(__GNUC__)
#include <cpuid.h>
static void cpuid(int info[4], int function_id) {
    __cpuid_count(function_id, 0, info[0], info[1], info[2], info[3]);
}
#else
#define cpuid __cpuid
#endif

extern "C" int Deep2_HasAVX2() {
    int cpuInfo[4] = {0};
    cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 28))) return 0;
    cpuid(cpuInfo, 7);
    return (cpuInfo[1] & (1 << 5)) ? 1 : 0;
}

extern "C" int Deep2_HasAVX512() {
    int cpuInfo[4] = {0};
    cpuid(cpuInfo, 7);
    return (cpuInfo[1] & (1 << 16)) ? 1 : 0;
}

// Vector dot product
extern "C" void Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n) {
    if (n == 0) {
        *out = 0.0f;
        return;
    }
    
    __m256 sum_vec = _mm256_setzero_ps();
    size_t i = 0;
    
    for (; i + 8 <= n; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        sum_vec = _mm256_fmadd_ps(va, vb, sum_vec);
    }
    
    __m128 hi128 = _mm256_extractf128_ps(sum_vec, 1);
    __m128 lo128 = _mm256_castps256_ps128(sum_vec);
    __m128 sum128 = _mm_add_ps(lo128, hi128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    float sum = _mm_cvtss_f32(sum128);
    
    for (; i < n; ++i) {
        sum += a[i] * b[i];
    }
    
    *out = sum;
}

// SwiGLU activation
extern "C" void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n) {
    if (n == 0) return;
    
    const __m256 half = _mm256_set1_ps(0.5f);
    const __m256 one = _mm256_set1_ps(1.0f);
    
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        __m256 vx = _mm256_loadu_ps(x + i);
        __m256 vy = _mm256_loadu_ps(y + i);
        
        __m256 clamped = _mm256_max_ps(_mm256_set1_ps(-10.0f), 
                                       _mm256_min_ps(_mm256_set1_ps(10.0f), vy));
        
        __m256 half_y = _mm256_mul_ps(clamped, half);
        __m256 y2 = _mm256_mul_ps(half_y, half_y);
        __m256 tanh_approx = _mm256_mul_ps(half_y, 
            _mm256_fmadd_ps(y2, _mm256_set1_ps(-0.3333333f), one));
        tanh_approx = _mm256_fmadd_ps(_mm256_mul_ps(y2, y2), _mm256_set1_ps(0.1333333f), tanh_approx);
        __m256 sigmoid = _mm256_fmadd_ps(tanh_approx, half, half);
        
        __m256 result = _mm256_mul_ps(vx, _mm256_mul_ps(sigmoid, vy));
        _mm256_storeu_ps(out + i, result);
    }
    
    for (; i < n; ++i) {
        float sig = 1.0f / (1.0f + std::exp(-y[i]));
        out[i] = x[i] * sig * y[i];
    }
}

// RMSNorm
extern "C" void Deep2_RMSNorm(const float* x, float* out, size_t n, float eps) {
    if (n == 0) return;
    
    __m256 sum_vec = _mm256_setzero_ps();
    size_t i = 0;
    
    for (; i + 8 <= n; i += 8) {
        __m256 vx = _mm256_loadu_ps(x + i);
        sum_vec = _mm256_fmadd_ps(vx, vx, sum_vec);
    }
    
    __m128 hi = _mm256_extractf128_ps(sum_vec, 1);
    __m128 lo = _mm256_castps256_ps128(sum_vec);
    __m128 sum128 = _mm_add_ps(lo, hi);
    sum128 = _mm_hadd_ps(sum128, sum128);
    sum128 = _mm_hadd_ps(sum128, sum128);
    float sum = _mm_cvtss_f32(sum128);
    
    for (; i < n; ++i) {
        sum += x[i] * x[i];
    }
    
    float meanSq = sum / n;
    float rms = std::sqrt(meanSq + eps);
    __m256 scale_vec = _mm256_set1_ps(1.0f / rms);
    
    i = 0;
    for (; i + 8 <= n; i += 8) {
        __m256 vx = _mm256_loadu_ps(x + i);
        __m256 result = _mm256_mul_ps(vx, scale_vec);
        _mm256_storeu_ps(out + i, result);
    }
    
    float scale = 1.0f / rms;
    for (; i < n; ++i) {
        out[i] = x[i] * scale;
    }
}

// ============================================================================
// Test Framework
// ============================================================================
struct TestResult {
    const char* name;
    bool passed;
    double durationMs;
    const char* error;
};

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        result.error = msg; \
        result.passed = false; \
        printf("  [FAIL] %s\n", msg); \
        return result; \
    } \
} while(0)

// ============================================================================
// Test 1: CPU Feature Detection
// ============================================================================
TestResult Test_CPUFeatures() {
    TestResult result{"CPUFeatures", true, 0.0, nullptr};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] CPU Feature Detection\n");
    
    int hasAVX2 = Deep2_HasAVX2();
    int hasAVX512 = Deep2_HasAVX512();
    
    printf("  AVX2: %s\n", hasAVX2 ? "YES" : "NO");
    printf("  AVX-512: %s\n", hasAVX512 ? "YES" : "NO");
    
    TEST_ASSERT(hasAVX2 || hasAVX512, "No AVX2 or AVX-512 detected - modern CPU required");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] CPU feature detection in %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// Test 2: Vector Dot Product
// ============================================================================
TestResult Test_VecDotProduct() {
    TestResult result{"VecDotProduct", true, 0.0, nullptr};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] Vector Dot Product\n");
    
    alignas(32) float a[64];
    alignas(32) float b[64];
    
    for (int i = 0; i < 64; i++) {
        a[i] = (float)i * 0.01f;
        b[i] = (float)(63 - i) * 0.01f;
    }
    
    float result_val = 0.0f;
    Deep2_VecDotProduct(a, b, &result_val, 64);
    
    float expected = 0.0f;
    for (int i = 0; i < 64; i++) {
        expected += a[i] * b[i];
    }
    
    printf("  Result: %.6f, Expected: %.6f\n", result_val, expected);
    TEST_ASSERT(std::abs(result_val - expected) < 0.001f, "Dot product result mismatch");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] VecDotProduct in %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// Test 3: SwiGLU Activation
// ============================================================================
TestResult Test_SwiGLU() {
    TestResult result{"SwiGLU", true, 0.0, nullptr};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] SwiGLU Activation\n");
    
    alignas(32) float gate[64];
    alignas(32) float up[64];
    alignas(32) float out[64];
    
    for (int i = 0; i < 64; i++) {
        gate[i] = (float)i * 0.1f;
        up[i] = (float)(i % 10) * 0.1f;
    }
    
    Deep2_SwiGLU(gate, up, out, 64);
    
    bool hasNonZero = false;
    for (int i = 0; i < 64; i++) {
        if (!std::isfinite(out[i])) {
            TEST_ASSERT(false, "SwiGLU produced non-finite value");
        }
        if (out[i] != 0.0f) {
            hasNonZero = true;
        }
    }
    TEST_ASSERT(hasNonZero, "SwiGLU produced all zeros");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] SwiGLU in %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// Test 4: RMSNorm
// ============================================================================
TestResult Test_RMSNorm() {
    TestResult result{"RMSNorm", true, 0.0, nullptr};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] RMSNorm\n");
    
    alignas(32) float input[64];
    alignas(32) float output[64];
    
    for (int i = 0; i < 64; i++) {
        input[i] = 1.0f;
    }
    
    Deep2_RMSNorm(input, output, 64, 1e-6f);
    
    for (int i = 0; i < 64; i++) {
        if (!std::isfinite(output[i])) {
            TEST_ASSERT(false, "RMSNorm produced non-finite value");
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] RMSNorm in %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// Test 5: Memory Alignment
// ============================================================================
TestResult Test_MemoryAlignment() {
    TestResult result{"MemoryAlignment", true, 0.0, nullptr};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] Memory Alignment\n");
    
    #ifdef _WIN32
        float* aligned = (float*)_aligned_malloc(256 * sizeof(float), 32);
    #else
        float* aligned = (float*)aligned_alloc(32, 256 * sizeof(float));
    #endif
    
    TEST_ASSERT(aligned != nullptr, "Aligned allocation failed");
    TEST_ASSERT(reinterpret_cast<uintptr_t>(aligned) % 32 == 0, "Memory not 32-byte aligned");
    
    for (int i = 0; i < 256; i++) {
        aligned[i] = (float)i;
    }
    
    for (int i = 0; i < 256; i++) {
        TEST_ASSERT(aligned[i] == (float)i, "Memory read/write failed");
    }
    
    #ifdef _WIN32
        _aligned_free(aligned);
    #else
        free(aligned);
    #endif
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] Memory alignment in %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// Test 6: Kernel Performance Benchmark
// ============================================================================
TestResult Test_KernelBenchmark() {
    TestResult result{"KernelBenchmark", true, 0.0, nullptr};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] Kernel Performance Benchmark\n");
    
    const int iterations = 1000;
    const int size = 4096;
    
    float* a = (float*)_aligned_malloc(size * sizeof(float), 32);
    float* b = (float*)_aligned_malloc(size * sizeof(float), 32);
    float dot_result = 0.0f;
    
    for (int i = 0; i < size; i++) {
        a[i] = (float)(i % 100) * 0.01f;
        b[i] = (float)((size - i) % 100) * 0.01f;
    }
    
    auto bench_start = std::chrono::high_resolution_clock::now();
    
    for (int iter = 0; iter < iterations; iter++) {
        Deep2_VecDotProduct(a, b, &dot_result, size);
    }
    
    auto bench_end = std::chrono::high_resolution_clock::now();
    double bench_ms = std::chrono::duration<double, std::milli>(bench_end - bench_start).count();
    
    double ops_per_sec = (double)iterations * size / (bench_ms / 1000.0);
    double gflops = ops_per_sec / 1e9;
    
    printf("  %d iterations of %d-element dot product\n", iterations, size);
    printf("  Total time: %.2f ms\n", bench_ms);
    printf("  Throughput: %.2f GFLOPS\n", gflops);
    
    _aligned_free(a);
    _aligned_free(b);
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] Kernel benchmark in %.2f ms\n", result.durationMs);
    return result;
}

// ============================================================================
// Test Runner
// ============================================================================
using TestFunc = TestResult(*)();

struct TestSuite {
    const char* category;
    TestFunc func;
};

static const TestSuite g_testSuite[] = {
    {"CORE", Test_CPUFeatures},
    {"CORE", Test_VecDotProduct},
    {"CORE", Test_SwiGLU},
    {"CORE", Test_RMSNorm},
    {"CORE", Test_MemoryAlignment},
    {"PERF", Test_KernelBenchmark},
};

int RunAllSmokeTests() {
    printf("\n");
    printf("================================================================================\n");
    printf("  Deep2Engine Kernel Smoketest\n");
    printf("  Testing: Core kernel functionality (self-contained)\n");
    printf("================================================================================\n");
    
    g_testsPassed = 0;
    g_testsFailed = 0;
    
    const size_t numTests = sizeof(g_testSuite) / sizeof(g_testSuite[0]);
    printf("\nRunning %zu tests...\n\n", numTests);
    
    const char* currentCategory = "";
    double totalTime = 0.0;
    
    for (size_t i = 0; i < numTests; i++) {
        if (strcmp(g_testSuite[i].category, currentCategory) != 0) {
            currentCategory = g_testSuite[i].category;
            printf("\n[%s TESTS]\n", currentCategory);
        }
        
        TestResult result = g_testSuite[i].func();
        totalTime += result.durationMs;
        
        if (result.passed) {
            g_testsPassed++;
        } else {
            g_testsFailed++;
            printf("  *** TEST FAILED: %s - %s\n", result.name, result.error);
        }
    }
    
    printf("\n");
    printf("================================================================================\n");
    printf("  TEST SUMMARY\n");
    printf("================================================================================\n");
    printf("  Total tests:  %zu\n", numTests);
    printf("  Passed:       %d\n", g_testsPassed);
    printf("  Failed:       %d\n", g_testsFailed);
    printf("  Success rate: %.1f%%\n", (100.0 * g_testsPassed) / numTests);
    printf("  Total time:   %.2f ms\n", totalTime);
    printf("================================================================================\n");
    
    if (g_testsFailed == 0) {
        printf("  ALL TESTS PASSED - Core kernels operational\n");
    } else {
        printf("  SOME TESTS FAILED - Review errors above\n");
    }
    printf("================================================================================\n");
    printf("\n");
    
    return g_testsFailed == 0 ? 0 : 1;
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("Deep2Engine Kernel Smoketest\n");
    printf("Build: %s %s\n\n", __DATE__, __TIME__);
    
    return RunAllSmokeTests();
}
