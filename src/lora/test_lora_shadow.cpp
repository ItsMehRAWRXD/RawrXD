/**
 * @file test_lora_shadow.cpp
 * @brief Phase 21: Build-Time LoRA Kernel Validation (Shadow Test)
 * 
 * This test runs during the build process to validate that the MASM-optimized
 * LoRA kernels are functioning correctly. It performs a shadow run comparing
 * C++ reference implementation against ASM optimized kernels.
 * 
 * Exit codes:
 *   0 - All tests passed
 *   1 - Kernel validation failed
 *   2 - Performance regression detected
 *   3 - Memory allocation error
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>
#include <random>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// Test configuration
constexpr size_t TEST_VECTOR_SIZE = 1048576;  // 1M elements
constexpr size_t RANK = 8;
constexpr double PERFORMANCE_THRESHOLD = 0.8;  // ASM must be at least 80% of C++ perf
constexpr int NUM_WARMUP = 10;
constexpr int NUM_ITERATIONS = 100;

// Feature detection
struct CPUFeatures {
    bool hasAVX512F = false;
    bool hasAVX512VL = false;
    bool hasAVX512BW = false;
    bool hasAVX2 = false;
    bool hasFMA = false;
};

CPUFeatures detectCPUFeatures() {
    CPUFeatures features;
    int cpuInfo[4] = {0};
    
#ifdef _WIN32
    __cpuid(cpuInfo, 1);
    features.hasAVX2 = (cpuInfo[2] & (1 << 5)) != 0;  // ECX bit 5
    features.hasFMA = (cpuInfo[2] & (1 << 12)) != 0;  // ECX bit 12
    
    __cpuid(cpuInfo, 7);
    features.hasAVX512F = (cpuInfo[1] & (1 << 16)) != 0;  // EBX bit 16
    features.hasAVX512VL = (cpuInfo[1] & (1 << 31)) != 0;  // EBX bit 31
    features.hasAVX512BW = (cpuInfo[1] & (1 << 30)) != 0;  // EBX bit 30
#else
    __cpuid(1, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    features.hasAVX2 = (cpuInfo[2] & (1 << 5)) != 0;
    features.hasFMA = (cpuInfo[2] & (1 << 12)) != 0;
    
    __cpuid_count(7, 0, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    features.hasAVX512F = (cpuInfo[1] & (1 << 16)) != 0;
    features.hasAVX512VL = (cpuInfo[1] & (1 << 31)) != 0;
    features.hasAVX512BW = (cpuInfo[1] & (1 << 30)) != 0;
#endif
    
    return features;
}

// C++ reference implementation of LoRA application
void applyLoRA_Reference(
    float* output,
    const float* input,
    const float* loraA,
    const float* loraB,
    float alpha,
    size_t n,
    size_t rank
) {
    // output = input + alpha * (input @ loraA) @ loraB
    std::vector<float> intermediate(n * rank);
    
    // First matmul: input @ loraA
    for (size_t i = 0; i < n; ++i) {
        for (size_t r = 0; r < rank; ++r) {
            float sum = 0.0f;
            for (size_t k = 0; k < n; ++k) {
                sum += input[i * n + k] * loraA[k * rank + r];
            }
            intermediate[i * rank + r] = sum;
        }
    }
    
    // Second matmul: intermediate @ loraB
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            float sum = 0.0f;
            for (size_t r = 0; r < rank; ++r) {
                sum += intermediate[i * rank + r] * loraB[r * n + j];
            }
            output[i * n + j] = input[i * n + j] + alpha * sum;
        }
    }
}

// Forward declarations for ASM kernels (extern "C" linkage)
extern "C" {
    // Optimized kernel with AVX-512
    void ApplyLoRA_Optimized(
        float* output,
        const float* input,
        const float* loraA,
        const float* loraB,
        float alpha,
        size_t n,
        size_t rank
    );
    
    // Standard kernel
    void ApplyLoRA(
        float* output,
        const float* input,
        const float* loraA,
        const float* loraB,
        float alpha,
        size_t n,
        size_t rank
    );
}

// Test result structure
struct TestResult {
    bool passed = false;
    double cppTimeMs = 0.0;
    double asmTimeMs = 0.0;
    double speedup = 0.0;
    float maxError = 0.0f;
    const char* errorMessage = nullptr;
};

// Validation test
TestResult runValidationTest() {
    TestResult result;
    
    printf("[Phase 21] LoRA Kernel Validation Test\n");
    printf("  Vector size: %zu\n", TEST_VECTOR_SIZE);
    printf("  Rank: %zu\n", RANK);
    printf("  Iterations: %d\n", NUM_ITERATIONS);
    
    // Allocate aligned memory
    float* input = nullptr;
    float* loraA = nullptr;
    float* loraB = nullptr;
    float* outputCpp = nullptr;
    float* outputAsm = nullptr;
    
#ifdef _WIN32
    input = (float*)_aligned_malloc(TEST_VECTOR_SIZE * sizeof(float), 64);
    loraA = (float*)_aligned_malloc(TEST_VECTOR_SIZE * RANK * sizeof(float), 64);
    loraB = (float*)_aligned_malloc(RANK * TEST_VECTOR_SIZE * sizeof(float), 64);
    outputCpp = (float*)_aligned_malloc(TEST_VECTOR_SIZE * sizeof(float), 64);
    outputAsm = (float*)_aligned_malloc(TEST_VECTOR_SIZE * sizeof(float), 64);
#else
    posix_memalign((void**)&input, 64, TEST_VECTOR_SIZE * sizeof(float));
    posix_memalign((void**)&loraA, 64, TEST_VECTOR_SIZE * RANK * sizeof(float));
    posix_memalign((void**)&loraB, 64, RANK * TEST_VECTOR_SIZE * sizeof(float));
    posix_memalign((void**)&outputCpp, 64, TEST_VECTOR_SIZE * sizeof(float));
    posix_memalign((void**)&outputAsm, 64, TEST_VECTOR_SIZE * sizeof(float));
#endif
    
    if (!input || !loraA || !loraB || !outputCpp || !outputAsm) {
        result.errorMessage = "Memory allocation failed";
        return result;
    }
    
    // Initialize with random data
    std::mt19937 rng(42);  // Fixed seed for reproducibility
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (size_t i = 0; i < TEST_VECTOR_SIZE; ++i) {
        input[i] = dist(rng);
    }
    for (size_t i = 0; i < TEST_VECTOR_SIZE * RANK; ++i) {
        loraA[i] = dist(rng) * 0.01f;  // Small values for stability
    }
    for (size_t i = 0; i < RANK * TEST_VECTOR_SIZE; ++i) {
        loraB[i] = dist(rng) * 0.01f;
    }
    
    float alpha = 0.5f;
    
    // Run C++ reference
    printf("  Running C++ reference...\n");
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_WARMUP; ++i) {
        applyLoRA_Reference(outputCpp, input, loraA, loraB, alpha, 
                           TEST_VECTOR_SIZE, RANK);
    }
    auto end = std::chrono::high_resolution_clock::now();
    result.cppTimeMs = std::chrono::duration<double, std::milli>(end - start).count() / NUM_WARMUP;
    
    // Run ASM kernel
    printf("  Running ASM kernel...\n");
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_WARMUP; ++i) {
        ApplyLoRA_Optimized(outputAsm, input, loraA, loraB, alpha,
                           TEST_VECTOR_SIZE, RANK);
    }
    end = std::chrono::high_resolution_clock::now();
    result.asmTimeMs = std::chrono::duration<double, std::milli>(end - start).count() / NUM_WARMUP;
    
    // Compare results
    result.maxError = 0.0f;
    for (size_t i = 0; i < TEST_VECTOR_SIZE; ++i) {
        float error = std::abs(outputCpp[i] - outputAsm[i]);
        if (error > result.maxError) {
            result.maxError = error;
        }
    }
    
    // Calculate speedup
    result.speedup = result.cppTimeMs / result.asmTimeMs;
    
    // Validation criteria
    const float ERROR_THRESHOLD = 1e-4f;
    bool accuracyPassed = result.maxError < ERROR_THRESHOLD;
    bool performancePassed = result.speedup >= PERFORMANCE_THRESHOLD;
    
    printf("\n  Results:\n");
    printf("    C++ time: %.3f ms\n", result.cppTimeMs);
    printf("    ASM time: %.3f ms\n", result.asmTimeMs);
    printf("    Speedup: %.2fx\n", result.speedup);
    printf("    Max error: %.6e\n", result.maxError);
    printf("    Accuracy: %s\n", accuracyPassed ? "PASS" : "FAIL");
    printf("    Performance: %s\n", performancePassed ? "PASS" : "FAIL");
    
    result.passed = accuracyPassed && performancePassed;
    
    if (!accuracyPassed) {
        result.errorMessage = "Accuracy validation failed";
    } else if (!performancePassed) {
        result.errorMessage = "Performance regression detected";
    }
    
    // Cleanup
#ifdef _WIN32
    _aligned_free(input);
    _aligned_free(loraA);
    _aligned_free(loraB);
    _aligned_free(outputCpp);
    _aligned_free(outputAsm);
#else
    free(input);
    free(loraA);
    free(loraB);
    free(outputCpp);
    free(outputAsm);
#endif
    
    return result;
}

// Feature test
bool runFeatureTest() {
    printf("\n[Phase 21] CPU Feature Detection\n");
    
    CPUFeatures features = detectCPUFeatures();
    
    printf("  AVX2: %s\n", features.hasAVX2 ? "YES" : "NO");
    printf("  FMA: %s\n", features.hasFMA ? "YES" : "NO");
    printf("  AVX-512F: %s\n", features.hasAVX512F ? "YES" : "NO");
    printf("  AVX-512VL: %s\n", features.hasAVX512VL ? "YES" : "NO");
    printf("  AVX-512BW: %s\n", features.hasAVX512BW ? "YES" : "NO");
    
    // For optimal performance, we want AVX-512
    if (!features.hasAVX512F) {
        printf("  WARNING: AVX-512 not detected. Performance may be reduced.\n");
    }
    
    return features.hasAVX2;  // Minimum requirement
}

int main(int argc, char* argv[]) {
    printf("=" &#8203;``【oaicite:0】``&#8203;60);
    printf("RawrXD Phase 21: LoRA Kernel Shadow Validation\n");
    printf("=" &#8203;``【oaicite:1】``&#8203;60);
    
    // Check for skip flag
    if (argc > 1 && strcmp(argv[1], "--skip-validation") == 0) {
        printf("Validation skipped (--skip-validation flag)\n");
        return 0;
    }
    
    // Feature detection
    if (!runFeatureTest()) {
        printf("\nERROR: Minimum CPU features not available (AVX2 required)\n");
        return 3;
    }
    
    // Run validation
    TestResult result = runValidationTest();
    
    printf("\n");
    printf("=" &#8203;``【oaicite:2】``&#8203;60);
    if (result.passed) {
        printf("VALIDATION PASSED\n");
        printf("=" &#8203;``【oaicite:3】``&#8203;60);
        printf("LoRA kernels are ready for production deployment.\n");
        return 0;
    } else {
        printf("VALIDATION FAILED\n");
        printf("=" &#8203;``【oaicite:4】``&#8203;60);
        if (result.errorMessage) {
            printf("Error: %s\n", result.errorMessage);
        }
        return 1;
    }
}
