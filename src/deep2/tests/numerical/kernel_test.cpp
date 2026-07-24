// ============================================================================
// Kernel Numerical Validation Tests
// Compares Deep2 kernels against reference implementations
// ============================================================================

#include <cstdio>
#include <cmath>
#include <vector>
#include <random>
#include <immintrin.h>

// Reference implementations (scalar, naive)
namespace Reference {
    float vecDotProduct(const float* a, const float* b, size_t n) {
        float sum = 0.0f;
        for (size_t i = 0; i < n; ++i) sum += a[i] * b[i];
        return sum;
    }
    
    void swiGLU(const float* gate, const float* up, float* out, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            float sig = 1.0f / (1.0f + std::exp(-gate[i]));
            out[i] = gate[i] * sig * up[i];
        }
    }
    
    void rmsNorm(const float* x, float* out, size_t n, float eps) {
        float sumSq = 0.0f;
        for (size_t i = 0; i < n; ++i) sumSq += x[i] * x[i];
        float scale = 1.0f / std::sqrt(sumSq / n + eps);
        for (size_t i = 0; i < n; ++i) out[i] = x[i] * scale;
    }
    
    void fp32GEMV(const float* weights, const float* input,
                  float* output, size_t rows, size_t cols) {
        for (size_t r = 0; r < rows; ++r) {
            float sum = 0.0f;
            for (size_t c = 0; c < cols; ++c) {
                sum += weights[r * cols + c] * input[c];
            }
            output[r] = sum;
        }
    }
}

// Test utilities
struct TestResult {
    const char* name;
    bool passed;
    float maxError;
    float meanError;
    double timeRef;  // ms
    double timeOpt;  // ms
};

// Generate random data
void generateRandomData(std::vector<float>& data, size_t n, unsigned seed) {
    std::mt19937 gen(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (size_t i = 0; i < n; ++i) data[i] = dist(gen);
}

// Compare arrays
void compareArrays(const float* ref, const float* opt, size_t n,
                   float& maxError, float& meanError) {
    maxError = 0.0f;
    meanError = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        float err = std::abs(ref[i] - opt[i]);
        maxError = std::max(maxError, err);
        meanError += err;
    }
    meanError /= n;
}

// Timing helper
#include <chrono>
template<typename Func>
double measureTime(Func f, int iterations = 100) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) f();
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count() / iterations;
}

// ============================================================================
// Test: Vector Dot Product
// ============================================================================
TestResult testVecDotProduct() {
    const size_t N = 4096;
    std::vector<float> a(N), b(N);
    generateRandomData(a, N, 42);
    generateRandomData(b, N, 43);
    
    float refResult, optResult;
    
    // Reference
    auto timeRef = measureTime([&]() {
        refResult = Reference::vecDotProduct(a.data(), b.data(), N);
    });
    
    // Optimized (Deep2)
    auto timeOpt = measureTime([&]() {
        extern void Deep2_VecDotProduct(const float*, const float*, float*, size_t);
        Deep2_VecDotProduct(a.data(), b.data(), &optResult, N);
    });
    
    float maxError = std::abs(refResult - optResult);
    
    return {
        "VecDotProduct (4096)",
        maxError < 1e-4f,
        maxError,
        maxError,  // mean same as max for scalar
        timeRef,
        timeOpt
    };
}

// ============================================================================
// Test: SwiGLU
// ============================================================================
TestResult testSwiGLU() {
    const size_t N = 11008;  // Typical intermediate dim
    std::vector<float> gate(N), up(N), refOut(N), optOut(N);
    generateRandomData(gate, N, 44);
    generateRandomData(up, N, 45);
    
    // Reference
    auto timeRef = measureTime([&]() {
        Reference::swiGLU(gate.data(), up.data(), refOut.data(), N);
    });
    
    // Optimized
    auto timeOpt = measureTime([&]() {
        extern void Deep2_SwiGLU(const float*, const float*, float*, size_t);
        Deep2_SwiGLU(gate.data(), up.data(), optOut.data(), N);
    });
    
    float maxError, meanError;
    compareArrays(refOut.data(), optOut.data(), N, maxError, meanError);
    
    // Note: Fast sigmoid approximation has higher error tolerance
    return {
        "SwiGLU (11008)",
        maxError < 0.01f,  // Approximate sigmoid tolerance
        maxError,
        meanError,
        timeRef,
        timeOpt
    };
}

// ============================================================================
// Test: RMSNorm
// ============================================================================
TestResult testRMSNorm() {
    const size_t N = 4096;
    std::vector<float> input(N), refOut(N), optOut(N);
    generateRandomData(input, N, 46);
    const float eps = 1e-6f;
    
    // Reference
    auto timeRef = measureTime([&]() {
        Reference::rmsNorm(input.data(), refOut.data(), N, eps);
    });
    
    // Optimized
    auto timeOpt = measureTime([&]() {
        extern void Deep2_RMSNorm(const float*, float*, size_t, float);
        Deep2_RMSNorm(input.data(), optOut.data(), N, eps);
    });
    
    float maxError, meanError;
    compareArrays(refOut.data(), optOut.data(), N, maxError, meanError);
    
    return {
        "RMSNorm (4096)",
        maxError < 1e-5f,
        maxError,
        meanError,
        timeRef,
        timeOpt
    };
}

// ============================================================================
// Test: FP32 GEMV
// ============================================================================
TestResult testFP32GEMV() {
    const size_t ROWS = 4096;
    const size_t COLS = 4096;
    std::vector<float> weights(ROWS * COLS), input(COLS), refOut(ROWS), optOut(ROWS);
    generateRandomData(weights, ROWS * COLS, 47);
    generateRandomData(input, COLS, 48);
    
    // Reference
    auto timeRef = measureTime([&]() {
        Reference::fp32GEMV(weights.data(), input.data(), refOut.data(), ROWS, COLS);
    });
    
    // Optimized (from Deep2Engine.cpp)
    auto timeOpt = measureTime([&]() {
        // fp32GEMV is static, need to expose or duplicate
        // For now, use Deep2_VecDotProduct per row
        for (size_t r = 0; r < ROWS; ++r) {
            extern void Deep2_VecDotProduct(const float*, const float*, float*, size_t);
            Deep2_VecDotProduct(&weights[r * COLS], input.data(), &optOut[r], COLS);
        }
    });
    
    float maxError, meanError;
    compareArrays(refOut.data(), optOut.data(), ROWS, maxError, meanError);
    
    return {
        "FP32 GEMV (4096x4096)",
        maxError < 1e-4f,
        maxError,
        meanError,
        timeRef,
        timeOpt
    };
}

// ============================================================================
// Main Test Runner
// ============================================================================
int main() {
    printf("=================================================================\n");
    printf("Deep2Engine Kernel Numerical Validation\n");
    printf("=================================================================\n\n");
    
    std::vector<TestResult> results;
    results.push_back(testVecDotProduct());
    results.push_back(testSwiGLU());
    results.push_back(testRMSNorm());
    results.push_back(testFP32GEMV());
    
    // Print results table
    printf("%-25s %8s %12s %12s %10s %10s\n",
           "Test", "Status", "Max Error", "Mean Error", "Ref(ms)", "Opt(ms)");
    printf("-----------------------------------------------------------------\n");
    
    int passed = 0, failed = 0;
    for (const auto& r : results) {
        printf("%-25s %8s %12.6f %12.6f %10.3f %10.3f\n",
               r.name,
               r.passed ? "PASS" : "FAIL",
               r.maxError,
               r.meanError,
               r.timeRef,
               r.timeOpt);
        
        if (r.passed) passed++; else failed++;
        
        // Speedup
        if (r.timeRef > 0 && r.timeOpt > 0) {
            double speedup = r.timeRef / r.timeOpt;
            printf("  -> Speedup: %.2fx\n", speedup);
        }
    }
    
    printf("-----------------------------------------------------------------\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    printf("=================================================================\n");
    
    return failed > 0 ? 1 : 0;
}
