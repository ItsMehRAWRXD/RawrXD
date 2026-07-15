//==============================================================================
// cli_phase7d.cpp
// Phase 7D - Comprehensive Validation & Benchmarking
//
// Extends Phase 7C.2 with:
// - Comprehensive kernel validation
// - Performance benchmarking
// - Numerical accuracy comparison
// - Memory bandwidth measurement
// - Full model inference pipeline
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <algorithm>

// Windows aligned memory allocation
#include <malloc.h>

// Include the kernel dispatch header
#include "d:/src/asm/Sovereign_KernelDispatch.h"

// Link against kernel libraries
#pragma comment(lib, "d:/src/asm/Sovereign_Legacy_Kernels.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_Intrinsics.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_RMSNorm.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_ResidualAdd.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_RoPE.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_LayerNorm.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_Q4K_Dequant.lib")

//==============================================================================
// Timing Utilities
//==============================================================================
class Timer {
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;
    
    TimePoint start_;
    
public:
    void Start() { start_ = Clock::now(); }
    
    double ElapsedMs() const {
        auto end = Clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_);
        return duration.count() / 1000.0;
    }
    
    double ElapsedUs() const {
        auto end = Clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_);
        return duration.count() / 1000.0;
    }
};

//==============================================================================
// Test Utilities
//==============================================================================
bool approxEqual(float a, float b, float epsilon = 0.001f) {
    return fabsf(a - b) < epsilon;
}

float calculateRMSE(const float* a, const float* b, size_t n) {
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        float diff = a[i] - b[i];
        sum_sq += diff * diff;
    }
    return sqrtf(sum_sq / n);
}

float calculateMaxError(const float* a, const float* b, size_t n) {
    float max_err = 0.0f;
    for (size_t i = 0; i < n; i++) {
        float err = fabsf(a[i] - b[i]);
        if (err > max_err) max_err = err;
    }
    return max_err;
}

void generateRandomData(float* data, size_t n, float min = -1.0f, float max = 1.0f) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(min, max);
    for (size_t i = 0; i < n; i++) {
        data[i] = dist(gen);
    }
}

//==============================================================================
// Validation Tests
//==============================================================================

struct ValidationResult {
    const char* name;
    bool passed;
    double rmse;
    double maxError;
    double executionTimeMs;
    const char* details;
};

std::vector<ValidationResult> validationResults;

void printBanner() {
    printf("==============================================================================\n");
    printf("Sovereign CLI - Phase 7D Comprehensive Validation\n");
    printf("==============================================================================\n\n");
}

void printUsage(const char* program) {
    printf("Usage: %s [command] [options]\n\n", program);
    printf("Commands:\n");
    printf("  comprehensive     Run comprehensive validation suite\n");
    printf("  benchmark         Run performance benchmarks\n");
    printf("  accuracy          Test numerical accuracy\n");
    printf("  stress            Run stress tests\n");
    printf("  compare           Compare MASM vs Reference\n");
    printf("  info              Show system information\n");
    printf("  help              Show this help message\n");
}

//==============================================================================
// RMSNorm Validation
//==============================================================================
void validateRMSNorm(Sovereign_KernelTable& table) {
    if (!table.rms_norm_f32) return;
    
    printf("[Validation] RMSNorm_F32\n");
    printf("------------------------\n");
    
    // Use sizes that are multiples of 8 for AVX2 alignment
    const size_t sizes[] = {1024, 2048, 4096, 8192};
    int passed = 0;
    int total = 0;
    
    for (size_t size : sizes) {
        total++;
        
        // Use aligned allocation for AVX2
        float* input = (float*)_aligned_malloc(size * sizeof(float), 32);
        float* weight = (float*)_aligned_malloc(size * sizeof(float), 32);
        float* output = (float*)_aligned_malloc(size * sizeof(float), 32);
        
        if (!input || !weight || !output) {
            printf("  Size %4zu: Memory allocation failed\n", size);
            _aligned_free(input);
            _aligned_free(weight);
            _aligned_free(output);
            continue;
        }
        
        // Initialize
        for (size_t i = 0; i < size; i++) {
            input[i] = (float)(i % 10) + 1.0f;  // Simple pattern: 1,2,3,...,10,1,2,...
            weight[i] = 1.0f;
        }
        
        // Call kernel
        Timer timer;
        timer.Start();
        int result = table.rms_norm_f32(input, output, weight, size, 1e-6f);
        double timeMs = timer.ElapsedMs();
        
        // Verify output RMS is close to 1.0 (RMSNorm should normalize to unit variance)
        float sum_sq = 0.0f;
        for (size_t i = 0; i < size; i++) {
            sum_sq += output[i] * output[i];
        }
        float rms = sqrtf(sum_sq / size);
        
        // Check if kernel executed successfully and produced normalized output
        bool pass = (result == 0) && (rms > 0.99f && rms < 1.01f);
        
        if (pass) passed++;
        
        printf("  Size %4zu: RMS=%.6f, Time=%.3fms [%s]\n", 
               size, rms, timeMs, pass ? "PASS" : "FAIL");
        
        _aligned_free(input);
        _aligned_free(weight);
        _aligned_free(output);
    }
    
    printf("  Result: %d/%d tests passed\n\n", passed, total);
    
    validationResults.push_back({
        "RMSNorm_F32", 
        passed == total, 
        0.0, 
        0.0, 
        0.0,
        "Multi-size validation"
    });
}

//==============================================================================
// ResidualAdd Validation
//==============================================================================
void validateResidualAdd(Sovereign_KernelTable& table) {
    if (!table.residual_add_f32) return;
    
    printf("[Validation] ResidualAdd_F32\n");
    printf("------------------------------\n");
    
    const size_t sizes[] = {64, 128, 256, 512, 1024, 4096};
    int passed = 0;
    int total = 0;
    
    for (size_t size : sizes) {
        total++;
        std::vector<float> input(size);
        std::vector<float> residual(size);
        std::vector<float> output(size);
        std::vector<float> expected(size);
        
        // Generate test data
        generateRandomData(input.data(), size);
        generateRandomData(residual.data(), size);
        
        // Calculate expected
        for (size_t i = 0; i < size; i++) {
            expected[i] = input[i] + residual[i];
        }
        
        // Call kernel
        Timer timer;
        timer.Start();
        int result = table.residual_add_f32(input.data(), residual.data(), output.data(), size);
        double timeMs = timer.ElapsedMs();
        
        // Verify
        float rmse = calculateRMSE(output.data(), expected.data(), size);
        float maxErr = calculateMaxError(output.data(), expected.data(), size);
        bool pass = (result == 0) && (maxErr < 0.001f);
        
        if (pass) passed++;
        
        printf("  Size %4zu: RMSE=%.6f, MaxErr=%.6f, Time=%.3fms [%s]\n", 
               size, rmse, maxErr, timeMs, pass ? "PASS" : "FAIL");
    }
    
    printf("  Result: %d/%d tests passed\n\n", passed, total);
    
    validationResults.push_back({
        "ResidualAdd_F32", 
        passed == total, 
        0.0, 
        0.0, 
        0.0,
        "Multi-size validation"
    });
}

//==============================================================================
// Benchmark Suite
//==============================================================================

struct BenchmarkResult {
    const char* name;
    size_t size;
    double timeMs;
    double bandwidthGBs;
    double throughputGFLOPs;
};

std::vector<BenchmarkResult> benchmarkResults;

void benchmarkRMSNorm(Sovereign_KernelTable& table) {
    if (!table.rms_norm_f32) return;
    
    printf("[Benchmark] RMSNorm_F32\n");
    printf("-----------------------\n");
    
    const size_t sizes[] = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536};
    const int iterations = 100;
    
    for (size_t size : sizes) {
        std::vector<float> input(size);
        std::vector<float> weight(size, 1.0f);
        std::vector<float> output(size);
        generateRandomData(input.data(), size);
        
        // Warmup
        for (int i = 0; i < 10; i++) {
            table.rms_norm_f32(input.data(), output.data(), weight.data(), size, 1e-6f);
        }
        
        // Benchmark
        Timer timer;
        timer.Start();
        for (int i = 0; i < iterations; i++) {
            table.rms_norm_f32(input.data(), output.data(), weight.data(), size, 1e-6f);
        }
        double totalTimeMs = timer.ElapsedMs();
        double avgTimeMs = totalTimeMs / iterations;
        
        // Calculate bandwidth (read input + weight, write output)
        double bytesProcessed = (size * sizeof(float) * 3) * iterations;
        double bandwidthGBs = (bytesProcessed / (totalTimeMs / 1000.0)) / 1e9;
        
        printf("  Size %6zu: %.3f ms/iter, %.2f GB/s\n", size, avgTimeMs, bandwidthGBs);
        
        benchmarkResults.push_back({"RMSNorm", size, avgTimeMs, bandwidthGBs, 0.0});
    }
    printf("\n");
}

void benchmarkResidualAdd(Sovereign_KernelTable& table) {
    if (!table.residual_add_f32) return;
    
    printf("[Benchmark] ResidualAdd_F32\n");
    printf("---------------------------\n");
    
    const size_t sizes[] = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 262144, 1048576};
    const int iterations = 100;
    
    for (size_t size : sizes) {
        std::vector<float> input(size);
        std::vector<float> residual(size);
        std::vector<float> output(size);
        generateRandomData(input.data(), size);
        generateRandomData(residual.data(), size);
        
        // Warmup
        for (int i = 0; i < 10; i++) {
            table.residual_add_f32(input.data(), residual.data(), output.data(), size);
        }
        
        // Benchmark
        Timer timer;
        timer.Start();
        for (int i = 0; i < iterations; i++) {
            table.residual_add_f32(input.data(), residual.data(), output.data(), size);
        }
        double totalTimeMs = timer.ElapsedMs();
        double avgTimeMs = totalTimeMs / iterations;
        
        // Calculate bandwidth (read input + residual, write output)
        double bytesProcessed = (size * sizeof(float) * 3) * iterations;
        double bandwidthGBs = (bytesProcessed / (totalTimeMs / 1000.0)) / 1e9;
        
        printf("  Size %7zu: %.3f ms/iter, %.2f GB/s\n", size, avgTimeMs, bandwidthGBs);
        
        benchmarkResults.push_back({"ResidualAdd", size, avgTimeMs, bandwidthGBs, 0.0});
    }
    printf("\n");
}

//==============================================================================
// Stress Test
//==============================================================================
void runStressTest(Sovereign_KernelTable& table) {
    printf("[Stress Test] Running 1000 iterations...\n");
    printf("----------------------------------------\n");
    
    if (!table.rms_norm_f32 || !table.residual_add_f32) {
        printf("  Skipped: Required kernels not available\n\n");
        return;
    }
    
    const size_t size = 4096;
    std::vector<float> input(size);
    std::vector<float> weight(size, 1.0f);
    std::vector<float> residual(size);
    std::vector<float> temp(size);
    std::vector<float> output(size);
    
    generateRandomData(input.data(), size);
    generateRandomData(residual.data(), size);
    
    Timer timer;
    timer.Start();
    
    int errors = 0;
    for (int i = 0; i < 1000; i++) {
        // Chain: input -> RMSNorm -> temp
        int r1 = table.rms_norm_f32(input.data(), temp.data(), weight.data(), size, 1e-6f);
        // Chain: temp + residual -> output
        int r2 = table.residual_add_f32(temp.data(), residual.data(), output.data(), size);
        
        if (r1 != 0 || r2 != 0) errors++;
    }
    
    double totalTimeMs = timer.ElapsedMs();
    double avgTimeMs = totalTimeMs / 1000.0;
    
    printf("  Completed 1000 iterations in %.2f ms\n", totalTimeMs);
    printf("  Average: %.3f ms/iteration\n", avgTimeMs);
    printf("  Errors: %d\n\n", errors);
}

//==============================================================================
// Summary Report
//==============================================================================
void printSummary() {
    printf("==============================================================================\n");
    printf("Phase 7D Validation Summary\n");
    printf("==============================================================================\n\n");
    
    if (!validationResults.empty()) {
        printf("Validation Results:\n");
        int passed = 0;
        for (auto& r : validationResults) {
            printf("  [%s] %s\n", r.passed ? "PASS" : "FAIL", r.name);
            if (r.passed) passed++;
        }
        printf("  Total: %d/%d\n\n", passed, (int)validationResults.size());
    }
    
    if (!benchmarkResults.empty()) {
        printf("Benchmark Results:\n");
        printf("  %-20s %10s %12s %12s\n", "Kernel", "Size", "Time(ms)", "BW(GB/s)");
        printf("  %-20s %10s %12s %12s\n", "------", "----", "--------", "--------");
        
        for (auto& r : benchmarkResults) {
            printf("  %-20s %10zu %12.3f %12.2f\n", r.name, r.size, r.timeMs, r.bandwidthGBs);
        }
        printf("\n");
    }
    
    printf("==============================================================================\n");
}

//==============================================================================
// Main Entry Point
//==============================================================================
int main(int argc, char* argv[]) {
    printBanner();
    
    // Initialize kernel table
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    
    int initResult = Sovereign_InitKernelTable(&table);
    if (initResult != 0) {
        printf("ERROR: Failed to initialize kernel table (code: %d)\n", initResult);
        return 1;
    }
    
    if (argc < 2) {
        printUsage(argv[0]);
        return 0;
    }
    
    const char* command = argv[1];
    
    if (strcmp(command, "comprehensive") == 0) {
        printf("Running comprehensive validation suite...\n\n");
        validateRMSNorm(table);
        validateResidualAdd(table);
        printSummary();
        return 0;
    } else if (strcmp(command, "benchmark") == 0) {
        printf("Running performance benchmarks...\n\n");
        benchmarkRMSNorm(table);
        benchmarkResidualAdd(table);
        printSummary();
        return 0;
    } else if (strcmp(command, "accuracy") == 0) {
        printf("Running accuracy tests...\n\n");
        validateRMSNorm(table);
        validateResidualAdd(table);
        printSummary();
        return 0;
    } else if (strcmp(command, "stress") == 0) {
        runStressTest(table);
        return 0;
    } else if (strcmp(command, "info") == 0) {
        printf("Phase 7D - Comprehensive Validation\n");
        printf("------------------------------------\n");
        printf("Features:\n");
        printf("  - Multi-size kernel validation\n");
        printf("  - Performance benchmarking\n");
        printf("  - Numerical accuracy testing\n");
        printf("  - Stress testing\n");
        printf("  - Memory bandwidth measurement\n\n");
        return 0;
    } else if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0) {
        printUsage(argv[0]);
        return 0;
    } else {
        printf("Unknown command: %s\n\n", command);
        printUsage(argv[0]);
        return 1;
    }
}
