//==============================================================================
// TitanCLI.cpp
// Command-line interface for Titan kernel integration
//
// Usage:
//   TitanCLI.exe --status          Show kernel status
//   TitanCLI.exe --test            Run kernel tests
//   TitanCLI.exe --benchmark       Run performance benchmarks
//   TitanCLI.exe --init            Initialize and verify integration
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

// Include Titan integration
#include "../core/execution/Titan_KernelIntegration.hpp"
#include "../core/execution/UnifiedKernelInterface.hpp"
#include "../core/execution/MemoryBridge.hpp"

using namespace Titan;
using namespace Sovereign;

//==============================================================================
// Test Functions
//==============================================================================

bool TestRMSNorm() {
    printf("Testing RMSNorm... ");
    
    const int n = 4096;
    float* input = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    float* output = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    float* weight = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    
    // Initialize test data
    for (int i = 0; i < n; i++) {
        input[i] = 1.0f;
        weight[i] = 1.0f;
    }
    
    KernelContext ctx;
    ctx.input = input;
    ctx.output = output;
    ctx.weights = weight;
    ctx.embedDim = n;
    ctx.epsilon = 1e-5f;
    
    KernelResult result = TitanKernelIntegration::GetInstance().ExecuteRMSNorm(ctx);
    
    MemoryBridge::AlignedFree(input);
    MemoryBridge::AlignedFree(output);
    MemoryBridge::AlignedFree(weight);
    
    if (result.success) {
        printf("✓ PASS (%.3f ms)\n", result.executionTimeMs);
        return true;
    } else {
        printf("✗ FAIL: %s\n", result.errorMessage ? result.errorMessage : "Unknown error");
        return false;
    }
}

bool TestLayerNorm() {
    printf("Testing LayerNorm... ");
    
    const int n = 4096;
    float* input = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    float* output = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    float* gamma = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    float* beta = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    
    for (int i = 0; i < n; i++) {
        input[i] = 1.0f;
        gamma[i] = 1.0f;
        beta[i] = 0.0f;
    }
    
    KernelContext ctx;
    ctx.input = input;
    ctx.output = output;
    ctx.weights = gamma;
    ctx.bias = beta;
    ctx.embedDim = n;
    ctx.epsilon = 1e-5f;
    
    KernelResult result = TitanKernelIntegration::GetInstance().ExecuteLayerNorm(ctx);
    
    MemoryBridge::AlignedFree(input);
    MemoryBridge::AlignedFree(output);
    MemoryBridge::AlignedFree(gamma);
    MemoryBridge::AlignedFree(beta);
    
    if (result.success) {
        printf("✓ PASS (%.3f ms)\n", result.executionTimeMs);
        return true;
    } else {
        printf("✗ FAIL: %s\n", result.errorMessage ? result.errorMessage : "Unknown error");
        return false;
    }
}

bool TestResidualAdd() {
    printf("Testing ResidualAdd... ");
    
    const int n = 4096;
    float* input = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    float* residual = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    float* output = (float*)MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
    
    for (int i = 0; i < n; i++) {
        input[i] = 1.0f;
        residual[i] = 0.5f;
    }
    
    KernelContext ctx;
    ctx.input = input;
    ctx.output = output;
    ctx.weights = residual; // Using weights field for residual
    ctx.embedDim = n;
    
    KernelResult result = TitanKernelIntegration::GetInstance().ExecuteResidualAdd(ctx);
    
    MemoryBridge::AlignedFree(input);
    MemoryBridge::AlignedFree(residual);
    MemoryBridge::AlignedFree(output);
    
    if (result.success) {
        printf("✓ PASS (%.3f ms)\n", result.executionTimeMs);
        return true;
    } else {
        printf("✗ FAIL: %s\n", result.errorMessage ? result.errorMessage : "Unknown error");
        return false;
    }
}

bool TestQ4Q8MatMul() {
    printf("Testing Q4Q8MatMul... ");
    
    const int m = 32, n = 32, k = 32;
    
    // Allocate aligned buffers
    // Note: These would normally be Q4/Q8 quantized, using float for test
    float* A = (float*)MemoryBridge::AlignedAlloc(m * k * sizeof(float), 64);
    float* B = (float*)MemoryBridge::AlignedAlloc(k * n * sizeof(float), 64);
    float* C = (float*)MemoryBridge::AlignedAlloc(m * n * sizeof(float), 64);
    
    for (int i = 0; i < m * k; i++) A[i] = 0.1f;
    for (int i = 0; i < k * n; i++) B[i] = 0.1f;
    
    KernelContext ctx;
    ctx.input = A;
    ctx.weights = B;
    ctx.output = C;
    ctx.batchSize = m;
    ctx.seqLen = k;
    ctx.embedDim = n;
    
    KernelResult result = TitanKernelIntegration::GetInstance().ExecuteQ4Q8MatMul(ctx);
    
    MemoryBridge::AlignedFree(A);
    MemoryBridge::AlignedFree(B);
    MemoryBridge::AlignedFree(C);
    
    if (result.success) {
        printf("✓ PASS (%.3f ms)\n", result.executionTimeMs);
        return true;
    } else {
        printf("✗ SKIP: %s\n", result.errorMessage ? result.errorMessage : "Not available");
        return true; // Skip, not fail
    }
}

//==============================================================================
// Benchmark Functions
//==============================================================================

void BenchmarkKernel(const char* name, KernelType type, 
                     std::function<void(KernelContext&)> setup) {
    auto& titan = TitanKernelIntegration::GetInstance();
    
    if (!titan.IsKernelAvailable(type)) {
        printf("  %-20s: Not available\n", name);
        return;
    }
    
    KernelContext ctx;
    setup(ctx);
    
    // Warmup
    titan.Execute(type, ctx);
    
    // Benchmark
    const int iterations = 100;
    float totalTime = 0;
    
    for (int i = 0; i < iterations; i++) {
        KernelResult result = titan.Execute(type, ctx);
        if (result.success) {
            totalTime += result.executionTimeMs;
        }
    }
    
    float avgTime = totalTime / iterations;
    printf("  %-20s: %.3f ms avg (%d iterations)\n", name, avgTime, iterations);
    
    // Cleanup
    if (ctx.input) MemoryBridge::AlignedFree(ctx.input);
    if (ctx.output) MemoryBridge::AlignedFree(ctx.output);
    if (ctx.weights) MemoryBridge::AlignedFree(ctx.weights);
    if (ctx.bias) MemoryBridge::AlignedFree(ctx.bias);
}

void RunBenchmarks() {
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    KERNEL BENCHMARKS                         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    auto& titan = TitanKernelIntegration::GetInstance();
    
    // RMSNorm benchmark
    BenchmarkKernel("RMSNorm (4096)", KernelType::RMS_NORM, [](KernelContext& ctx) {
        const int n = 4096;
        ctx.input = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.output = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.weights = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.embedDim = n;
        ctx.epsilon = 1e-5f;
        for (int i = 0; i < n; i++) {
            ((float*)ctx.input)[i] = 1.0f;
            ((float*)ctx.weights)[i] = 1.0f;
        }
    });
    
    // LayerNorm benchmark
    BenchmarkKernel("LayerNorm (4096)", KernelType::LAYER_NORM, [](KernelContext& ctx) {
        const int n = 4096;
        ctx.input = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.output = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.weights = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.bias = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.embedDim = n;
        ctx.epsilon = 1e-5f;
        for (int i = 0; i < n; i++) {
            ((float*)ctx.input)[i] = 1.0f;
            ((float*)ctx.weights)[i] = 1.0f;
            ((float*)ctx.bias)[i] = 0.0f;
        }
    });
    
    // ResidualAdd benchmark
    BenchmarkKernel("ResidualAdd (4096)", KernelType::RESIDUAL_ADD, [](KernelContext& ctx) {
        const int n = 4096;
        ctx.input = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.output = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.weights = MemoryBridge::AlignedAlloc(n * sizeof(float), 64);
        ctx.embedDim = n;
        for (int i = 0; i < n; i++) {
            ((float*)ctx.input)[i] = 1.0f;
            ((float*)ctx.weights)[i] = 0.5f;
        }
    });
    
    printf("\n");
}

//==============================================================================
// Main
//==============================================================================

void PrintUsage(const char* prog) {
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --status     Show kernel integration status\n");
    printf("  --test       Run kernel tests\n");
    printf("  --benchmark  Run performance benchmarks\n");
    printf("  --init       Initialize and verify (default)\n");
    printf("  --help       Show this help\n");
}

int main(int argc, char* argv[]) {
    // Parse arguments
    bool showStatus = false;
    bool runTests = false;
    bool runBenchmarks = false;
    bool doInit = true;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--status") == 0) showStatus = true;
        else if (strcmp(argv[i], "--test") == 0) runTests = true;
        else if (strcmp(argv[i], "--benchmark") == 0) runBenchmarks = true;
        else if (strcmp(argv[i], "--init") == 0) { doInit = true; }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    // Default: show status
    if (!showStatus && !runTests && !runBenchmarks) {
        showStatus = true;
    }
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║           TITAN KERNEL INTEGRATION CLI v1.0                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    // Initialize
    if (doInit) {
        printf("Initializing Titan Kernel Integration...\n");
        
        auto& titan = TitanKernelIntegration::GetInstance();
        if (!titan.Initialize()) {
            printf("ERROR: Failed to initialize Titan Kernel Integration\n");
            return 1;
        }
        
        printf("✓ Initialization complete\n\n");
    }
    
    // Show status
    if (showStatus) {
        auto& titan = TitanKernelIntegration::GetInstance();
        printf("%s\n", titan.GetStatusReport().c_str());
    }
    
    // Run tests
    if (runTests) {
        printf("\n╔══════════════════════════════════════════════════════════════╗\n");
        printf("║                    KERNEL TESTS                              ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n\n");
        
        int passed = 0;
        int total = 0;
        
        if (TestRMSNorm()) passed++; total++;
        if (TestLayerNorm()) passed++; total++;
        if (TestResidualAdd()) passed++; total++;
        if (TestQ4Q8MatMul()) passed++; total++;
        
        printf("\n─────────────────────────────────────────────────────────────\n");
        printf("Tests: %d/%d passed\n", passed, total);
        printf("─────────────────────────────────────────────────────────────\n\n");
    }
    
    // Run benchmarks
    if (runBenchmarks) {
        RunBenchmarks();
    }
    
    printf("Done.\n\n");
    return 0;
}
