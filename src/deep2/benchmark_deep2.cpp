// ============================================================================
// benchmark_deep2.cpp - Deep2 Engine Performance Benchmark
// Measures TPS (Tokens Per Second) for valuation metrics
// ============================================================================

#include "Deep2.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <random>

// Simulate a transformer layer forward pass using Deep2 kernels
void SimulateTransformerLayer(
    const float* input,
    float* output,
    size_t hiddenDim,
    size_t seqLen,
    Deep2::Context& ctx
) {
    // Self-attention simulation (simplified)
    std::vector<float> q(hiddenDim * seqLen);
    std::vector<float> k(hiddenDim * seqLen);
    std::vector<float> v(hiddenDim * seqLen);
    
    // Q = input * Wq (simulated with dot products)
    for (size_t s = 0; s < seqLen; ++s) {
        const float* inRow = input + s * hiddenDim;
        float* qRow = q.data() + s * hiddenDim;
        
        // Simulate linear projection using dot product
        for (size_t h = 0; h < hiddenDim; ++h) {
            float dotResult;
            Deep2_VecDotProduct(inRow, inRow, &dotResult, hiddenDim);
            qRow[h] = dotResult * 0.01f; // Scaled
        }
    }
    
    // Apply SwiGLU activation to simulate FFN
    std::vector<float> ffnGate(hiddenDim * seqLen);
    std::vector<float> ffnUp(hiddenDim * seqLen);
    std::vector<float> ffnOut(hiddenDim * seqLen);
    
    // Initialize with random data for realistic test
    std::mt19937 gen(42);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    for (auto& val : ffnGate) val = dist(gen);
    for (auto& val : ffnUp) val = dist(gen);
    
    // Run SwiGLU on aligned buffers
    float* alignedGate = Deep2_AlignedAlloc(hiddenDim * seqLen);
    float* alignedUp = Deep2_AlignedAlloc(hiddenDim * seqLen);
    float* alignedOut = Deep2_AlignedAlloc(hiddenDim * seqLen);
    
    memcpy(alignedGate, ffnGate.data(), hiddenDim * seqLen * sizeof(float));
    memcpy(alignedUp, ffnUp.data(), hiddenDim * seqLen * sizeof(float));
    
    Deep2_SwiGLU(alignedGate, alignedUp, alignedOut, hiddenDim * seqLen);
    
    // Apply RMSNorm
    Deep2_RMSNorm(alignedOut, alignedOut, hiddenDim * seqLen, 1e-6f);
    
    // Copy result to output
    memcpy(output, alignedOut, hiddenDim * seqLen * sizeof(float));
    
    Deep2_AlignedFree(alignedGate);
    Deep2_AlignedFree(alignedUp);
    Deep2_AlignedFree(alignedOut);
}

// ============================================================================
// Benchmark: Measure TPS for different model sizes
// ============================================================================
struct BenchmarkResult {
    const char* modelName;
    size_t hiddenDim;
    size_t numLayers;
    size_t seqLen;
    double tokensPerSecond;
    double latencyMs;
    double throughputGBps;
};

void RunBenchmark(const char* name, size_t hiddenDim, size_t numLayers, size_t seqLen) {
    printf("\n[Benchmark] %s\n", name);
    printf("  Hidden Dim: %zu, Layers: %zu, Seq Len: %zu\n", hiddenDim, numLayers, seqLen);
    
    // Initialize Deep2 context
    Deep2::Config config;
    config.hiddenDim = static_cast<int32_t>(hiddenDim);
    config.numExperts = 8;
    config.expertsPerToken = 2;
    
    Deep2::Context ctx;
    if (!ctx.Initialize(config)) {
        printf("  ERROR: Failed to initialize Deep2 context\n");
        return;
    }
    
    // Allocate buffers
    size_t bufferSize = hiddenDim * seqLen;
    float* input = Deep2_AlignedAlloc(bufferSize);
    float* output = Deep2_AlignedAlloc(bufferSize);
    
    if (!input || !output) {
        printf("  ERROR: Memory allocation failed\n");
        return;
    }
    
    // Initialize input with test pattern
    for (size_t i = 0; i < bufferSize; ++i) {
        input[i] = static_cast<float>(i % 100) / 100.0f;
    }
    
    // Warmup
    printf("  Warming up...\n");
    for (size_t w = 0; w < 3; ++w) {
        SimulateTransformerLayer(input, output, hiddenDim, seqLen, ctx);
    }
    
    // Benchmark
    printf("  Running benchmark...\n");
    auto start = std::chrono::high_resolution_clock::now();
    uint64_t tscStart = Deep2::Perf::ReadTSC();
    
    for (size_t layer = 0; layer < numLayers; ++layer) {
        SimulateTransformerLayer(input, output, hiddenDim, seqLen, ctx);
        // Swap input/output for next layer
        std::swap(input, output);
    }
    
    uint64_t tscEnd = Deep2::Perf::ReadTSC();
    auto end = std::chrono::high_resolution_clock::now();
    
    // Calculate metrics
    double elapsedMs = std::chrono::duration<double, std::milli>(end - start).count();
    double elapsedSec = elapsedMs / 1000.0;
    size_t totalTokens = seqLen * numLayers;
    double tps = totalTokens / elapsedSec;
    
    // Memory throughput (rough estimate: 2 reads + 1 write per element)
    size_t bytesProcessed = bufferSize * sizeof(float) * 3 * numLayers;
    double throughputGBps = (bytesProcessed / elapsedSec) / (1024.0 * 1024.0 * 1024.0);
    
    printf("\n  === Results ===\n");
    printf("  Time:        %.2f ms\n", elapsedMs);
    printf("  Tokens:      %zu\n", totalTokens);
    printf("  TPS:         %.2f tokens/sec\n", tps);
    printf("  Latency:     %.3f ms/token\n", elapsedMs / totalTokens);
    printf("  Throughput:  %.2f GB/s\n", throughputGBps);
    printf("  Cycles:      %.2f cycles/token\n", 
           static_cast<double>(tscEnd - tscStart) / totalTokens);
    
    Deep2_AlignedFree(input);
    Deep2_AlignedFree(output);
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=================================================================\n");
    printf("Deep2 Engine Performance Benchmark\n");
    printf("=================================================================\n");
    
    // Check CPU features
    printf("\n[System Info]\n");
    printf("  AVX2:    %s\n", Deep2_HasAVX2() ? "YES" : "NO");
    printf("  AVX512:  %s\n", Deep2_HasAVX512() ? "YES" : "NO");
    
    if (!Deep2_HasAVX2()) {
        printf("\nERROR: AVX2 required but not available\n");
        return 1;
    }
    
    // Run benchmarks for different model configurations
    printf("\n=================================================================\n");
    printf("Model Size Benchmarks\n");
    printf("=================================================================\n");
    
    // Small model (Llama 3.2 3B equivalent)
    RunBenchmark("Small Model (3B params)", 3072, 28, 128);
    
    // Medium model (Llama 3.1 8B equivalent)
    RunBenchmark("Medium Model (8B params)", 4096, 32, 128);
    
    // Large model (Llama 3.1 70B equivalent)
    RunBenchmark("Large Model (70B params)", 8192, 80, 64);
    
    // XL model (DeepSeek 671B MoE - single expert)
    RunBenchmark("XL Model (671B MoE - single expert)", 7168, 61, 32);
    
    printf("\n=================================================================\n");
    printf("Benchmark Complete\n");
    printf("=================================================================\n");
    
    return 0;
}
