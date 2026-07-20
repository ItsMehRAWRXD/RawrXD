// ============================================================================
// deep2_q4_gemv_bench.cpp - Q4_K_M GEMV Kernel Benchmark
// Tests actual Q4 dequantization + GEMV performance
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <random>
#include <cstdint>

// Q4_K_M kernel interface
extern "C" {
    void Deep2_Q4K_GEMV(const void* weights, const float* input, float* output,
                        uint32_t numBlocks, uint32_t rows);
}

// Aligned allocation
float* alignedAllocFloat(size_t count) {
    return (float*)_aligned_malloc(count * sizeof(float), 32);
}

void alignedFree(void* ptr) {
    _aligned_free(ptr);
}

// Q4_K_M Block structure
struct alignas(32) Q4_K_M_Block {
    uint16_t scales[32];
    uint16_t mins[32];
    uint8_t  weights[128];
};

// Initialize Q4 blocks with random data
void initQ4Blocks(Q4_K_M_Block* blocks, size_t numBlocks) {
    std::mt19937 gen(42);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    
    for (size_t b = 0; b < numBlocks; b++) {
        Q4_K_M_Block* block = &blocks[b];
        
        for (int g = 0; g < 32; g++) {
            // Generate 8 weights for this group
            float weights[8];
            float minVal = 1e6, maxVal = -1e6;
            
            for (int i = 0; i < 8; i++) {
                weights[i] = dist(gen);
                minVal = (weights[i] < minVal) ? weights[i] : minVal;
                maxVal = (weights[i] > maxVal) ? weights[i] : maxVal;
            }
            
            // Quantize to 4-bit
            float scale = (maxVal - minVal) / 15.0f;
            if (scale < 1e-6f) scale = 1e-6f;
            
            // Store scale/min as FP16 (simplified to scaled int here)
            block->scales[g] = static_cast<uint16_t>(scale * 1000);
            block->mins[g] = static_cast<uint16_t>(minVal * 1000);
            
            // Pack 4-bit weights
            for (int i = 0; i < 8; i += 2) {
                int q0 = static_cast<int>((weights[i] - minVal) / scale + 0.5f);
                int q1 = static_cast<int>((weights[i+1] - minVal) / scale + 0.5f);
                q0 = (q0 < 0) ? 0 : (q0 > 15) ? 15 : q0;
                q1 = (q1 < 0) ? 0 : (q1 > 15) ? 15 : q1;
                block->weights[g * 4 + i/2] = static_cast<uint8_t>((q1 << 4) | q0);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Deep2 Q4_K_M GEMV Kernel Benchmark\n");
    printf("Q4 dequantization + Matrix-Vector Multiply\n");
    printf("========================================\n\n");
    
    // Configuration
    size_t hiddenDim = 4096;
    size_t numIterations = 1000;
    
    if (argc > 1) hiddenDim = atoi(argv[1]);
    if (argc > 2) numIterations = atoi(argv[2]);
    
    size_t numBlocks = (hiddenDim + 255) / 256;
    size_t weightBytes = numBlocks * sizeof(Q4_K_M_Block);
    
    printf("Configuration:\n");
    printf("  Hidden Dim: %zu\n", hiddenDim);
    printf("  Num Blocks: %zu\n", numBlocks);
    printf("  Weight Memory: %.2f KB (Q4) vs %.2f KB (FP32)\n",
           weightBytes / 1024.0, hiddenDim * sizeof(float) / 1024.0);
    printf("  Compression: 4.00x\n\n");
    
    // Allocate and initialize
    Q4_K_M_Block* weights = (Q4_K_M_Block*)_aligned_malloc(weightBytes, 32);
    float* input = alignedAllocFloat(hiddenDim);
    float* output = alignedAllocFloat(hiddenDim);
    
    initQ4Blocks(weights, numBlocks);
    
    // Initialize input
    std::mt19937 gen(123);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (size_t i = 0; i < hiddenDim; i++) {
        input[i] = dist(gen);
    }
    
    // Warmup
    printf("Warming up...\n");
    for (int i = 0; i < 10; i++) {
        Deep2_Q4K_GEMV(weights, input, output, static_cast<uint32_t>(numBlocks),
                      static_cast<uint32_t>(hiddenDim));
    }
    
    // Benchmark
    printf("Running benchmark (%zu iterations)...\n", numIterations);
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < numIterations; i++) {
        Deep2_Q4K_GEMV(weights, input, output, static_cast<uint32_t>(numBlocks),
                      static_cast<uint32_t>(hiddenDim));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double totalMs = duration.count() / 1000.0;
    double avgMs = totalMs / numIterations;
    
    // Calculate metrics
    double opsPerCall = 2.0 * hiddenDim * hiddenDim; // MAC operations
    double totalOps = opsPerCall * numIterations;
    double gflops = totalOps / 1e9 / (totalMs / 1000.0);
    
    double bytesRead = (weightBytes + hiddenDim * sizeof(float)) * numIterations;
    double bandwidthGBps = (bytesRead / 1e9) / (totalMs / 1000.0);
    
    // Estimate transformer TPS
    // 32 layers * 6 GEMV per layer (Q,K,V,O, up, gate) = 192 GEMV per token
    double gemvPerToken = 192;
    double tokensPerSecond = 1000.0 / (avgMs * gemvPerToken);
    
    printf("\n========================================\n");
    printf("Q4_K_M GEMV BENCHMARK RESULTS\n");
    printf("========================================\n");
    printf("Iterations:          %zu\n", numIterations);
    printf("Total Time:          %.2f ms\n", totalMs);
    printf("Avg Time/GEMV:       %.3f ms\n", avgMs);
    printf("----------------------------------------\n");
    printf("Compute:             %.2f GFLOP/s\n", gflops);
    printf("Bandwidth:           %.2f GB/s\n", bandwidthGBps);
    printf("----------------------------------------\n");
    printf("Est. Transformer:  %.2f TPS\n", tokensPerSecond);
    printf("(32 layers, 6 GEMV/layer)\n");
    printf("========================================\n");
    
    // Export to CSV
    FILE* csv = fopen("deep2_q4_gemv_results.csv", "w");
    if (csv) {
        fprintf(csv, "Metric,Value,Unit\n");
        fprintf(csv, "HiddenDim,%zu,\n", hiddenDim);
        fprintf(csv, "NumIterations,%zu,\n", numIterations);
        fprintf(csv, "TotalTimeMs,%.2f,ms\n", totalMs);
        fprintf(csv, "AvgTimePerGEMV,%.3f,ms\n", avgMs);
        fprintf(csv, "ComputeGFLOPs,%.2f,GFLOP/s\n", gflops);
        fprintf(csv, "BandwidthGBps,%.2f,GB/s\n", bandwidthGBps);
        fprintf(csv, "EstTokensPerSec,%.2f,tokens/sec\n", tokensPerSecond);
        fclose(csv);
        printf("\nResults exported to: deep2_q4_gemv_results.csv\n");
    }
    
    // Cleanup
    _aligned_free(weights);
    alignedFree(input);
    alignedFree(output);
    
    printf("\nBenchmark complete!\n");
    return 0;
}
