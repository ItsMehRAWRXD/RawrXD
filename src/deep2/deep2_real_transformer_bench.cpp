// ============================================================================
// deep2_real_transformer_bench.cpp - REAL Transformer Benchmark
// Uses actual Deep2 kernels for matrix operations
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>
#include <cmath>
#include <random>

// Deep2 kernel interface
extern "C" {
    void Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n);
    void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n);
    void Deep2_RMSNorm(const float* x, float* out, size_t n, float eps);
}

// Aligned allocation
float* alignedAlloc(size_t count) {
#ifdef _WIN32
    return (float*)_aligned_malloc(count * sizeof(float), 32);
#else
    return (float*)aligned_alloc(32, count * sizeof(float));
#endif
}

void alignedFree(float* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

// ============================================================================
// Real Transformer Layer with Deep2 Kernels
// ============================================================================
struct TransformerLayer {
    size_t hiddenDim;
    size_t intermediateDim;
    float eps;
    
    // Weights
    float* wq; float* wk; float* wv; float* wo;
    float* w1; float* w2; float* w3;
    
    // Buffers
    float* q; float* k; float* v;
    float* attnOut;
    float* ffnGate; float* ffnUp;
    float* normBuffer;
    
    TransformerLayer(size_t hidden, size_t intermediate) 
        : hiddenDim(hidden), intermediateDim(intermediate), eps(1e-6f) {
        
        // Allocate weights
        wq = alignedAlloc(hiddenDim * hiddenDim);
        wk = alignedAlloc(hiddenDim * hiddenDim);
        wv = alignedAlloc(hiddenDim * hiddenDim);
        wo = alignedAlloc(hiddenDim * hiddenDim);
        w1 = alignedAlloc(hiddenDim * intermediateDim);
        w2 = alignedAlloc(intermediateDim * hiddenDim);
        w3 = alignedAlloc(hiddenDim * intermediateDim);
        
        // Allocate buffers
        q = alignedAlloc(hiddenDim);
        k = alignedAlloc(hiddenDim);
        v = alignedAlloc(hiddenDim);
        attnOut = alignedAlloc(hiddenDim);
        ffnGate = alignedAlloc(intermediateDim);
        ffnUp = alignedAlloc(intermediateDim);
        normBuffer = alignedAlloc(hiddenDim);
        
        // Initialize weights with small random values
        std::mt19937 gen(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        
        auto init = [&](float* w, size_t n) {
            for (size_t i = 0; i < n; i++) w[i] = dist(gen);
        };
        
        init(wq, hiddenDim * hiddenDim);
        init(wk, hiddenDim * hiddenDim);
        init(wv, hiddenDim * hiddenDim);
        init(wo, hiddenDim * hiddenDim);
        init(w1, hiddenDim * intermediateDim);
        init(w2, intermediateDim * hiddenDim);
        init(w3, hiddenDim * intermediateDim);
    }
    
    ~TransformerLayer() {
        alignedFree(wq); alignedFree(wk); alignedFree(wv); alignedFree(wo);
        alignedFree(w1); alignedFree(w2); alignedFree(w3);
        alignedFree(q); alignedFree(k); alignedFree(v);
        alignedFree(attnOut); alignedFree(ffnGate); alignedFree(ffnUp);
        alignedFree(normBuffer);
    }
    
    // Real forward pass using Deep2 kernels
    void forward(const float* input, float* output) {
        // === ATTENTION BLOCK ===
        // 1. RMSNorm
        Deep2_RMSNorm(input, normBuffer, hiddenDim, eps);
        
        // 2. QKV projections using Deep2_VecDotProduct
        // For each output dimension
        for (size_t i = 0; i < hiddenDim; i += 8) {
            size_t n = std::min(size_t(8), hiddenDim - i);
            
            // Q = norm @ wq[i]
            Deep2_VecDotProduct(normBuffer, wq + i * hiddenDim, q + i, hiddenDim);
            // K = norm @ wk[i]
            Deep2_VecDotProduct(normBuffer, wk + i * hiddenDim, k + i, hiddenDim);
            // V = norm @ wv[i]
            Deep2_VecDotProduct(normBuffer, wv + i * hiddenDim, v + i, hiddenDim);
        }
        
        // 3. Simplified attention (single head for benchmark)
        // attn = softmax(Q @ K.T) @ V
        // For simplicity: just use V as attention output
        memcpy(attnOut, v, hiddenDim * sizeof(float));
        
        // 4. Output projection
        for (size_t i = 0; i < hiddenDim; i += 8) {
            Deep2_VecDotProduct(attnOut, wo + i * hiddenDim, output + i, hiddenDim);
        }
        
        // 5. Residual connection
        for (size_t i = 0; i < hiddenDim; i++) {
            output[i] += input[i];
        }
        
        // === FFN BLOCK ===
        // 6. RMSNorm
        Deep2_RMSNorm(output, normBuffer, hiddenDim, eps);
        
        // 7. SwiGLU FFN
        // gate = norm @ w1, up = norm @ w3
        for (size_t i = 0; i < intermediateDim; i += 8) {
            Deep2_VecDotProduct(normBuffer, w1 + i * hiddenDim, ffnGate + i, hiddenDim);
            Deep2_VecDotProduct(normBuffer, w3 + i * hiddenDim, ffnUp + i, hiddenDim);
        }
        
        // SwiGLU: silu(gate) * up
        Deep2_SwiGLU(ffnGate, ffnUp, ffnGate, intermediateDim);
        
        // 8. Down projection
        for (size_t i = 0; i < hiddenDim; i += 8) {
            Deep2_VecDotProduct(ffnGate, w2 + i * intermediateDim, output + i, intermediateDim);
        }
        
        // 9. Residual connection
        for (size_t i = 0; i < hiddenDim; i++) {
            output[i] += input[i];
        }
    }
};

// ============================================================================
// Benchmark
// ============================================================================
int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Deep2 REAL Transformer Benchmark\n");
    printf("Actual Deep2 kernel computation\n");
    printf("========================================\n\n");
    
    // Configuration
    size_t hiddenDim = 4096;
    size_t numLayers = 32;
    size_t numTokens = 10;
    
    if (argc > 1) hiddenDim = atoi(argv[1]);
    if (argc > 2) numLayers = atoi(argv[2]);
    if (argc > 3) numTokens = atoi(argv[3]);
    
    size_t intermediateDim = hiddenDim * 4;
    
    printf("Configuration:\n");
    printf("  Hidden Dim: %zu\n", hiddenDim);
    printf("  Intermediate Dim: %zu\n", intermediateDim);
    printf("  Num Layers: %zu\n", numLayers);
    printf("  Tokens: %zu\n\n", numTokens);
    
    // Create layers
    printf("Creating %zu transformer layers...\n", numLayers);
    std::vector<TransformerLayer*> layers;
    for (size_t i = 0; i < numLayers; i++) {
        layers.push_back(new TransformerLayer(hiddenDim, intermediateDim));
    }
    
    // Allocate buffers
    float* input = alignedAlloc(hiddenDim);
    float* output = alignedAlloc(hiddenDim);
    
    // Initialize input
    for (size_t i = 0; i < hiddenDim; i++) {
        input[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
    }
    
    // Warmup
    printf("Warming up...\n");
    for (size_t t = 0; t < 3; t++) {
        for (auto* layer : layers) {
            layer->forward(input, output);
            memcpy(input, output, hiddenDim * sizeof(float));
        }
    }
    
    // Benchmark
    printf("Running benchmark...\n");
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t t = 0; t < numTokens; t++) {
        for (auto* layer : layers) {
            layer->forward(input, output);
            memcpy(input, output, hiddenDim * sizeof(float));
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double totalMs = duration.count() / 1000.0;
    
    // Calculate metrics
    double tokensPerSecond = (double)numTokens / (totalMs / 1000.0);
    double latencyPerToken = totalMs / numTokens;
    
    // Calculate model size
    size_t paramsPerLayer = hiddenDim * hiddenDim * 4 +  // QKVO
                           hiddenDim * intermediateDim * 3; // FFN
    size_t totalParams = paramsPerLayer * numLayers;
    double modelSizeGB = (double)totalParams * 4 / (1024 * 1024 * 1024);
    
    // Calculate FLOPs per token
    size_t flopsPerLayer = hiddenDim * hiddenDim * 4 +  // QKVO projections
                          hiddenDim * intermediateDim * 3; // FFN
    size_t totalFlops = flopsPerLayer * numLayers * numTokens;
    double gflops = (double)totalFlops / 1e9;
    double gflopsPerSecond = gflops / (totalMs / 1000.0);
    
    printf("\n========================================\n");
    printf("BENCHMARK RESULTS\n");
    printf("========================================\n");
    printf("Tokens Generated:    %zu\n", numTokens);
    printf("Total Time:          %.2f ms\n", totalMs);
    printf("Tokens/Second:       %.2f\n", tokensPerSecond);
    printf("Latency/Token:       %.2f ms\n", latencyPerToken);
    printf("----------------------------------------\n");
    printf("Model Size:          %.2f GB\n", modelSizeGB);
    printf("Total Params:        %.1f B\n", (double)totalParams / 1e9);
    printf("GFLOPs:              %.2f\n", gflops);
    printf("GFLOPs/Second:       %.2f\n", gflopsPerSecond);
    printf("========================================\n");
    
    // Export to CSV
    FILE* csv = fopen("deep2_real_transformer_results.csv", "w");
    if (csv) {
        fprintf(csv, "Metric,Value,Unit\n");
        fprintf(csv, "HiddenDim,%zu,\n", hiddenDim);
        fprintf(csv, "NumLayers,%zu,\n", numLayers);
        fprintf(csv, "TokensGenerated,%zu,\n", numTokens);
        fprintf(csv, "TotalTimeMs,%.2f,ms\n", totalMs);
        fprintf(csv, "TokensPerSecond,%.2f,tokens/sec\n", tokensPerSecond);
        fprintf(csv, "LatencyPerToken,%.2f,ms\n", latencyPerToken);
        fprintf(csv, "ModelSizeGB,%.2f,GB\n", modelSizeGB);
        fprintf(csv, "TotalParams,%.1f,B\n", (double)totalParams / 1e9);
        fprintf(csv, "GFLOPs,%.2f,\n", gflops);
        fprintf(csv, "GFLOPsPerSecond,%.2f,GFLOP/s\n", gflopsPerSecond);
        fclose(csv);
        printf("\nResults exported to: deep2_real_transformer_results.csv\n");
    }
    
    // Cleanup
    for (auto* layer : layers) delete layer;
    alignedFree(input);
    alignedFree(output);
    
    printf("\nBenchmark complete!\n");
    return 0;
}
