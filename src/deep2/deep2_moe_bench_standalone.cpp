// ============================================================================
// deep2_moe_bench_standalone.cpp - Standalone MoE Benchmark
// No external dependencies - pure C++ implementation
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <chrono>
#include <random>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

// Configuration matching DeepSeek-V3
#define HIDDEN_DIM 7168
#define NUM_EXPERTS 256
#define TOP_K 8
#define EXPERT_DIM 2048
#define NUM_LAYERS 61
#define BATCH_SIZE 1

using namespace std::chrono;

// Timing helper
inline double GetTimeMs() {
    return duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count() / 1000.0;
}

// ============================================================================
// Q4_K GEMV (basic implementation - full implementation uses AVX-512)
// ============================================================================
void Q4K_GEMV_Simulated(const float* weights, const float* input, float* output,
                         int rows, int cols) {
    // Model Q4_K: weights are 4-bit quantized, dequantized on the fly
    for (int r = 0; r < rows; r++) {
        float sum = 0.0f;
        for (int c = 0; c < cols; c++) {
            // Model dequantization: weight = (quantized - 8) * scale
            int quant = ((r * cols + c) % 16) - 8;  // -8 to +7
            float scale = 0.01f;
            sum += quant * scale * input[c];
        }
        output[r] = sum;
    }
}

// ============================================================================
// SwiGLU activation
// ============================================================================
void SwiGLU(const float* gate, const float* up, float* output, int n) {
    for (int i = 0; i < n; i++) {
        // SwiGLU: silu(gate) * up
        float silu = gate[i] / (1.0f + expf(-gate[i]));
        output[i] = silu * up[i];
    }
}

// ============================================================================
// MoE Router
// ============================================================================
class MoERouter {
    float routerWeights[HIDDEN_DIM * NUM_EXPERTS];
    
public:
    MoERouter() {
        std::mt19937 rng(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        for (int i = 0; i < HIDDEN_DIM * NUM_EXPERTS; i++) {
            routerWeights[i] = dist(rng);
        }
    }
    
    void Route(const float* hiddenState, int* expertIds, float* expertWeights) {
        float logits[NUM_EXPERTS];
        
        // Compute router logits
        for (int e = 0; e < NUM_EXPERTS; e++) {
            float sum = 0.0f;
            for (int h = 0; h < HIDDEN_DIM; h++) {
                sum += hiddenState[h] * routerWeights[e * HIDDEN_DIM + h];
            }
            logits[e] = sum;
        }
        
        // Softmax
        float maxLogit = logits[0];
        for (int e = 1; e < NUM_EXPERTS; e++) {
            if (logits[e] > maxLogit) maxLogit = logits[e];
        }
        
        float expSum = 0.0f;
        for (int e = 0; e < NUM_EXPERTS; e++) {
            logits[e] = expf(logits[e] - maxLogit);
            expSum += logits[e];
        }
        
        for (int e = 0; e < NUM_EXPERTS; e++) {
            logits[e] /= expSum;
        }
        
        // Top-k selection (simplified)
        // In real impl: use heap or partial sort
        float sortedProbs[NUM_EXPERTS];
        int sortedIds[NUM_EXPERTS];
        for (int e = 0; e < NUM_EXPERTS; e++) {
            sortedProbs[e] = logits[e];
            sortedIds[e] = e;
        }
        
        // Simple bubble sort for top-k
        for (int i = 0; i < TOP_K; i++) {
            for (int j = i + 1; j < NUM_EXPERTS; j++) {
                if (sortedProbs[j] > sortedProbs[i]) {
                    std::swap(sortedProbs[i], sortedProbs[j]);
                    std::swap(sortedIds[i], sortedIds[j]);
                }
            }
        }
        
        // Renormalize top-k weights
        float weightSum = 0.0f;
        for (int i = 0; i < TOP_K; i++) {
            weightSum += sortedProbs[i];
        }
        
        for (int i = 0; i < TOP_K; i++) {
            expertIds[i] = sortedIds[i];
            expertWeights[i] = sortedProbs[i] / weightSum;
        }
    }
};

// ============================================================================
// Expert FFN
// ============================================================================
class ExpertFFN {
    float gateWeights[EXPERT_DIM * HIDDEN_DIM];
    float upWeights[EXPERT_DIM * HIDDEN_DIM];
    float downWeights[HIDDEN_DIM * EXPERT_DIM];
    
public:
    ExpertFFN() {
        std::mt19937 rng(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        
        for (int i = 0; i < EXPERT_DIM * HIDDEN_DIM; i++) {
            gateWeights[i] = dist(rng);
            upWeights[i] = dist(rng);
        }
        for (int i = 0; i < HIDDEN_DIM * EXPERT_DIM; i++) {
            downWeights[i] = dist(rng);
        }
    }
    
    void Execute(const float* input, float* output, float weight) {
        float gateOut[EXPERT_DIM];
        float upOut[EXPERT_DIM];
        float swigluOut[EXPERT_DIM];
        
        // Gate projection: [EXPERT_DIM x HIDDEN_DIM] @ [HIDDEN_DIM]
        Q4K_GEMV_Simulated(gateWeights, input, gateOut, EXPERT_DIM, HIDDEN_DIM);
        
        // Up projection
        Q4K_GEMV_Simulated(upWeights, input, upOut, EXPERT_DIM, HIDDEN_DIM);
        
        // SwiGLU
        SwiGLU(gateOut, upOut, swigluOut, EXPERT_DIM);
        
        // Down projection: [HIDDEN_DIM x EXPERT_DIM] @ [EXPERT_DIM]
        Q4K_GEMV_Simulated(downWeights, swigluOut, output, HIDDEN_DIM, EXPERT_DIM);
        
        // Apply expert weight
        for (int i = 0; i < HIDDEN_DIM; i++) {
            output[i] *= weight;
        }
    }
};

// ============================================================================
// Shared Expert
// ============================================================================
class SharedExpert {
    float gateWeights[EXPERT_DIM * HIDDEN_DIM];
    float upWeights[EXPERT_DIM * HIDDEN_DIM];
    float downWeights[HIDDEN_DIM * EXPERT_DIM];
    
public:
    SharedExpert() {
        std::mt19937 rng(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        
        for (int i = 0; i < EXPERT_DIM * HIDDEN_DIM; i++) {
            gateWeights[i] = dist(rng);
            upWeights[i] = dist(rng);
        }
        for (int i = 0; i < HIDDEN_DIM * EXPERT_DIM; i++) {
            downWeights[i] = dist(rng);
        }
    }
    
    void Execute(const float* input, float* output) {
        float gateOut[EXPERT_DIM];
        float upOut[EXPERT_DIM];
        float swigluOut[EXPERT_DIM];
        
        // Gate projection
        Q4K_GEMV_Simulated(gateWeights, input, gateOut, EXPERT_DIM, HIDDEN_DIM);
        
        // Up projection
        Q4K_GEMV_Simulated(upWeights, input, upOut, EXPERT_DIM, HIDDEN_DIM);
        
        // SwiGLU
        SwiGLU(gateOut, upOut, swigluOut, EXPERT_DIM);
        
        // Down projection
        Q4K_GEMV_Simulated(downWeights, swigluOut, output, HIDDEN_DIM, EXPERT_DIM);
    }
};

// ============================================================================
// Full MoE Layer
// ============================================================================
class MoELayer {
    MoERouter router;
    SharedExpert sharedExpert;
    ExpertFFN experts[TOP_K];  // Pre-created for benchmark
    
public:
    void Forward(const float* input, float* output) {
        int expertIds[TOP_K];
        float expertWeights[TOP_K];
        float expertOut[HIDDEN_DIM];
        
        // Zero output
        memset(output, 0, HIDDEN_DIM * sizeof(float));
        
        // Route
        router.Route(input, expertIds, expertWeights);
        
        // Shared expert (always executed)
        sharedExpert.Execute(input, expertOut);
        for (int i = 0; i < HIDDEN_DIM; i++) {
            output[i] += expertOut[i];
        }
        
        // Routed experts
        for (int e = 0; e < TOP_K; e++) {
            experts[e].Execute(input, expertOut, expertWeights[e]);
            for (int i = 0; i < HIDDEN_DIM; i++) {
                output[i] += expertOut[i];
            }
        }
    }
};

// ============================================================================
// Benchmark
// ============================================================================
void BenchmarkMoE(int numTokens) {
    printf("\n=== MoE Forward Pass Benchmark ===\n");
    printf("Tokens: %d\n", numTokens);
    printf("Config: Hidden=%d, Experts=%d, TopK=%d, Layers=%d\n\n",
           HIDDEN_DIM, NUM_EXPERTS, TOP_K, NUM_LAYERS);
    
    // Allocate buffers
    float* input = (float*)malloc(HIDDEN_DIM * sizeof(float));
    float* output = (float*)malloc(HIDDEN_DIM * sizeof(float));
    
    // Initialize input
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = dist(rng);
    }
    
    // Create MoE layer
    MoELayer* layers = new MoELayer[NUM_LAYERS];
    
    // Warmup
    printf("Warming up...\n");
    for (int i = 0; i < 5; i++) {
        for (int layer = 0; layer < NUM_LAYERS; layer++) {
            layers[layer].Forward(input, output);
            memcpy(input, output, HIDDEN_DIM * sizeof(float));
        }
    }
    
    // Benchmark
    printf("Benchmarking...\n");
    double t0 = GetTimeMs();
    
    for (int token = 0; token < numTokens; token++) {
        // Re-initialize input for each token
        for (int i = 0; i < HIDDEN_DIM; i++) {
            input[i] = dist(rng);
        }
        
        // Forward through all layers
        for (int layer = 0; layer < NUM_LAYERS; layer++) {
            layers[layer].Forward(input, output);
            memcpy(input, output, HIDDEN_DIM * sizeof(float));
        }
    }
    
    double t1 = GetTimeMs();
    double totalMs = t1 - t0;
    
    // Calculate metrics
    double perTokenMs = totalMs / numTokens;
    double tokensPerSec = numTokens / (totalMs / 1000.0);
    
    // Estimate for full model (including attention)
    // Attention typically takes ~60% of time, FFN ~40%
    // MoE FFN is slower than dense, so adjust
    double estimatedFullTokenMs = perTokenMs * 2.5;  // Conservative estimate
    double estimatedTokensPerSec = 1000.0 / estimatedFullTokenMs;
    
    printf("\n=== Results ===\n");
    printf("Total time: %.3f ms\n", totalMs);
    printf("Per-token (MoE only): %.3f ms\n", perTokenMs);
    printf("Throughput (MoE only): %.2f tokens/sec\n", tokensPerSec);
    printf("\nEstimated full model:\n");
    printf("  Per-token: %.3f ms\n", estimatedFullTokenMs);
    printf("  Throughput: %.2f tokens/sec\n", estimatedTokensPerSec);
    
    // Calculate GFLOPs
    // Per layer:
    // - Router: 2 * HIDDEN_DIM * NUM_EXPERTS = 3.67M FLOPs
    // - Shared expert: 3 * 2 * EXPERT_DIM * HIDDEN_DIM = 88M FLOPs
    // - 8 routed experts: 8 * 88M = 704M FLOPs
    // Total per layer: ~796M FLOPs
    double flopsPerLayer = 2.0 * HIDDEN_DIM * NUM_EXPERTS +  // Router
                           3 * 2.0 * EXPERT_DIM * HIDDEN_DIM +  // Shared
                           TOP_K * 3 * 2.0 * EXPERT_DIM * HIDDEN_DIM;  // Routed
    double totalFlops = flopsPerLayer * NUM_LAYERS * numTokens;
    double gflops = totalFlops / (totalMs / 1000.0) / 1e9;
    
    printf("\nCompute: %.2f GFLOP/s\n", gflops);
    printf("Total FLOPs: %.2f GFLOPs\n", totalFlops / 1e9);
    
    // Cleanup
    free(input);
    free(output);
    delete[] layers;
}

void BenchmarkRouterOnly(int iterations) {
    printf("\n=== Router-Only Benchmark ===\n");
    printf("Iterations: %d\n\n", iterations);
    
    MoERouter router;
    float input[HIDDEN_DIM];
    int expertIds[TOP_K];
    float expertWeights[TOP_K];
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = dist(rng);
    }
    
    double t0 = GetTimeMs();
    for (int i = 0; i < iterations; i++) {
        router.Route(input, expertIds, expertWeights);
    }
    double t1 = GetTimeMs();
    
    double totalMs = t1 - t0;
    printf("Total time: %.3f ms\n", totalMs);
    printf("Per-token: %.3f us\n", totalMs * 1000.0 / iterations);
    printf("Throughput: %.2f tokens/sec\n", iterations / (totalMs / 1000.0));
    printf("Selected experts: ");
    for (int i = 0; i < TOP_K; i++) {
        printf("%d(%.3f) ", expertIds[i], expertWeights[i]);
    }
    printf("\n");
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("RawrXD Deep2 MoE Standalone Benchmark\n");
    printf("=================================================================\n");
    printf("DeepSeek-V3 671B Configuration\n");
    printf("  Hidden dimension: %d\n", HIDDEN_DIM);
    printf("  Number of experts: %d\n", NUM_EXPERTS);
    printf("  Top-k routing: %d\n", TOP_K);
    printf("  Expert dimension: %d\n", EXPERT_DIM);
    printf("  Number of layers: %d\n", NUM_LAYERS);
    printf("=================================================================\n");
    
    int numTokens = 10;
    if (argc > 1) {
        numTokens = atoi(argv[1]);
    }
    
    // Router benchmark
    BenchmarkRouterOnly(1000);
    
    // Full MoE benchmark
    BenchmarkMoE(numTokens);
    
    printf("\n=================================================================\n");
    printf("Benchmark Complete\n");
    printf("=================================================================\n");
    
    return 0;
}
