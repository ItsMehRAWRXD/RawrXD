// ============================================================================
// moe_simple_bench.cpp - Simplified MoE Benchmark
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <chrono>

#define HIDDEN_DIM 7168
#define NUM_EXPERTS 256
#define TOP_K 8

using namespace std::chrono;

inline double GetTimeMs() {
    return duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count() / 1000.0;
}

// Simple router benchmark
void BenchmarkRouter(int iterations) {
    printf("Router Benchmark (%d iterations)...\n", iterations);
    
    float hiddenState[HIDDEN_DIM];
    float routerWeights[HIDDEN_DIM * NUM_EXPERTS];
    float logits[NUM_EXPERTS];
    
    // Initialize
    for (int i = 0; i < HIDDEN_DIM; i++) hiddenState[i] = 0.01f;
    for (int i = 0; i < HIDDEN_DIM * NUM_EXPERTS; i++) routerWeights[i] = 0.001f;
    
    double t0 = GetTimeMs();
    
    for (int iter = 0; iter < iterations; iter++) {
        // Compute logits
        for (int e = 0; e < NUM_EXPERTS; e++) {
            float sum = 0.0f;
            for (int h = 0; h < HIDDEN_DIM; h++) {
                sum += hiddenState[h] * routerWeights[e * HIDDEN_DIM + h];
            }
            logits[e] = sum;
        }
        
        // Simple softmax
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
    }
    
    double t1 = GetTimeMs();
    double totalMs = t1 - t0;
    
    printf("  Total: %.3f ms\n", totalMs);
    printf("  Per token: %.3f us\n", totalMs * 1000.0 / iterations);
    printf("  Throughput: %.2f tokens/sec\n\n", iterations / (totalMs / 1000.0));
}

// Simple expert benchmark
void BenchmarkExpert(int iterations) {
    printf("Expert FFN Benchmark (%d iterations)...\n", iterations);
    
    const int EXPERT_DIM = 2048;
    float input[HIDDEN_DIM];
    float gateOut[EXPERT_DIM];
    float upOut[EXPERT_DIM];
    float output[HIDDEN_DIM];
    
    // Initialize
    for (int i = 0; i < HIDDEN_DIM; i++) input[i] = 0.01f;
    
    double t0 = GetTimeMs();
    
    for (int iter = 0; iter < iterations; iter++) {
        // Gate projection: [EXPERT_DIM x HIDDEN_DIM] @ [HIDDEN_DIM]
        for (int r = 0; r < EXPERT_DIM; r++) {
            float sum = 0.0f;
            for (int c = 0; c < HIDDEN_DIM; c++) {
                sum += input[c] * 0.001f; // Simulated weight
            }
            gateOut[r] = sum;
        }
        
        // Up projection
        for (int r = 0; r < EXPERT_DIM; r++) {
            float sum = 0.0f;
            for (int c = 0; c < HIDDEN_DIM; c++) {
                sum += input[c] * 0.001f;
            }
            upOut[r] = sum;
        }
        
        // SwiGLU
        for (int i = 0; i < EXPERT_DIM; i++) {
            float silu = gateOut[i] / (1.0f + expf(-gateOut[i]));
            gateOut[i] = silu * upOut[i];
        }
        
        // Down projection: [HIDDEN_DIM x EXPERT_DIM] @ [EXPERT_DIM]
        for (int r = 0; r < HIDDEN_DIM; r++) {
            float sum = 0.0f;
            for (int c = 0; c < EXPERT_DIM; c++) {
                sum += gateOut[c] * 0.001f;
            }
            output[r] = sum;
        }
    }
    
    double t1 = GetTimeMs();
    double totalMs = t1 - t0;
    
    printf("  Total: %.3f ms\n", totalMs);
    printf("  Per expert: %.3f ms\n", totalMs / iterations);
    printf("  Throughput: %.2f experts/sec\n\n", iterations / (totalMs / 1000.0));
}

// Full MoE layer
void BenchmarkFullMoE(int iterations) {
    printf("Full MoE Layer Benchmark (%d iterations)...\n", iterations);
    
    const int EXPERT_DIM = 2048;
    float input[HIDDEN_DIM];
    float output[HIDDEN_DIM];
    float expertOut[HIDDEN_DIM];
    float routerWeights[HIDDEN_DIM * NUM_EXPERTS];
    float logits[NUM_EXPERTS];
    
    // Initialize
    for (int i = 0; i < HIDDEN_DIM; i++) input[i] = 0.01f;
    for (int i = 0; i < HIDDEN_DIM * NUM_EXPERTS; i++) routerWeights[i] = 0.001f;
    
    double t0 = GetTimeMs();
    
    for (int iter = 0; iter < iterations; iter++) {
        // Router
        for (int e = 0; e < NUM_EXPERTS; e++) {
            float sum = 0.0f;
            for (int h = 0; h < HIDDEN_DIM; h++) {
                sum += input[h] * routerWeights[e * HIDDEN_DIM + h];
            }
            logits[e] = sum;
        }
        
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
        
        // Zero output
        for (int i = 0; i < HIDDEN_DIM; i++) output[i] = 0.0f;
        
        // Shared expert (simplified)
        for (int i = 0; i < HIDDEN_DIM; i++) {
            output[i] += input[i] * 0.5f;
        }
        
        // Top-8 experts (simplified)
        for (int e = 0; e < TOP_K; e++) {
            // Simulate expert FFN
            float gateOut[EXPERT_DIM];
            float upOut[EXPERT_DIM];
            
            for (int r = 0; r < EXPERT_DIM; r++) {
                float sum = 0.0f;
                for (int c = 0; c < HIDDEN_DIM; c++) {
                    sum += input[c] * 0.001f;
                }
                gateOut[r] = sum;
            }
            
            for (int r = 0; r < EXPERT_DIM; r++) {
                float sum = 0.0f;
                for (int c = 0; c < HIDDEN_DIM; c++) {
                    sum += input[c] * 0.001f;
                }
                upOut[r] = sum;
            }
            
            for (int i = 0; i < EXPERT_DIM; i++) {
                float silu = gateOut[i] / (1.0f + expf(-gateOut[i]));
                gateOut[i] = silu * upOut[i];
            }
            
            for (int r = 0; r < HIDDEN_DIM; r++) {
                float sum = 0.0f;
                for (int c = 0; c < EXPERT_DIM; c++) {
                    sum += gateOut[c] * 0.001f;
                }
                expertOut[r] = sum * logits[e]; // Weighted
            }
            
            for (int i = 0; i < HIDDEN_DIM; i++) {
                output[i] += expertOut[i];
            }
        }
    }
    
    double t1 = GetTimeMs();
    double totalMs = t1 - t0;
    
    printf("  Total: %.3f ms\n", totalMs);
    printf("  Per token: %.3f ms\n", totalMs / iterations);
    printf("  Throughput: %.2f tokens/sec\n", iterations / (totalMs / 1000.0));
    printf("  (Simulating %d layers: %.2f tokens/sec)\n\n", 61, iterations / (totalMs / 1000.0) / 61);
}

int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("RawrXD MoE Simple Benchmark\n");
    printf("=================================================================\n");
    printf("Config: Hidden=%d, Experts=%d, TopK=%d\n\n", HIDDEN_DIM, NUM_EXPERTS, TOP_K);
    
    int iterations = 100;
    if (argc > 1) iterations = atoi(argv[1]);
    
    BenchmarkRouter(iterations * 10);
    BenchmarkExpert(iterations);
    BenchmarkFullMoE(iterations / 10);
    
    printf("=================================================================\n");
    printf("Benchmark Complete\n");
    printf("=================================================================\n");
    
    return 0;
}
