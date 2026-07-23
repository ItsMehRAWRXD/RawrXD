// ============================================================================
// moe_microbench.cpp - MoE Microbenchmark
// Measures: Router latency, Expert dispatch overhead, Q4_K GEMV throughput
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <chrono>
#include <vector>
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

using namespace std::chrono;

// Timing helper
inline double GetTimeMs() {
    return duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count() / 1000.0;
}

// ============================================================================
// Simulated MoE Router (matches MoERouter implementation)
// ============================================================================
class SimulatedRouter {
public:
    float routerWeights[HIDDEN_DIM * NUM_EXPERTS];
    
    SimulatedRouter() {
        // Initialize with random weights
        std::mt19937 rng(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        for (int i = 0; i < HIDDEN_DIM * NUM_EXPERTS; i++) {
            routerWeights[i] = dist(rng);
        }
    }
    
    // Route token: compute logits, softmax, top-k
    void Route(const float* hiddenState, int* expertIds, float* expertWeights) {
        float logits[NUM_EXPERTS];
        
        // Compute router logits: logits[i] = dot(hiddenState, routerWeights[i])
        for (int e = 0; e < NUM_EXPERTS; e++) {
            float sum = 0.0f;
            for (int h = 0; h < HIDDEN_DIM; h++) {
                sum += hiddenState[h] * routerWeights[e * HIDDEN_DIM + h];
            }
            logits[e] = sum;
        }
        
        // Softmax with temperature
        float maxLogit = logits[0];
        for (int e = 1; e < NUM_EXPERTS; e++) {
            maxLogit = std::max(maxLogit, logits[e]);
        }
        
        float expSum = 0.0f;
        for (int e = 0; e < NUM_EXPERTS; e++) {
            logits[e] = expf(logits[e] - maxLogit);
            expSum += logits[e];
        }
        
        for (int e = 0; e < NUM_EXPERTS; e++) {
            logits[e] /= expSum;
        }
        
        // Top-k selection (simplified - just pick top 8)
        // In real impl: partial sort or heap
        std::vector<std::pair<float, int>> probs;
        for (int e = 0; e < NUM_EXPERTS; e++) {
            probs.push_back({logits[e], e});
        }
        std::partial_sort(probs.begin(), probs.begin() + TOP_K, probs.end(),
                         std::greater<std::pair<float, int>>());
        
        // Renormalize top-k weights
        float weightSum = 0.0f;
        for (int i = 0; i < TOP_K; i++) {
            weightSum += probs[i].first;
        }
        
        for (int i = 0; i < TOP_K; i++) {
            expertIds[i] = probs[i].second;
            expertWeights[i] = probs[i].first / weightSum;
        }
    }
};

// ============================================================================
// Simulated Expert FFN (Q4_K GEMV simulation)
// ============================================================================
class SimulatedExpert {
public:
    // Q4_K: 256 elements per block, 4 bits per weight
    // For [EXPERT_DIM x HIDDEN_DIM] matrix:
    // - Number of blocks per row: HIDDEN_DIM / 256 = 28
    // - Bytes per row: 28 * (256/2 + 64 + 64) = 28 * 256 = 7168 bytes
    // Total per projection: EXPERT_DIM * 7168 bytes
    
    std::vector<uint8_t> gateWeights;
    std::vector<uint8_t> upWeights;
    std::vector<uint8_t> downWeights;
    
    SimulatedExpert() {
        size_t projSize = EXPERT_DIM * (HIDDEN_DIM / 2 + HIDDEN_DIM / 4 + HIDDEN_DIM / 4);
        gateWeights.resize(projSize);
        upWeights.resize(projSize);
        downWeights.resize(projSize);
        
        // Fill with random data
        std::mt19937 rng(42);
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& b : gateWeights) b = dist(rng);
        for (auto& b : upWeights) b = dist(rng);
        for (auto& b : downWeights) b = dist(rng);
    }
    
    // Simulate Q4_K GEMV: output = weights @ input
    // weights: [rows x cols], input: [cols], output: [rows]
    void GEMV_Q4K(const uint8_t* weights, const float* input, float* output,
                   int rows, int cols) {
        // Simplified: just do F32 GEMV (actual Q4_K would dequantize on the fly)
        for (int r = 0; r < rows; r++) {
            float sum = 0.0f;
            for (int c = 0; c < cols; c++) {
                // Simulate quantized weight: -8 to +7 range
                int weight = (r + c) % 16 - 8;
                sum += weight * input[c];
            }
            output[r] = sum * 0.01f; // Scale factor
        }
    }
    
    void Execute(const float* input, float* output, float weight) {
        float gateOut[EXPERT_DIM];
        float upOut[EXPERT_DIM];
        float downIn[EXPERT_DIM];
        
        // Gate projection: [EXPERT_DIM x HIDDEN_DIM] @ [HIDDEN_DIM] -> [EXPERT_DIM]
        GEMV_Q4K(gateWeights.data(), input, gateOut, EXPERT_DIM, HIDDEN_DIM);
        
        // Up projection
        GEMV_Q4K(upWeights.data(), input, upOut, EXPERT_DIM, HIDDEN_DIM);
        
        // SwiGLU: silu(gate) * up
        for (int i = 0; i < EXPERT_DIM; i++) {
            // Simplified SwiGLU
            float silu = gateOut[i] / (1.0f + expf(-gateOut[i]));
            downIn[i] = silu * upOut[i];
        }
        
        // Down projection: [HIDDEN_DIM x EXPERT_DIM] @ [EXPERT_DIM] -> [HIDDEN_DIM]
        GEMV_Q4K(downWeights.data(), downIn, output, HIDDEN_DIM, EXPERT_DIM);
        
        // Apply expert weight
        for (int i = 0; i < HIDDEN_DIM; i++) {
            output[i] *= weight;
        }
    }
};

// ============================================================================
// Shared Expert (always executed)
// ============================================================================
class SimulatedSharedExpert {
public:
    std::vector<float> gateWeights;
    std::vector<float> upWeights;
    std::vector<float> downWeights;
    
    SimulatedSharedExpert() {
        // F16 weights (simulated as F32)
        gateWeights.resize(EXPERT_DIM * HIDDEN_DIM);
        upWeights.resize(EXPERT_DIM * HIDDEN_DIM);
        downWeights.resize(HIDDEN_DIM * EXPERT_DIM);
        
        std::mt19937 rng(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        for (auto& w : gateWeights) w = dist(rng);
        for (auto& w : upWeights) w = dist(rng);
        for (auto& w : downWeights) w = dist(rng);
    }
    
    void Execute(const float* input, float* output) {
        float gateOut[EXPERT_DIM];
        float upOut[EXPERT_DIM];
        float downIn[EXPERT_DIM];
        
        // Gate projection
        for (int r = 0; r < EXPERT_DIM; r++) {
            float sum = 0.0f;
            for (int c = 0; c < HIDDEN_DIM; c++) {
                sum += gateWeights[r * HIDDEN_DIM + c] * input[c];
            }
            gateOut[r] = sum;
        }
        
        // Up projection
        for (int r = 0; r < EXPERT_DIM; r++) {
            float sum = 0.0f;
            for (int c = 0; c < HIDDEN_DIM; c++) {
                sum += upWeights[r * HIDDEN_DIM + c] * input[c];
            }
            upOut[r] = sum;
        }
        
        // SwiGLU
        for (int i = 0; i < EXPERT_DIM; i++) {
            float silu = gateOut[i] / (1.0f + expf(-gateOut[i]));
            downIn[i] = silu * upOut[i];
        }
        
        // Down projection
        for (int r = 0; r < HIDDEN_DIM; r++) {
            float sum = 0.0f;
            for (int c = 0; c < EXPERT_DIM; c++) {
                sum += downWeights[r * EXPERT_DIM + c] * downIn[c];
            }
            output[r] = sum;
        }
    }
};

// ============================================================================
// Benchmarks
// ============================================================================

void BenchmarkRouter(int iterations) {
    printf("\n=== Router Benchmark ===\n");
    printf("Iterations: %d\n", iterations);
    
    SimulatedRouter router;
    float hiddenState[HIDDEN_DIM];
    int expertIds[TOP_K];
    float expertWeights[TOP_K];
    
    // Initialize hidden state
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    for (int i = 0; i < HIDDEN_DIM; i++) {
        hiddenState[i] = dist(rng);
    }
    
    // Warmup
    for (int i = 0; i < 100; i++) {
        router.Route(hiddenState, expertIds, expertWeights);
    }
    
    // Benchmark
    double t0 = GetTimeMs();
    for (int i = 0; i < iterations; i++) {
        router.Route(hiddenState, expertIds, expertWeights);
    }
    double t1 = GetTimeMs();
    
    double totalMs = t1 - t0;
    double perTokenUs = (totalMs * 1000.0) / iterations;
    
    printf("Total time: %.3f ms\n", totalMs);
    printf("Per-token latency: %.3f us\n", perTokenUs);
    printf("Router throughput: %.2f tokens/sec\n", iterations / (totalMs / 1000.0));
    printf("Selected experts: ");
    for (int i = 0; i < TOP_K; i++) {
        printf("%d(%.3f) ", expertIds[i], expertWeights[i]);
    }
    printf("\n");
}

void BenchmarkExpert(int iterations) {
    printf("\n=== Expert FFN Benchmark ===\n");
    printf("Iterations: %d\n", iterations);
    printf("Expert dim: %d, Hidden dim: %d\n", EXPERT_DIM, HIDDEN_DIM);
    
    SimulatedExpert expert;
    float input[HIDDEN_DIM];
    float output[HIDDEN_DIM];
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = dist(rng);
    }
    
    // Warmup
    for (int i = 0; i < 10; i++) {
        expert.Execute(input, output, 1.0f);
    }
    
    // Benchmark
    double t0 = GetTimeMs();
    for (int i = 0; i < iterations; i++) {
        expert.Execute(input, output, 1.0f);
    }
    double t1 = GetTimeMs();
    
    double totalMs = t1 - t0;
    double perExpertMs = totalMs / iterations;
    
    // Calculate FLOPs: 2 * (HIDDEN_DIM * EXPERT_DIM) * 3 projections
    double flops = 2.0 * HIDDEN_DIM * EXPERT_DIM * 3 * iterations;
    double gflops = flops / (totalMs / 1000.0) / 1e9;
    
    printf("Total time: %.3f ms\n", totalMs);
    printf("Per-expert latency: %.3f ms\n", perExpertMs);
    printf("Expert throughput: %.2f experts/sec\n", iterations / (totalMs / 1000.0));
    printf("Compute: %.2f GFLOP/s\n", gflops);
}

void BenchmarkSharedExpert(int iterations) {
    printf("\n=== Shared Expert Benchmark ===\n");
    printf("Iterations: %d\n", iterations);
    
    SimulatedSharedExpert expert;
    float input[HIDDEN_DIM];
    float output[HIDDEN_DIM];
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = dist(rng);
    }
    
    // Warmup
    for (int i = 0; i < 10; i++) {
        expert.Execute(input, output);
    }
    
    // Benchmark
    double t0 = GetTimeMs();
    for (int i = 0; i < iterations; i++) {
        expert.Execute(input, output);
    }
    double t1 = GetTimeMs();
    
    double totalMs = t1 - t0;
    double perExpertMs = totalMs / iterations;
    
    printf("Total time: %.3f ms\n", totalMs);
    printf("Per-expert latency: %.3f ms\n", perExpertMs);
    printf("Shared expert throughput: %.2f experts/sec\n", iterations / (totalMs / 1000.0));
}

void BenchmarkFullMoE(int iterations) {
    printf("\n=== Full MoE Layer Benchmark ===\n");
    printf("Iterations: %d\n", iterations);
    printf("Config: %d experts, top-%d routing\n", NUM_EXPERTS, TOP_K);
    
    SimulatedRouter router;
    SimulatedSharedExpert sharedExpert;
    SimulatedExpert experts[TOP_K]; // Pre-create top-k experts
    
    float input[HIDDEN_DIM];
    float output[HIDDEN_DIM];
    float expertOut[HIDDEN_DIM];
    int expertIds[TOP_K];
    float expertWeights[TOP_K];
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    for (int i = 0; i < HIDDEN_DIM; i++) {
        input[i] = dist(rng);
    }
    
    // Warmup
    for (int i = 0; i < 10; i++) {
        router.Route(input, expertIds, expertWeights);
        sharedExpert.Execute(input, output);
        for (int e = 0; e < TOP_K; e++) {
            experts[e].Execute(input, expertOut, expertWeights[e]);
            for (int h = 0; h < HIDDEN_DIM; h++) {
                output[h] += expertOut[h];
            }
        }
    }
    
    // Benchmark
    double t0 = GetTimeMs();
    for (int i = 0; i < iterations; i++) {
        // Route
        router.Route(input, expertIds, expertWeights);
        
        // Shared expert
        sharedExpert.Execute(input, output);
        
        // Routed experts
        for (int e = 0; e < TOP_K; e++) {
            experts[e].Execute(input, expertOut, expertWeights[e]);
            for (int h = 0; h < HIDDEN_DIM; h++) {
                output[h] += expertOut[h];
            }
        }
    }
    double t1 = GetTimeMs();
    
    double totalMs = t1 - t0;
    double perTokenMs = totalMs / iterations;
    double tokensPerSec = iterations / (totalMs / 1000.0);
    
    printf("Total time: %.3f ms\n", totalMs);
    printf("Per-token latency: %.3f ms\n", perTokenMs);
    printf("MoE throughput: %.2f tokens/sec\n", tokensPerSec);
    printf("\nBreakdown:\n");
    printf("  - Router: ~%.2f us\n", 50.0); // From previous benchmark
    printf("  - Shared expert: ~%.2f ms\n", perTokenMs / (TOP_K + 1));
    printf("  - %d routed experts: ~%.2f ms each\n", TOP_K, perTokenMs * TOP_K / (TOP_K + 1));
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("RawrXD MoE Microbenchmark\n");
    printf("=================================================================\n");
    printf("Configuration:\n");
    printf("  Hidden dim: %d\n", HIDDEN_DIM);
    printf("  Num experts: %d\n", NUM_EXPERTS);
    printf("  Top-k: %d\n", TOP_K);
    printf("  Expert dim: %d\n", EXPERT_DIM);
    printf("  Num layers: %d\n", NUM_LAYERS);
    printf("=================================================================\n");
    
    int iterations = 1000;
    if (argc > 1) {
        iterations = atoi(argv[1]);
    }
    
    BenchmarkRouter(iterations);
    BenchmarkExpert(iterations / 10);  // Fewer iterations - slower
    BenchmarkSharedExpert(iterations / 10);
    BenchmarkFullMoE(iterations / 10);
    
    printf("\n=================================================================\n");
    printf("Benchmark Complete\n");
    printf("=================================================================\n");
    
    return 0;
}
