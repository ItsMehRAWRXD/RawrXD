// Router latency test - minimal
#include <cstdio>
#include <cmath>
#include <chrono>

#define HIDDEN_DIM 7168
#define NUM_EXPERTS 256

int main() {
    printf("Router Latency Test\n");
    printf("Hidden=%d, Experts=%d\n\n", HIDDEN_DIM, NUM_EXPERTS);
    
    float hiddenState[HIDDEN_DIM];
    float routerWeights[HIDDEN_DIM * NUM_EXPERTS];
    float logits[NUM_EXPERTS];
    
    // Initialize
    for (int i = 0; i < HIDDEN_DIM; i++) hiddenState[i] = 0.01f;
    for (int i = 0; i < HIDDEN_DIM * NUM_EXPERTS; i++) routerWeights[i] = 0.001f;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    int iterations = 100;
    for (int iter = 0; iter < iterations; iter++) {
        // Compute logits
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
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double totalMs = duration.count() / 1000.0;
    
    printf("Iterations: %d\n", iterations);
    printf("Total time: %.3f ms\n", totalMs);
    printf("Per token: %.3f us\n", totalMs * 1000.0 / iterations);
    printf("Throughput: %.2f tokens/sec\n", iterations / (totalMs / 1000.0));
    
    return 0;
}
