// ============================================================================
// deep2_production_bench.cpp - Production Deep2 Engine Benchmark
// Tests: ThreadPool + KVCache + Full Transformer Stack
// ============================================================================

#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <thread>

using namespace Deep2;

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Deep2 Production Engine Benchmark\n");
    printf("ThreadPool + KVCache + Transformer Stack\n");
    printf("========================================\n\n");
    
    // Parse arguments
    size_t hiddenDim = 4096;
    size_t numLayers = 32;
    size_t numHeads = 32;
    size_t numTokens = 100;
    bool useKVCache = true;
    bool useThreadPool = true;
    
    if (argc > 1) hiddenDim = atoi(argv[1]);
    if (argc > 2) numLayers = atoi(argv[2]);
    if (argc > 3) numTokens = atoi(argv[3]);
    if (argc > 4) useKVCache = atoi(argv[4]) != 0;
    if (argc > 5) useThreadPool = atoi(argv[5]) != 0;
    
    printf("Configuration:\n");
    printf("  Hidden Dim: %zu\n", hiddenDim);
    printf("  Num Layers: %zu\n", numLayers);
    printf("  Num Heads: %zu\n", numHeads);
    printf("  Tokens: %zu\n", numTokens);
    printf("  KV Cache: %s\n", useKVCache ? "ON" : "OFF");
    printf("  ThreadPool: %s\n\n", useThreadPool ? "ON" : "OFF");
    
    // Configure engine
    EngineConfig config;
    config.hiddenDim = hiddenDim;
    config.numLayers = numLayers;
    config.numHeads = numHeads;
    config.maxSeqLen = 2048;
    config.useKVCache = useKVCache;
    config.useThreadPool = useThreadPool;
    
    // Initialize engine
    Deep2Engine engine;
    if (!engine.initialize(config)) {
        printf("ERROR: Failed to initialize engine\n");
        return 1;
    }
    
    // Dummy prompt
    int promptTokens[] = {1, 2, 3, 4, 5};
    size_t promptLen = 5;
    
    // Allocate output buffer
    int* outputTokens = new int[numTokens];
    
    // Warmup
    printf("Warming up...\n");
    engine.reset();
    InferenceStats warmupStats;
    engine.generate(promptTokens, promptLen, outputTokens, 10, &warmupStats);
    
    // Benchmark
    printf("Running benchmark...\n");
    engine.reset();
    
    InferenceStats stats;
    size_t generated = engine.generate(promptTokens, promptLen, outputTokens, numTokens, &stats);
    
    // Print results
    printf("\n========================================\n");
    printf("BENCHMARK RESULTS\n");
    printf("========================================\n");
    printf("Tokens Generated:    %zu\n", generated);
    printf("Total Time:          %.2f ms\n", stats.latencyMs * generated);
    printf("Tokens/Second:       %.2f\n", stats.tokensPerSecond);
    printf("Latency/Token:       %.2f ms\n", stats.latencyMs);
    printf("========================================\n");
    
    // Calculate model size
    size_t paramsPerLayer = hiddenDim * hiddenDim * 4 +  // Attention weights
                           hiddenDim * 4 * hiddenDim * 3; // FFN weights
    size_t totalParams = paramsPerLayer * numLayers + hiddenDim * 32000; // + embeddings
    double modelSizeGB = (double)totalParams * 4 / (1024 * 1024 * 1024);
    
    printf("Model Size:          %.2f GB\n", modelSizeGB);
    printf("Params:              %.1f B\n", (double)totalParams / 1e9);
    printf("Memory Bandwidth:    %.2f GB/s (theoretical)\n", 
           stats.tokensPerSecond * modelSizeGB);
    printf("========================================\n");
    
    // Export to CSV
    FILE* csv = fopen("deep2_production_results.csv", "w");
    if (csv) {
        fprintf(csv, "Metric,Value,Unit\n");
        fprintf(csv, "HiddenDim,%zu,\n", hiddenDim);
        fprintf(csv, "NumLayers,%zu,\n", numLayers);
        fprintf(csv, "NumHeads,%zu,\n", numHeads);
        fprintf(csv, "UseKVCache,%s,\n", useKVCache ? "YES" : "NO");
        fprintf(csv, "UseThreadPool,%s,\n", useThreadPool ? "YES" : "NO");
        fprintf(csv, "TokensGenerated,%zu,\n", generated);
        fprintf(csv, "TokensPerSecond,%.2f,tokens/sec\n", stats.tokensPerSecond);
        fprintf(csv, "LatencyPerToken,%.2f,ms\n", stats.latencyMs);
        fprintf(csv, "ModelSizeGB,%.2f,GB\n", modelSizeGB);
        fprintf(csv, "TotalParams,%.1f,B\n", (double)totalParams / 1e9);
        fclose(csv);
        printf("\nResults exported to: deep2_production_results.csv\n");
    }
    
    // Cleanup
    delete[] outputTokens;
    
    printf("\nBenchmark complete!\n");
    return 0;
}
