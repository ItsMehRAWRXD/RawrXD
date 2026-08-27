// ============================================================================
// Deep2_Elastic_Generation_Test.cpp
// Full inference integration: real GGUF → Deep2Engine.generate() with
// ElasticResidencyManager managing all weight tensors across the full
// prefill + decode loop.
//
// Usage: Deep2_Elastic_Generation_Test.exe [path_to.gguf] [prompt]
// ============================================================================

#include "Deep2Engine.h"
#include "ElasticResidencyManager.hpp"
#include "QuantKernelRegistry.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <vector>
#include <string>

using namespace Deep2;

// Stub ResidencyTrace C interface (no ASM dependency)
extern "C" {
    int TraceInit(const char*) { return 1; }
    void TraceShutdown(void) {}
    struct ResidencyEvent { uint32_t dummy; };
    ResidencyEvent* TraceBegin(uint32_t, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t) { return nullptr; }
    void TraceSetDestination(ResidencyEvent*, uint32_t, uint64_t, uint64_t, uint64_t, uint32_t, uint32_t) {}
    void TraceComplete(ResidencyEvent*, uint64_t, uint64_t, int) {}
    void TraceFlush(void) {}
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1] : "G:\\Franken\\BackwardsUnlock\\1b\\unlock-1B-Q4_K_M.gguf";
    const char* prompt = argc > 2 ? argv[2] : "Hello";

    printf("=================================================================\n");
    printf(" Deep2Engine.generate() + ElasticResidencyManager Integration\n");
    printf("=================================================================\n");
    printf("Model: %s\n", modelPath);
    printf("Prompt: \"%s\"\n\n", prompt);

    // --- Step 1: Create and initialize engine ---
    printf("[Step 1] Creating Deep2Engine...\n");
    Deep2Engine engine;
    EngineConfig config;
    config.numThreads = 4;
    if (!engine.initialize(config)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }
    printf("[PASS] Engine initialized\n");

    // --- Step 2: Load model ---
    printf("\n[Step 2] Loading GGUF model...\n");
    if (!engine.loadModel(modelPath)) {
        printf("[FAIL] Model load failed\n");
        return 1;
    }
    if (!engine.isModelLoaded()) {
        printf("[FAIL] Model not loaded after loadModel()\n");
        return 1;
    }
    printf("[PASS] Model loaded\n");
    printf("  Layers: %zu, Hidden: %zu, Vocab: %zu\n",
           engine.getModelWeights().numLayers,
           engine.getModelWeights().hiddenDim,
           engine.getModelWeights().vocabSize);

    // --- Step 3: Enable ElasticResidencyManager ---
    printf("\n[Step 3] Enabling ElasticResidencyManager...\n");
    engine.enableElasticResidency(true);
    if (!engine.isElasticResidencyEnabled()) {
        printf("[FAIL] Elastic residency not enabled\n");
        return 1;
    }
    printf("[PASS] Elastic residency enabled\n");

    // --- Step 4: Tokenize prompt ---
    printf("\n[Step 4] Tokenizing prompt...\n");
    std::vector<int> promptTokens = engine.tokenize(prompt);
    if (promptTokens.empty()) {
        printf("[FAIL] Tokenization produced no tokens\n");
        return 1;
    }
    printf("[PASS] Tokenized to %zu tokens: ", promptTokens.size());
    for (size_t i = 0; i < promptTokens.size() && i < 10; ++i) {
        printf("%d ", promptTokens[i]);
    }
    printf("...\n");

    // --- Step 5: Generate tokens ---
    printf("\n[Step 5] Generating tokens...\n");
    const size_t maxTokens = 16;
    std::vector<int> outputTokens(maxTokens, 0);
    InferenceStats stats;

    auto t0 = std::chrono::steady_clock::now();
    size_t generated = engine.generate(
        promptTokens.data(), promptTokens.size(),
        outputTokens.data(), maxTokens,
        &stats,
        [](int token) {
            printf("  token=%d\n", token);
            return true;  // continue generation
        }
    );
    auto t1 = std::chrono::steady_clock::now();
    double msTotal = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // --- Step 6: Validate generation ---
    printf("\n[Step 6] Validating generation...\n");
    if (generated == 0) {
        printf("[FAIL] No tokens generated\n");
        return 1;
    }
    printf("[PASS] Generated %zu tokens in %.2f ms (%.2f TPS)\n",
           generated, msTotal, stats.tokensPerSecond);

    // Check for all-zeros or all-same (indicates a bug)
    bool allSame = true;
    bool allZero = true;
    for (size_t i = 0; i < generated; ++i) {
        if (outputTokens[i] != 0) allZero = false;
        if (i > 0 && outputTokens[i] != outputTokens[0]) allSame = false;
    }
    if (allZero) {
        printf("[FAIL] All generated tokens are zero\n");
        return 1;
    }
    if (allSame && generated > 3) {
        printf("[WARN] All generated tokens are identical (possible bug)\n");
    }

    // --- Step 7: Detokenize and print ---
    printf("\n[Step 7] Detokenizing output...\n");
    std::vector<int> fullSequence = promptTokens;
    fullSequence.insert(fullSequence.end(), outputTokens.begin(), outputTokens.begin() + generated);
    std::string generatedText = engine.detokenize(fullSequence);
    printf("Generated text: \"%s\"\n", generatedText.c_str());

    // --- Step 8: Residency telemetry ---
    printf("\n[Step 8] Residency telemetry:\n");
    auto* erm = engine.getElasticResidencyManager();
    if (erm) {
        auto& telem = erm->GetTelemetry();
        printf("  Ghost hits:   %llu\n", (unsigned long long)telem.ghostHits.load());
        printf("  Ghost misses: %llu\n", (unsigned long long)telem.ghostMisses.load());
    } else {
        printf("  (ElasticResidencyManager not available)\n");
    }

    // --- Step 9: Batch 21 telemetry ---
    printf("\n[Step 9] Batch 21 telemetry:\n");
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    reg.PrintBatch21Report();

    // --- Cleanup ---
    engine.unloadModel();

    printf("\n=================================================================\n");
    printf(" PASS: Full generation with ElasticResidencyManager\n");
    printf(" Tokens: %zu | Time: %.2f ms | TPS: %.2f\n", generated, msTotal, stats.tokensPerSecond);
    printf("=================================================================\n");
    return 0;
}
