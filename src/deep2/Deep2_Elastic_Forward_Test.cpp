// ============================================================================
// Deep2_Elastic_Forward_Test.cpp
// Minimal integration test: real GGUF → Deep2Engine → ElasticResidencyManager
// → real forwardLayer() under memory pressure.
//
// Usage: Deep2_Elastic_Forward_Test.exe [path_to.gguf]
// ============================================================================

#include "Deep2Engine.h"
#include "ElasticResidencyManager.hpp"
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

    printf("=================================================================\n");
    printf(" Deep2Engine + ElasticResidencyManager Forward Pass Test\n");
    printf("=================================================================\n");
    printf("Model: %s\n\n", modelPath);

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

    // --- Step 3: Enable ElasticResidencyManager with pressure budget ---
    printf("\n[Step 3] Enabling ElasticResidencyManager (pressure mode)...\n");
    engine.enableElasticResidency(true);
    if (!engine.isElasticResidencyEnabled()) {
        printf("[FAIL] Elastic residency not enabled\n");
        return 1;
    }
    printf("[PASS] Elastic residency enabled\n");

    // --- Step 4: Allocate input/output buffers ---
    size_t hiddenDim = engine.getConfig().hiddenDim;
    std::vector<float> input(hiddenDim, 0.0f);
    std::vector<float> output(hiddenDim, 0.0f);

    // Use a simple pattern: token 42 embedding index
    if (hiddenDim > 0) input[0] = 1.0f;

    // --- Step 5: Run forward pass on layer 0 (cold) ---
    printf("\n[Step 4] Forward pass layer 0 (cold)...\n");
    auto t0 = std::chrono::steady_clock::now();
    engine.forwardLayerPublic(0, input.data(), output.data(), 1);
    auto t1 = std::chrono::steady_clock::now();
    double msCold = std::chrono::duration<double, std::milli>(t1 - t0).count();
    printf("  Cold pass: %.2f ms\n", msCold);

    // Validate output
    bool outputValid = true;
    size_t nonzero = 0;
    for (size_t i = 0; i < hiddenDim; ++i) {
        if (!std::isfinite(output[i])) { outputValid = false; break; }
        if (output[i] != 0.0f) ++nonzero;
    }
    if (!outputValid) {
        printf("[FAIL] Layer 0 output contains non-finite values\n");
        return 1;
    }
    if (nonzero == 0) {
        printf("[FAIL] Layer 0 output is all zeros\n");
        return 1;
    }
    printf("[PASS] Layer 0 output valid: %zu/%zu non-zero\n", nonzero, hiddenDim);

    // --- Step 6: Run forward pass again (warm / potential GhostCache) ---
    printf("\n[Step 5] Forward pass layer 0 (warm)...\n");
    std::fill(output.begin(), output.end(), 0.0f);
    t0 = std::chrono::steady_clock::now();
    engine.forwardLayerPublic(0, input.data(), output.data(), 1);
    t1 = std::chrono::steady_clock::now();
    double msWarm = std::chrono::duration<double, std::milli>(t1 - t0).count();
    printf("  Warm pass: %.2f ms\n", msWarm);

    // Validate output again
    outputValid = true;
    nonzero = 0;
    for (size_t i = 0; i < hiddenDim; ++i) {
        if (!std::isfinite(output[i])) { outputValid = false; break; }
        if (output[i] != 0.0f) ++nonzero;
    }
    if (!outputValid || nonzero == 0) {
        printf("[FAIL] Warm pass output invalid\n");
        return 1;
    }
    printf("[PASS] Warm pass output valid: %zu/%zu non-zero\n", nonzero, hiddenDim);

    // --- Step 7: Print residency telemetry ---
    printf("\n[Step 6] Residency telemetry:\n");
    auto* erm = engine.getElasticResidencyManager();
    if (erm) {
        auto& telem = erm->GetTelemetry();
        printf("  Ghost hits:   %llu\n", (unsigned long long)telem.ghostHits.load());
        printf("  Ghost misses: %llu\n", (unsigned long long)telem.ghostMisses.load());
    } else {
        printf("  (ElasticResidencyManager not available)\n");
    }

    // --- Cleanup ---
    engine.unloadModel();

    printf("\n=================================================================\n");
    printf(" PASS: Deep2Engine forwardLayer() with ElasticResidencyManager\n");
    printf(" Cold: %.2f ms | Warm: %.2f ms\n", msCold, msWarm);
    printf("=================================================================\n");
    return 0;
}
