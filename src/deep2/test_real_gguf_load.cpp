// test_real_gguf_load.cpp - Minimal test: does Deep2Engine actually load the 23GB GGUF?
#include <cstdio>
#include <cstdlib>
#include "Deep2Engine.h"

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1] : "F:\\OllamaModels\\BigDaddyG-Q2_K-ULTRA.gguf";

    printf("[TEST] Loading real GGUF: %s\n", modelPath);

    Deep2Engine engine;
    EngineConfig cfg;
    cfg.hiddenDim = 7168;
    cfg.numLayers = 61;
    cfg.numHeads = 128;
    cfg.vocabSize = 129280;
    cfg.maxSeqLen = 4096;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 16;

    printf("[TEST] Initializing engine...\n");
    if (!engine.initialize(cfg)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }
    printf("[TEST] Engine initialized OK\n");

    printf("[TEST] Calling loadModel()...\n");
    bool ok = engine.loadModel(modelPath);
    if (!ok) {
        printf("[FAIL] loadModel() returned false\n");
        return 1;
    }

    printf("[PASS] loadModel() succeeded!\n");
    printf("[INFO] isModelLoaded: %s\n", engine.isModelLoaded() ? "YES" : "NO");
    printf("[INFO] numLayers: %zu\n", engine.getModelWeights().numLayers);
    printf("[INFO] hiddenDim: %zu\n", engine.getModelWeights().hiddenDim);
    printf("[INFO] vocabSize: %zu\n", engine.getModelWeights().vocabSize);
    printf("[INFO] isMoE: %s\n", engine.getModelWeights().isMoE ? "YES" : "NO");
    printf("[INFO] numExperts: %zu\n", engine.getModelWeights().numExperts);
    printf("[INFO] numExpertsPerToken: %zu\n", engine.getModelWeights().numExpertsPerToken);
    printf("[INFO] numSharedExperts: %zu\n", engine.getModelWeights().numSharedExperts);
    printf("[INFO] numTensors: %zu\n", engine.getModelWeights().layers.size());

    return 0;
}
