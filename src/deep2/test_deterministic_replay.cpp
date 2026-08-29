// ============================================================================
// test_deterministic_replay.cpp
// STREAMER-CERT-001: Prove temperature=0 produces identical token sequences
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include "Deep2Engine.h"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Deep2;

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";

    printf("=== STREAMER-CERT-001: Deterministic Replay ===\n");
    printf("Model: %s\n", modelPath);

    Deep2Engine engine;
    if (!engine.loadModel(modelPath)) {
        printf("[FAIL] loadModel() returned false\n");
        return 1;
    }

    const auto& mw = engine.getModelWeights();
    EngineConfig cfg;
    cfg.hiddenDim   = mw.hiddenDim;
    cfg.numLayers   = mw.numLayers;
    cfg.numHeads    = mw.numHeads;
    cfg.numKVHeads  = mw.numKVHeads;
    cfg.headDim     = mw.headDim;
    cfg.vocabSize   = mw.vocabSize;
    cfg.maxSeqLen   = 4096;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;
    cfg.numThreads  = 16;

    if (!engine.initialize(cfg)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }

    std::string prompt = "hello";
    const size_t maxTokens = 15;

    // Run 1: temperature=0 (greedy)
    std::vector<int> tokens1(maxTokens);
    {
        GenerationOptions opt;
        opt.maxTokens = static_cast<uint32_t>(maxTokens);
        opt.temperature = 0.0f;
        opt.topK = 1;
        opt.topP = 1.0f;
        opt.seed = 42;

        std::string acc;
        engine.generateStream(prompt, opt, [&](int32_t tok, const std::string& piece) -> bool {
            acc += piece;
            return true;
        });

        // Also get raw tokens via generate()
        engine.reset();
        size_t n = engine.generate(
            engine.tokenize(prompt).data(),
            engine.tokenize(prompt).size(),
            tokens1.data(), maxTokens);
        tokens1.resize(n);
    }

    // Run 2: temperature=0 (greedy) again
    std::vector<int> tokens2(maxTokens);
    {
        engine.reset();
        size_t n = engine.generate(
            engine.tokenize(prompt).data(),
            engine.tokenize(prompt).size(),
            tokens2.data(), maxTokens);
        tokens2.resize(n);
    }

    printf("Run 1 tokens (%zu): ", tokens1.size());
    for (auto t : tokens1) printf("%d ", t);
    printf("\n");

    printf("Run 2 tokens (%zu): ", tokens2.size());
    for (auto t : tokens2) printf("%d ", t);
    printf("\n");

    bool match = (tokens1.size() == tokens2.size());
    if (match) {
        for (size_t i = 0; i < tokens1.size(); ++i) {
            if (tokens1[i] != tokens2[i]) {
                match = false;
                printf("[MISMATCH] at position %zu: run1=%d run2=%d\n",
                       i, tokens1[i], tokens2[i]);
                break;
            }
        }
    } else {
        printf("[MISMATCH] token count: run1=%zu run2=%zu\n",
               tokens1.size(), tokens2.size());
    }

    if (match) {
        printf("[PASS] Deterministic replay: %zu tokens identical\n", tokens1.size());
        return 0;
    } else {
        printf("[FAIL] Deterministic replay failed\n");
        return 1;
    }
}
