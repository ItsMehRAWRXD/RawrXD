// test_generate_token.cpp - Minimal test: load GGUF and generate ONE token
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include "Deep2Engine.h"

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1] : "G:\\OllamaModels\\Codestral-22B-v0.1-Q4_K_M.gguf";

    printf("[TEST] Token Generation Test\n");
    printf("[TEST] Model: %s\n", modelPath);

    Deep2Engine engine;
    EngineConfig cfg;
    cfg.hiddenDim = 6144;
    cfg.numLayers = 56;
    cfg.numHeads = 48;
    cfg.numKVHeads = 8;
    cfg.vocabSize = 32768;
    cfg.maxSeqLen = 4096;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 16;

    printf("[TEST] Initializing engine (dim=%zu, layers=%zu, heads=%zu)...\n",
           cfg.hiddenDim, cfg.numLayers, cfg.numHeads);
    if (!engine.initialize(cfg)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }
    printf("[PASS] Engine initialized\n");

    printf("[TEST] Loading model...\n");
    if (!engine.loadModel(modelPath)) {
        printf("[FAIL] loadModel() returned false\n");
        return 1;
    }
    printf("[PASS] Model loaded: %zu tensors, vocab=%zu\n",
           engine.getModelWeights().numLayers,
           engine.getModelWeights().vocabSize);

    // Tokenize a simple prompt
    std::string prompt = "Hello";
    printf("[TEST] Tokenizing prompt: '%s'\n", prompt.c_str());
    std::vector<int> tokens = engine.tokenize(prompt);
    printf("[PASS] Tokenized to %zu tokens\n", tokens.size());

    // Generate ONE token
    printf("[TEST] Generating 1 token...\n");
    std::vector<int> outputTokens(1);
    size_t generated = engine.generate(tokens.data(), tokens.size(),
                                        outputTokens.data(), 1);
    if (generated == 0) {
        printf("[FAIL] generate() returned 0 tokens\n");
        return 1;
    }

    printf("[PASS] Generated token ID: %d\n", outputTokens[0]);

    // Detokenize
    std::vector<int> singleToken = {outputTokens[0]};
    std::string text = engine.detokenize(singleToken);
    printf("[PASS] Detokenized: '%s'\n", text.c_str());

    printf("\n=== TOKEN GENERATION SUCCESS ===\n");
    printf("Prompt: '%s' -> Generated token: %d ('%s')\n",
           prompt.c_str(), outputTokens[0], text.c_str());

    return 0;
}
