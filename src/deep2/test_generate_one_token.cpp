// test_generate_one_token.cpp - Minimal: load Codestral and generate 1 token
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cstring>
#include "Deep2Engine.h"
#include "gguf_embedded_tokenizer.hpp"

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1] : "G:\\OllamaModels\\Codestral-22B-v0.1-Q4_K_M.gguf";

    printf("[TEST] Token Generation Test\n");
    printf("[TEST] Model: %s\n", modelPath);

    // Load embedded tokenizer from GGUF
    RawrXD::GGUFEmbeddedTokenizer tokenizer;
    printf("[Tokenizer] Loading from GGUF...\n");
    if (!tokenizer.LoadFromGGUF(modelPath)) {
        printf("[FAIL] Failed to load embedded tokenizer from GGUF\n");
        return 1;
    }
    printf("[Tokenizer] source=GGUF\n");
    printf("[Tokenizer] vocab=%zu\n", tokenizer.VocabSize());
    printf("[Tokenizer] external_tokenizer=false\n");
    printf("[Tokenizer] EncodeLongestMatch=ready\n");
    printf("[Tokenizer] Decode=ready\n");

    Deep2Engine engine;

    printf("[TEST] Loading model to detect architecture...\n");
    if (!engine.loadModel(modelPath)) {
        printf("[FAIL] loadModel() returned false\n");
        return 1;
    }
    const auto& mw = engine.getModelWeights();
    printf("[PASS] Model loaded: hidden=%zu layers=%zu heads=%zu kv_heads=%zu headDim=%zu vocab=%zu\n",
           mw.hiddenDim, mw.numLayers, mw.numHeads, mw.numKVHeads, mw.headDim, mw.vocabSize);

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

    printf("[TEST] Initializing engine (dim=%zu, layers=%zu, heads=%zu, kv_heads=%zu, headDim=%zu)...\n",
           cfg.hiddenDim, cfg.numLayers, cfg.numHeads, cfg.numKVHeads, cfg.headDim);
    if (!engine.initialize(cfg)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }
    printf("[PASS] Engine initialized\n");

    // Tokenize a simple prompt using embedded tokenizer
    std::string prompt = "Hello";
    printf("[TEST] Tokenizing prompt: '%s'\n", prompt.c_str());
    std::vector<uint32_t> promptTokens;
    if (!tokenizer.EncodeLongestMatch(prompt, promptTokens)) {
        printf("[FAIL] EncodeLongestMatch failed\n");
        return 1;
    }
    printf("[PASS] Tokenized to %zu tokens\n", promptTokens.size());
    for (size_t i = 0; i < promptTokens.size(); ++i) {
        printf("  token[%zu]=%u text=\"%s\"\n", i, promptTokens[i],
               tokenizer.Token(promptTokens[i]).c_str());
    }

    // Convert to int vector for engine
    std::vector<int> tokens;
    for (auto t : promptTokens) tokens.push_back(static_cast<int>(t));

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

    // Detokenize using embedded tokenizer
    std::string text = tokenizer.Token(static_cast<uint32_t>(outputTokens[0]));
    printf("[PASS] Detokenized: '%s'\n", text.c_str());

    printf("\n=== TOKEN GENERATION SUCCESS ===\n");
    printf("Prompt: '%s' -> Generated token: %d ('%s')\n",
           prompt.c_str(), outputTokens[0], text.c_str());

    return 0;
}
