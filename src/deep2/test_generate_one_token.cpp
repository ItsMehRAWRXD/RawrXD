// test_generate_one_token.cpp - Minimal: load a GGUF model and generate 1 token
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cstring>
#include "Deep2Engine.h"
#include "gguf_embedded_tokenizer.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Deep2;

static void deep2_enable_utf8_console() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

int main(int argc, char** argv) {
    deep2_enable_utf8_console();

    const char* modelPath = argc > 1 ? argv[1] : "G:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";

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
    std::string prompt = "hello";
    printf("[TEST] Tokenizing prompt: '%s'\n", prompt.c_str());
    std::vector<uint32_t> promptTokens;
    if (!tokenizer.EncodeLongestMatch(prompt, promptTokens)) {
        printf("[FAIL] EncodeLongestMatch failed\n");
        return 1;
    }
    printf("[PASS] Tokenized to %zu tokens\n", promptTokens.size());
    for (size_t i = 0; i < promptTokens.size(); ++i) {
        printf("  prompt_token[%zu]=%u text=\"%s\"\n", i, promptTokens[i],
               tokenizer.Token(promptTokens[i]).c_str());
    }

    // Convert to int vector for engine
    std::vector<int> tokens;
    for (auto t : promptTokens) tokens.push_back(static_cast<int>(t));

    // Generate 16 tokens
    const size_t kGenCount = 16;
    printf("[TEST] Generating %zu tokens...\n", kGenCount);
    std::vector<int> outputTokens(kGenCount);
    size_t generated = engine.generate(tokens.data(), tokens.size(),
                                        outputTokens.data(), kGenCount);
    if (generated == 0) {
        printf("[FAIL] generate() returned 0 tokens\n");
        return 1;
    }

    printf("[PASS] Generated %zu tokens\n", generated);
    fflush(stdout);
    std::string allText;
    for (size_t i = 0; i < generated; ++i) {
        std::string text = tokenizer.Token(static_cast<uint32_t>(outputTokens[i]));
        allText += text;
    }

    printf("\n=== GENERATED RESPONSE ===\n");
    printf("Prompt: '%s'\n", prompt.c_str());
    printf("Response: '%s'\n", allText.c_str());
    printf("=== TOKEN GENERATION SUCCESS ===\n");
    fflush(stdout);

    printf("[TEST] Returning 0\n");
    fflush(stdout);

    // ── Fast-exit teardown A/B: bypass CRT teardown to test for destructor crash ──
    if (std::getenv("RAWRXD_CERT_FAST_EXIT")) {
#ifdef _WIN32
        ::ExitProcess(0);
#else
        std::_Exit(0);
#endif
    }

    return 0;
}
