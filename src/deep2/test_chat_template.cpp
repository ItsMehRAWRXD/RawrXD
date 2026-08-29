// test_chat_template.cpp - Chat template + streaming generation test
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include "Deep2Engine.h"
#include "ChatTemplate.hpp"
#include "gguf_embedded_tokenizer.hpp"

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1] : "G:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";

    printf("[TEST] Chat Template + Streaming Generation Test\n");
    printf("[TEST] Model: %s\n", modelPath);

    Deep2Engine engine;

    printf("[TEST] Loading model...\n");
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

    printf("[TEST] Initializing engine...\n");
    if (!engine.initialize(cfg)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }
    printf("[PASS] Engine initialized\n");

    // Initialize chat template from model metadata
    ChatTemplate chatTmpl;
    const ModelMetadata& meta = engine.getModelMetadata();
    if (!chatTmpl.initFromMetadata(meta.architecture, "", meta.chatTemplate,
                                    meta.bosToken, meta.eosToken)) {
        printf("[WARN] Failed to init chat template, using fallback\n");
    }
    printf("[ChatTemplate] Detected type: %s\n", chatTmpl.getTypeName());

    // Test 1: Single-turn chat with system prompt
    printf("\n=== TEST 1: Single-turn chat ===\n");
    std::string userMsg = "hello";
    std::string sysPrompt = "You are a helpful assistant.";
    
    std::string formatted = chatTmpl.formatSingle(userMsg, sysPrompt);
    printf("Formatted prompt:\n%s\n", formatted.c_str());

    // Tokenize and generate with streaming
    std::vector<int> promptTokens = engine.tokenize(formatted);
    printf("Prompt tokens: %zu\n", promptTokens.size());

    const size_t kGenCount = 16;
    std::vector<int> outputTokens(kGenCount);
    
    printf("\n--- Streaming generation ---\n");
    size_t generated = engine.generate(promptTokens.data(), promptTokens.size(),
                                        outputTokens.data(), kGenCount,
                                        nullptr,
                                        [](int tokenId) -> bool {
                                            // In a real app, you'd detokenize here
                                            // For this test, we just collect
                                            return true;  // Continue generating
                                        });

    printf("\nGenerated %zu tokens\n", generated);
    
    // Detokenize and display
    std::string response = engine.detokenize(
        std::vector<int>(outputTokens.begin(), outputTokens.begin() + generated));
    printf("Response: '%s'\n", response.c_str());

    // Test 2: Multi-turn conversation
    printf("\n=== TEST 2: Multi-turn conversation ===\n");
    std::vector<ChatMessage> messages = {
        {"system", "You are a helpful coding assistant.", ""},
        {"user", "Write a hello world in C++.", ""},
    };
    
    std::string multiFormatted = chatTmpl.format(messages);
    printf("Multi-turn formatted prompt:\n%s\n", multiFormatted.c_str());

    // Test 3: Raw prompt comparison (no template)
    printf("\n=== TEST 3: Raw prompt (no template) ===\n");
    std::string rawPrompt = "hello";
    std::vector<int> rawTokens = engine.tokenize(rawPrompt);
    std::vector<int> rawOutput(kGenCount);
    size_t rawGenerated = engine.generate(rawTokens.data(), rawTokens.size(),
                                           rawOutput.data(), kGenCount);
    std::string rawResponse = engine.detokenize(
        std::vector<int>(rawOutput.begin(), rawOutput.begin() + rawGenerated));
    printf("Raw response: '%s'\n", rawResponse.c_str());

    printf("\n=== CHAT TEMPLATE TEST COMPLETE ===\n");
    return 0;
}
