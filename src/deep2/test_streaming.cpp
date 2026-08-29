// test_streaming.cpp -- Minimal streaming test: token-by-token output
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <sstream>
#include "Deep2Engine.h"
#include "ChatTemplate.hpp"
#include "gguf_embedded_tokenizer.hpp"

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1] : "G:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";

    printf("[STREAM_TEST] Streaming Generation Test\n");
    printf("[STREAM_TEST] Model: %s\n", modelPath);

    Deep2Engine engine;

    printf("[STREAM_TEST] Loading model...\n");
    if (!engine.loadModel(modelPath)) {
        printf("[STREAM_TEST] FAIL: loadModel() returned false\n");
        return 1;
    }
    const auto& mw = engine.getModelWeights();
    printf("[STREAM_TEST] Model loaded: hidden=%zu layers=%zu heads=%zu vocab=%zu\n",
           mw.hiddenDim, mw.numLayers, mw.numHeads, mw.vocabSize);

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

    printf("[STREAM_TEST] Initializing engine...\n");
    if (!engine.initialize(cfg)) {
        printf("[STREAM_TEST] FAIL: Engine initialization failed\n");
        return 1;
    }
    printf("[STREAM_TEST] Engine initialized\n");

    // Initialize chat template from model metadata
    ChatTemplate chatTmpl;
    const ModelMetadata& meta = engine.getModelMetadata();
    chatTmpl.initFromMetadata(meta.architecture, "", meta.chatTemplate,
                               meta.bosToken, meta.eosToken);
    printf("[STREAM_TEST] Chat template: %s\n", chatTmpl.getTypeName());

    // Format prompt with chat template
    std::string userMsg = "hello";
    std::string sysPrompt = "You are a helpful assistant.";
    std::string formatted = chatTmpl.formatSingle(userMsg, sysPrompt);
    printf("[STREAM_TEST] Formatted prompt: %s\n", formatted.c_str());

    // Tokenize
    std::vector<int> promptTokens = engine.tokenize(formatted);
    printf("[STREAM_TEST] Prompt tokens: %zu\n", promptTokens.size());

    // Generate with streaming callback
    const size_t kGenCount = 16;
    std::vector<int> outputTokens(kGenCount);
    std::string accumulated;

    printf("\n[STREAM_TEST] === BEGIN STREAM ===\n");
    fflush(stdout);

    size_t generated = engine.generate(
        promptTokens.data(), promptTokens.size(),
        outputTokens.data(), kGenCount,
        nullptr,
        [&engine, &accumulated](int tokenId) -> bool {
            std::string piece = engine.detokenize({tokenId});
            printf("[STREAM] token=%d piece=\"%s\"\n", tokenId, piece.c_str());
            fflush(stdout);
            accumulated += piece;
            return true;  // Continue generating
        }
    );

    printf("[STREAM_TEST] === END STREAM ===\n");
    printf("[STREAM_TEST] Generated %zu tokens\n", generated);
    printf("[STREAM_TEST] Accumulated response: \"%s\"\n", accumulated.c_str());
    printf("[STREAM_TEST] === SUCCESS ===\n");
    fflush(stdout);

    return 0;
}
