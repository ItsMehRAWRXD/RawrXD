// test_generate_one_token.cpp — Minimal one-token generation gate for Gemma3
// Usage: test_generate_one_token <path-to-gemma3.gguf>
#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1]
        : "D:\\rawrxd\\gemma3-1b-Q2_K.gguf";

    std::fprintf(stderr, "GATE=DEEP2_ONE_TOKEN_GENERATION\n");
    std::fprintf(stderr, "MODEL=%s\n", modelPath);

    Deep2Engine engine;

    EngineConfig cfg{};
    cfg.maxSeqLen   = 4096;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;
    cfg.numThreads  = 16;
    cfg.useRoPE     = true;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", modelPath);

    if (!engine.initialize(cfg)) {
        std::fprintf(stderr, "FAIL=initialize\n");
        return 1;
    }
    std::fprintf(stderr, "PASS=initialize\n");

    if (!engine.loadModel(modelPath)) {
        std::fprintf(stderr, "FAIL=loadModel\n");
        return 1;
    }
    std::fprintf(stderr, "PASS=loadModel\n");

    const auto& mw = engine.getModelWeights();

    // Greedy deterministic sampling for reproducibility
    GenerationOptions go{};
    go.temperature = 0.0f;
    go.topK = 1;
    go.maxTokens = 1;
    go.seed = 42;
    engine.configureGeneration(go);

    std::string prompt = "Hello";
    std::vector<int> tokens = engine.tokenize(prompt);
    if (tokens.empty()) {
        std::fprintf(stderr, "FAIL=tokenize_empty\n");
        return 1;
    }
    std::fprintf(stderr, "PASS=tokenize count=%zu\n", tokens.size());

    int outputToken = 0;
    InferenceStats stats{};
    size_t generated = engine.generate(
        tokens.data(), tokens.size(),
        &outputToken, 1,
        &stats,
        nullptr /* onToken callback */
    );

    if (generated == 0) {
        std::fprintf(stderr, "FAIL=generate_zero_tokens\n");
        return 1;
    }

    std::string detok = engine.detokenize({outputToken});
    std::fprintf(stderr, "PASS=generate token_id=%d detok=\"", outputToken);
    for (char c : detok) {
        if (c == '\\' || c == '"') std::fprintf(stderr, "\\%c", c);
        else if (c >= 0x20 && c < 0x7f) std::fprintf(stderr, "%c", c);
        else std::fprintf(stderr, "\\x%02x", (unsigned char)c);
    }
    std::fprintf(stderr, "\"\n");
    std::fprintf(stderr, "STATS tokensGenerated=%zu promptTokens=%zu prefillMs=%.3f decodeMs=%.3f\n",
        stats.tokensGenerated, stats.promptTokens, stats.prefillMs, stats.decodeMs);
    std::fprintf(stderr, "RESULT=PASS\n");
    return 0;
}

