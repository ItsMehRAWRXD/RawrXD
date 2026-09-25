// test_generate_313_tokens.cpp — BATCH007 313-token regression gate for Gemma3
// Usage: test_generate_313_tokens <path-to-gemma3.gguf>
// Outputs: token IDs 0-312 to stdout, one per line, for deterministic comparison.
#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1]
        : "D:\\rawrxd\\gemma3-1b-Q2_K.gguf";

    std::fprintf(stderr, "GATE=DEEP2_313_TOKEN_REGRESSION\n");
    std::fprintf(stderr, "MODEL=%s\n", modelPath);
    std::fprintf(stderr, "CACHE_STATE=%s\n", std::getenv("DEEP2_EXPERT_MIGRATION") ? std::getenv("DEEP2_EXPERT_MIGRATION") : "default");

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

    engine.enableVulkan(true);
    std::fprintf(stderr, "VULKAN=ENABLED\n");

    if (!engine.loadModel(modelPath)) {
        std::fprintf(stderr, "FAIL=loadModel\n");
        return 1;
    }
    std::fprintf(stderr, "PASS=loadModel\n");

    // Deterministic greedy generation for reproducible regression
    GenerationOptions go{};
    go.temperature = 0.0f;
    go.topK = 1;
    go.maxTokens = 313;   // Exact regression requirement
    go.seed = 42;
    engine.configureGeneration(go);

    std::string prompt = "Hello";
    std::vector<int> tokens = engine.tokenize(prompt);
    if (tokens.empty()) {
        std::fprintf(stderr, "FAIL=tokenize_empty\n");
        return 1;
    }
    std::fprintf(stderr, "PASS=tokenize count=%zu\n", tokens.size());

    std::vector<int> outputTokens;
    outputTokens.resize(313);
    InferenceStats stats{};

    size_t generated = engine.generate(
        tokens.data(), tokens.size(),
        outputTokens.data(), outputTokens.size(),
        &stats,
        nullptr /* onToken callback */
    );

    if (generated == 0) {
        std::fprintf(stderr, "FAIL=generate_zero_tokens\n");
        return 1;
    }

    if (generated != 313) {
        std::fprintf(stderr, "FAIL=generate_wrong_count expected=313 got=%zu\n", generated);
        return 1;
    }

    // Emit token IDs for comparison
    for (size_t i = 0; i < generated; ++i) {
        std::printf("%d\n", outputTokens[i]);
    }

    std::fprintf(stderr, "PASS=generate count=%zu\n", generated);
    std::fprintf(stderr, "STATS tokensGenerated=%zu promptTokens=%zu prefillMs=%.3f decodeMs=%.3f\n",
        stats.tokensGenerated, stats.promptTokens, stats.prefillMs, stats.decodeMs);
    std::fprintf(stderr, "RESULT=PASS\n");
    return 0;
}
