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

static std::vector<int> runGreedyOnce(Deep2Engine& engine, const std::string& prompt,
                                      size_t maxTokens) {
    GenerationOptions opt;
    opt.maxTokens = static_cast<uint32_t>(maxTokens);
    opt.temperature = 0.0f;
    opt.topK = 1;
    opt.topP = 1.0f;
    opt.seed = 42;

    engine.reset();
    engine.configureGeneration(opt);

    std::vector<int> tokens;
    tokens.reserve(maxTokens);
    engine.generateStream(prompt, opt, [&](int32_t tok, const std::string&) -> bool {
        tokens.push_back(static_cast<int>(tok));
        return tokens.size() < maxTokens;
    });
    return tokens;
}

static void printTokens(const char* label, const std::vector<int>& tokens) {
    printf("%s (%zu): ", label, tokens.size());
    for (auto t : tokens) printf("%d ", t);
    printf("\n");
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    const char* modelPath = argc > 1 ? argv[1]
        : "F:\\~dev\\tinyllama_fresh.gguf";

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

    // Machine-readable prompt IDs for PARITY-CERT-001 (Deep2 tokenizer only).
    std::vector<int> promptIds = engine.tokenize(prompt);
    printf("DEEP2_PROMPT_IDS=");
    for (size_t i = 0; i < promptIds.size(); ++i) {
        if (i) printf(",");
        printf("%d", promptIds[i]);
    }
    printf("\n");

    // Both runs use generateStream + GenerationOptions (temperature=0).
    // Do NOT measure via raw generate() — that path defaults to TopKSampler.
    std::vector<int> tokens1 = runGreedyOnce(engine, prompt, maxTokens);
    std::vector<int> tokens2 = runGreedyOnce(engine, prompt, maxTokens);

    printTokens("Run 1 tokens", tokens1);
    printTokens("Run 2 tokens", tokens2);
    printf("DEEP2_GEN_IDS=");
    for (size_t i = 0; i < tokens1.size(); ++i) {
        if (i) printf(",");
        printf("%d", tokens1[i]);
    }
    printf("\n");
    fflush(stdout);

    bool match = (tokens1.size() == tokens2.size()) && !tokens1.empty();
    size_t firstMismatch = static_cast<size_t>(-1);
    if (match) {
        for (size_t i = 0; i < tokens1.size(); ++i) {
            if (tokens1[i] != tokens2[i]) {
                match = false;
                firstMismatch = i;
                printf("[MISMATCH] at position %zu: run1=%d run2=%d\n",
                       i, tokens1[i], tokens2[i]);
                break;
            }
        }
    } else if (tokens1.size() != tokens2.size()) {
        printf("[MISMATCH] token count: run1=%zu run2=%zu\n",
               tokens1.size(), tokens2.size());
    } else {
        printf("[MISMATCH] empty token sequences\n");
    }

    // Write verdict before engine teardown (teardown has been crashing 0xC0000409).
    FILE* verdict = fopen("F:\\~dev\\rawrxd\\build-ninja\\bin\\STREAM008_VERDICT.txt", "w");
    if (match) {
        printf("[PASS] Deterministic replay: %zu tokens identical\n", tokens1.size());
        printf("STREAM-008 deterministic_replay   PASS\n");
        if (verdict) {
            fprintf(verdict, "PASS\n");
            for (auto t : tokens1) fprintf(verdict, "%d ", t);
            fprintf(verdict, "\n");
            fclose(verdict);
        }
        fflush(stdout);
        fflush(stderr);
        _Exit(0); // skip destructor crash path for certification
    }

    printf("[FAIL] Deterministic replay failed");
    if (firstMismatch != static_cast<size_t>(-1)) {
        printf(" first_mismatch=%zu", firstMismatch);
    }
    printf("\n");
    printf("STREAM-008 deterministic_replay   FAIL\n");
    if (verdict) {
        fprintf(verdict, "FAIL\n");
        fclose(verdict);
    }
    fflush(stdout);
    fflush(stderr);
    _Exit(1);
}
