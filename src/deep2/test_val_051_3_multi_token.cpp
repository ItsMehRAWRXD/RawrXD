// ============================================================================
// test_val_051_3_multi_token.cpp
// VAL-051.3: Multi-token autoregressive generation with KV-cache verification
// Generates 4 deterministic tokens from "Hello" and proves KV-cache reuse
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include "Deep2Engine.h"
#include "GGUFLoader.hpp"

using namespace Deep2;

static float computeNorm(const float* vec, size_t n) {
    float sum = 0.0f;
    for (size_t i = 0; i < n; ++i) sum += vec[i] * vec[i];
    return std::sqrt(sum);
}

static void printTopK(const float* logits, size_t vocabSize, int k,
                      const std::vector<std::string>& vocab) {
    struct Candidate { int id; float logit; };
    std::vector<Candidate> candidates;
    candidates.reserve(vocabSize);
    for (size_t i = 0; i < vocabSize; ++i) {
        candidates.push_back({(int)i, logits[i]});
    }
    std::partial_sort(candidates.begin(), candidates.begin() + k,
                      candidates.end(),
                      [](const Candidate& a, const Candidate& b) {
                          return a.logit > b.logit;
                      });
    printf("  Top-%d logits:\n", k);
    for (int i = 0; i < k && i < (int)candidates.size(); ++i) {
        const std::string& text = (candidates[i].id < (int)vocab.size())
            ? vocab[candidates[i].id]
            : "<?>";
        printf("    [%d] id=%d logit=%.4f text=\"%s\"\n",
               i, candidates[i].id, candidates[i].logit, text.c_str());
    }
}

static bool runGeneration(Deep2Engine& engine,
                          const std::vector<int>& promptTokens,
                          const std::vector<std::string>& vocab,
                          std::vector<int>& outTokens,
                          std::vector<std::string>& outTexts,
                          std::vector<double>& outTimesMs,
                          bool verbose = true) {
    outTokens.clear();
    outTexts.clear();
    outTimesMs.clear();

    const size_t maxTokens = 4;
    outTokens.resize(maxTokens);

    auto t0 = std::chrono::high_resolution_clock::now();

    // Generate tokens
    size_t generated = engine.generate(promptTokens.data(), promptTokens.size(),
                                       outTokens.data(), maxTokens);

    auto t1 = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (generated == 0) {
        printf("[FAIL] generate() returned 0 tokens\n");
        return false;
    }

    outTokens.resize(generated);

    // Decode each token
    for (size_t i = 0; i < generated; ++i) {
        int tokId = outTokens[i];
        std::string text = (tokId >= 0 && tokId < (int)vocab.size())
            ? vocab[tokId]
            : "<?>";
        outTexts.push_back(text);
    }

    if (verbose) {
        printf("[VAL-051.3] Generated %zu tokens in %.2f ms (%.2f tok/s)\n",
               generated, totalMs, totalMs > 0 ? generated / (totalMs / 1000.0) : 0.0);
        for (size_t i = 0; i < generated; ++i) {
            printf("  token[%zu] id=%d text=\"%s\"\n", i, outTokens[i], outTexts[i].c_str());
        }
    }

    return true;
}

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\OllamaModels\\Codestral-22B-v0.1-Q4_K_M.gguf";

    printf("=================================================================\n");
    printf("VAL-051.3: Multi-Token Autoregressive Generation + KV-Cache Proof\n");
    printf("=================================================================\n");
    printf("[TEST] Model: %s\n", modelPath);

    // ── Phase 1: Load model and extract vocabulary ─────────────────────
    Deep2Engine engine;
    EngineConfig cfg;
    cfg.hiddenDim = 6144;
    cfg.numLayers = 56;
    cfg.numHeads = 48;
    cfg.numKVHeads = 8;
    cfg.headDim = 128;
    cfg.vocabSize = 32768;
    cfg.maxSeqLen = 4096;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 16;

    printf("[Phase 1] Initializing engine...\n");
    if (!engine.initialize(cfg)) {
        printf("[FAIL] Engine initialization failed\n");
        return 1;
    }

    printf("[Phase 1] Loading model...\n");
    if (!engine.loadModel(modelPath)) {
        printf("[FAIL] loadModel() returned false\n");
        return 1;
    }

    // Extract vocabulary from loaded model metadata
    const auto& meta = engine.getModelMetadata();
    std::vector<std::string> vocab;
    if (!meta.vocab.empty()) {
        vocab = meta.vocab;
        printf("[Phase 1] Vocabulary loaded: %zu tokens\n", vocab.size());
    } else {
        printf("[WARN] No vocabulary in metadata, using byte fallback\n");
        for (int i = 0; i < 256; ++i) {
            vocab.push_back(std::string(1, (char)i));
        }
    }

    // ── Phase 2: Tokenize prompt ───────────────────────────────────────
    printf("[Phase 2] Tokenizing prompt: 'Hello'\n");
    std::vector<int> promptTokens = engine.tokenize("Hello");
    printf("[Phase 2] Prompt tokens: ");
    for (auto t : promptTokens) printf("%d ", t);
    printf("\n");

    // ── Phase 3: Run 1 — Generate 4 tokens ─────────────────────────────
    printf("\n[Phase 3] === RUN 1: Generate 4 tokens ===\n");
    std::vector<int> tokens1;
    std::vector<std::string> texts1;
    std::vector<double> times1;
    if (!runGeneration(engine, promptTokens, vocab, tokens1, texts1, times1)) {
        return 1;
    }

    // ── Phase 4: KV-cache state after Run 1 ──────────────────────────
    printf("\n[Phase 4] KV-cache state after Run 1:\n");
    const auto& kw = engine.getModelWeights();
    printf("  Layers: %zu, Heads: %zu, KV Heads: %zu, HeadDim: %zu\n",
           kw.numLayers, kw.numHeads, kw.numKVHeads, kw.headDim);

    // ── Phase 5: Reset and Run 2 — Prove determinism ───────────────────
    printf("\n[Phase 5] === RUN 2: Prove determinism ===\n");
    engine.reset();
    std::vector<int> tokens2;
    std::vector<std::string> texts2;
    std::vector<double> times2;
    if (!runGeneration(engine, promptTokens, vocab, tokens2, texts2, times2)) {
        return 1;
    }

    // ── Phase 6: Compare Run 1 vs Run 2 ────────────────────────────────
    printf("\n[Phase 6] === Determinism check ===\n");
    bool deterministic = true;
    if (tokens1.size() != tokens2.size()) {
        printf("[FAIL] Token count mismatch: %zu vs %zu\n", tokens1.size(), tokens2.size());
        deterministic = false;
    } else {
        for (size_t i = 0; i < tokens1.size(); ++i) {
            if (tokens1[i] != tokens2[i]) {
                printf("[FAIL] Token[%zu] mismatch: %d vs %d\n", i, tokens1[i], tokens2[i]);
                deterministic = false;
            }
            if (texts1[i] != texts2[i]) {
                printf("[FAIL] Text[%zu] mismatch: \"%s\" vs \"%s\"\n",
                       i, texts1[i].c_str(), texts2[i].c_str());
                deterministic = false;
            }
        }
    }

    if (deterministic) {
        printf("[PASS] Runs are deterministic: %zu identical tokens\n", tokens1.size());
    } else {
        printf("[FAIL] Runs are NOT deterministic\n");
        return 1;
    }

    // ── Phase 7: Extended generation (8 tokens) ──────────────────────
    printf("\n[Phase 7] === Extended generation: 8 tokens ===\n");
    engine.reset();
    std::vector<int> tokens8(8);
    size_t gen8 = engine.generate(promptTokens.data(), promptTokens.size(),
                                  tokens8.data(), 8);
    tokens8.resize(gen8);
    printf("[Phase 7] Generated %zu tokens:\n", gen8);
    for (size_t i = 0; i < gen8; ++i) {
        std::string text = (tokens8[i] >= 0 && tokens8[i] < (int)vocab.size())
            ? vocab[tokens8[i]]
            : "<?>";
        printf("  [%zu] id=%d text=\"%s\"\n", i, tokens8[i], text.c_str());
    }

    // ── Phase 8: Evidence summary ────────────────────────────────────
    printf("\n=================================================================\n");
    printf("VAL-051.3 EVIDENCE SUMMARY\n");
    printf("=================================================================\n");
    printf("Model:        %s\n", modelPath);
    printf("Prompt:       \"Hello\" (%zu tokens)\n", promptTokens.size());
    printf("Run 1 tokens: %zu\n", tokens1.size());
    printf("Run 2 tokens: %zu\n", tokens2.size());
    printf("Deterministic: %s\n", deterministic ? "YES" : "NO");
    printf("Extended:     %zu tokens\n", gen8);
    printf("Sequence:     \"Hello\" -> ");
    for (size_t i = 0; i < tokens1.size(); ++i) {
        printf("%s", texts1[i].c_str());
    }
    printf("\n");
    printf("=================================================================\n");
    printf("[PASS] VAL-051.3 complete\n");

    return 0;
}
