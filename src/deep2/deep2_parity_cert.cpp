// ============================================================================
// deep2_parity_cert.cpp — PARITY-CERT-001: Deep2 vs external reference (token IDs)
// ============================================================================
// Deep2 side ONLY. Links InferenceEngine. ZERO Ollama / llama.cpp / cloud deps.
//
// Emits machine-readable lines for the orchestrator
// (scripts/run_parity_cert_001.ps1) which shells out to an EXTERNAL llama.cpp
// measuring-stick binary. That external process is NOT a Deep2 dependency.
//
// Contract:
//   model=F:\~dev\tinyllama_fresh.gguf
//   prompt=hello
//   max_new_tokens=15
//   temperature=0
//   top_k=1
//
// Usage:
//   deep2_parity_cert.exe [model.gguf] [--dump-top10-at N]
// ============================================================================

#include "Deep2Engine.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

using namespace Deep2;

static void printIdList(const char* key, const std::vector<int>& ids) {
    printf("%s=", key);
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) printf(",");
        printf("%d", ids[i]);
    }
    printf("\n");
}

static void dumpTop10(const float* logits, size_t vocab, Deep2Engine& engine) {
    std::vector<std::pair<float, int>> scored;
    scored.reserve(vocab);
    for (size_t i = 0; i < vocab; ++i) {
        scored.push_back({logits[i], static_cast<int>(i)});
    }
    const size_t k = std::min<size_t>(10, scored.size());
    std::partial_sort(scored.begin(), scored.begin() + static_cast<std::ptrdiff_t>(k),
                      scored.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });
    printf("DEEP2_TOP10=");
    for (size_t i = 0; i < k; ++i) {
        if (i) printf(",");
        printf("%d:%.6f", scored[i].second, scored[i].first);
        std::string piece = engine.detokenize(std::vector<int>{scored[i].second});
        // sanitize commas/newlines in piece for machine parse
        for (char& c : piece) {
            if (c == ',' || c == '\n' || c == '\r') c = ' ';
        }
        printf(":'%s'", piece.c_str());
    }
    printf("\n");
    if (k > 0) {
        printf("DEEP2_SELECTED_ID=%d\n", scored[0].second);
        printf("DEEP2_SELECTED_LOGIT=%.6f\n", scored[0].first);
    }
}

int main(int argc, char** argv) {
    const char* modelPath = R"(F:\~dev\tinyllama_fresh.gguf)";
    int dumpTop10At = -1; // generation step index; -1 = none unless env forces 0 on mismatch path
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--dump-top10-at" && i + 1 < argc) {
            dumpTop10At = std::atoi(argv[++i]);
        } else if (!a.empty() && a[0] != '-') {
            modelPath = argv[i];
        }
    }

    printf("PARITY-CERT-001\n");
    printf("side=Deep2\n");
    printf("deep2_inference_deps=NONE\n");
    printf("model=%s\n", modelPath);
    printf("prompt=hello\n");
    printf("max_new_tokens=15\n");
    printf("temperature=0\n");
    printf("top_k=1\n");
    printf("deep2_backend=Deep2\n");
    fflush(stdout);

    Deep2Engine engine;
    if (!engine.loadModel(modelPath)) {
        fprintf(stderr, "DEEP2_LOAD=FAIL\n");
        return 2;
    }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim;
    cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads;
    cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim;
    cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 16;
    strncpy_s(cfg.modelPath, modelPath, _TRUNCATE);
    if (!engine.initialize(cfg)) {
        fprintf(stderr, "DEEP2_INIT=FAIL\n");
        return 2;
    }
    printf("DEEP2_LOAD=PASS\n");
    printf("DEEP2_MODEL_META=hidden=%zu layers=%zu vocab=%zu\n",
           mw.hiddenDim, mw.numLayers, mw.vocabSize);

    const std::string prompt = "hello";
    GenerationOptions opts;
    opts.maxTokens = 15;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.seed = 0;
    engine.reset();
    engine.configureGeneration(opts);

    std::vector<int> promptTokens = engine.tokenize(prompt);
    printIdList("DEEP2_PROMPT_IDS", promptTokens);

    std::vector<int> out(15, 0);
    std::vector<int> generated;
    generated.reserve(15);

    // Capture first-step top-10 by generating one token with diagnostics already
    // printed by Deep2Engine::sampleToken when temperature==0 / topK==1.
    // For machine-readable TOP10 at a specific step we regenerate step-0 alone
    // when requested.
    if (dumpTop10At == 0) {
        // One-token pass: engine prints [Deep2Engine] Top-10 logits to stdout;
        // also emit DEEP2_TOP10 from a second one-token generate if logits pointer
        // is accessible — sample path already prints human top-10.
        // Force a one-token generate to surface diagnostics, then full 15.
        GenerationOptions one = opts;
        one.maxTokens = 1;
        engine.reset();
        engine.configureGeneration(one);
        std::vector<int> tmp(1, 0);
        engine.generate(promptTokens.data(), promptTokens.size(), tmp.data(), 1, nullptr, nullptr);
        engine.reset();
        engine.configureGeneration(opts);
    }

    size_t n = engine.generate(
        promptTokens.data(), promptTokens.size(),
        out.data(), out.size(),
        nullptr,
        [&](int tokenId) -> bool {
            generated.push_back(tokenId);
            return true;
        });

    if (n > generated.size()) {
        // sync path may fill `out` without callback in some builds — prefer callback
        if (generated.empty()) {
            for (size_t i = 0; i < n; ++i) generated.push_back(out[i]);
        }
    }
    printIdList("DEEP2_GEN_IDS", generated);
    printf("DEEP2_GEN_COUNT=%zu\n", generated.size());

    printf("DEEP2_GEN_PIECES=");
    for (size_t i = 0; i < generated.size(); ++i) {
        if (i) printf("|");
        std::string piece = engine.detokenize(std::vector<int>{generated[i]});
        for (char& c : piece) {
            if (c == '|' || c == '\n' || c == '\r') c = ' ';
        }
        printf("%s", piece.c_str());
    }
    printf("\n");

    printf("DEEP2_SIDE=DONE\n");
    fflush(stdout);
    fflush(stderr);

    // Avoid known destructor crash (LIFECYCLE-CERT-001 OPEN) — same as streamer cert.
    _Exit(generated.empty() ? 1 : 0);
}
