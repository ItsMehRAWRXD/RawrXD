/* Deep2 Standalone Test — End-to-end generate without external deps */
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <algorithm>
#include "deep2/Deep2Engine.h"
#include "deep2/Deep2GpuForward.hpp"
#include "deep2/deep2_e2e_trace.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: deep2_standalone.exe <model.gguf> [prompt] [max_tokens]\n");
        return 2;
    }

    const char* modelPath = argv[1];
    const char* prompt    = argc > 2 ? argv[2] : "hi";
    int maxTokens         = argc > 3 ? atoi(argv[3]) : 5;

    fprintf(stderr, "MODEL=%s\n", modelPath);
    fprintf(stderr, "PROMPT=%s\n", prompt);
    fprintf(stderr, "MAX_TOKENS=%d\n", maxTokens);

    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg{};
    cfg.hiddenDim = 256;
    cfg.numLayers = 2;
    cfg.numHeads = 4;
    cfg.numKVHeads = 4;
    cfg.headDim = 64;
    cfg.vocabSize = 128;
    cfg.intermediateDim = 1024;
    cfg.maxSeqLen = 512;
    cfg.numThreads = 4;

    if (!engine.initialize(cfg)) {
        fprintf(stderr, "FAIL: initialize\n");
        return 1;
    }
    fprintf(stderr, "PASS: initialize\n");

    if (!engine.loadModel(modelPath)) {
        fprintf(stderr, "FAIL: loadModel path=%s\n", modelPath);
        return 4;
    }
    fprintf(stderr, "PASS: loadModel\n");

    const auto& act = engine.getConfig();
    fprintf(stderr, "ACTUAL hiddenDim=%zu numLayers=%zu vocabSize=%zu\n",
            act.hiddenDim, act.numLayers, act.vocabSize);

    // Tokenize
    auto toks = engine.tokenize(prompt);
    fprintf(stderr, "Tokens: %zu\n", toks.size());
    for (size_t i = 0; i < toks.size() && i < 8; ++i) {
        std::string piece = engine.detokenize({toks[i]});
        fprintf(stderr, "  tok[%zu] id=%d piece=[%s]\n", i, toks[i], piece.c_str());
    }

    // E2E trace writer (must know actual layers and prompt token count)
    std::string tracePath = std::string(modelPath) + ".e2e.trace";
    deep2::E2ETraceWriter trace;
    std::vector<std::string> modelFiles = { modelPath };
    uint64_t modelFileSize = 0;
    try {
        modelFileSize = std::filesystem::file_size(modelPath);
    } catch (...) {}
    if (!trace.open(tracePath, "deep2_standalone",
                     static_cast<uint32_t>(act.numLayers),
                     static_cast<uint32_t>(maxTokens), 1,
                     static_cast<uint64_t>(toks.size()), modelFiles)) {
        fprintf(stderr, "WARN: trace open failed\n");
    }
    trace.discover();
    trace.opened();
    trace.backend();
    trace.tokenized(toks.size());
    trace.weight_touch(modelFileSize);

    // Configure generation to avoid greedy collapse
    Deep2::GenerationOptions genOpts{};
    genOpts.temperature = 0.8f;
    genOpts.topK = 40;
    engine.configureGeneration(genOpts);

    // Generate with streaming callback to capture stdout and trace
    std::vector<int> out;
    out.reserve(maxTokens);
    Deep2::InferenceStats stats{};
    std::vector<int> outputBuffer(maxTokens, 0);

    auto onToken = [&](int tok) -> bool {
        out.push_back(tok);
        uint32_t tokIdx = static_cast<uint32_t>(out.size());
        // E2E per-token events
        for (uint32_t layer = 0; layer < static_cast<uint32_t>(act.numLayers); ++layer) {
            trace.forward(tokIdx, layer);
        }
        trace.kv(tokIdx);
        trace.logits(tokIdx, act.vocabSize);
        trace.sample(tokIdx, tok);
        std::string piece = engine.detokenize({tok});
        trace.detokenize(tokIdx, tok, piece.data(), static_cast<uint32_t>(piece.size()));
        if (!piece.empty()) {
            std::cout << piece << std::flush;
            trace.stream(tokIdx, tok, piece.data(), static_cast<uint32_t>(piece.size()));
        }
        return true;
    };

    size_t n = engine.generate(toks.data(), toks.size(), outputBuffer.data(), (size_t)maxTokens, &stats, onToken);
    std::cout << std::endl;

    fprintf(stderr, "Generated: %zu tokens in %.2f ms (%.2f tok/s)\n",
           n, stats.decodeMs, stats.decodeTokensPerSecond);

    std::string text = engine.detokenize(out);
    fprintf(stderr, "Output: [%s]\n", text.c_str());

    trace.end();
    fprintf(stderr, "TRACE=%s\n", tracePath.c_str());

    // GPU counters
    Deep2::Deep2GpuForward_Emit(stderr, engine.gpuForwardCounters(), 0);

    fprintf(stderr, n > 0 ? "\n=== PASS ===\n" : "\n=== FAIL ===\n");
    return n > 0 ? 0 : 1;
}
