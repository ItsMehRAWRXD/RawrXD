#include "cpu_inference_engine.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <vector>
#include <string>
#include <cmath>

using namespace RawrXD;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: cpu_engine_e2e <model.gguf> [prompt]\n";
        return 2;
    }

    std::string modelPath = argv[1];
    std::string prompt = (argc > 2) ? argv[2] : "The capital of France is";
    int decodeLimit = (argc > 3) ? std::max(1, std::stoi(argv[3])) : 10;

    std::cout << "=== RawrXD CPU Engine End-to-End Test ===\n";
    std::cout << "Model: " << modelPath << "\n";
    std::cout << "Prompt: \"" << prompt << "\"\n\n";

    CPUInferenceEngine engine;

    // Load model
    std::cout << "[1/5] Loading model...\n";
    auto t0 = std::chrono::high_resolution_clock::now();
    if (!engine.LoadModel(modelPath)) {
        std::cerr << "FAIL: Model load failed\n";
        return 3;
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double loadMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "  Load time: " << std::fixed << std::setprecision(1) << loadMs << " ms\n";
    std::cout << "  Vocab size: " << engine.GetVocabSize() << "\n";
    std::cout << "  Embedding dim: " << engine.GetEmbeddingDim() << "\n";
    std::cout << "  Layers: " << engine.GetNumLayers() << "\n";
    std::cout << "  Heads: " << engine.GetNumHeads() << "\n\n";

    // Tokenize
    std::cout << "[2/5] Tokenizing prompt...\n";
    auto toks = engine.Tokenize(prompt);
    std::cout << "  Token count: " << toks.size() << "\n";
    std::cout << "  Token IDs: ";
    for (size_t i = 0; i < toks.size() && i < 20; ++i) {
        std::cout << toks[i] << (i + 1 < toks.size() && i + 1 < 20 ? "," : "");
    }
    if (toks.size() > 20) std::cout << " ...";
    std::cout << "\n";
    std::cout << "  Detokenize check: \"" << engine.Detokenize(toks) << "\"\n\n";

    // Single forward pass (prefill)
    std::cout << "[3/5] Running prefill forward pass...\n";
    auto t2 = std::chrono::high_resolution_clock::now();
    std::vector<float> logits = engine.Eval(toks);
    auto t3 = std::chrono::high_resolution_clock::now();
    double prefillMs = std::chrono::duration<double, std::milli>(t3 - t2).count();
    if (logits.empty()) {
        std::cerr << "FAIL: Forward pass returned empty logits\n";
        return 4;
    }
    bool allFinite = true;
    float maxLogit = -1e30f;
    int bestTok = 0;
    for (size_t i = 0; i < logits.size(); ++i) {
        if (!std::isfinite(logits[i])) { allFinite = false; break; }
        if (logits[i] > maxLogit) { maxLogit = logits[i]; bestTok = static_cast<int>(i); }
    }
    std::cout << "  Logit count: " << logits.size() << "\n";
    std::cout << "  All finite: " << (allFinite ? "YES" : "NO") << "\n";
    std::cout << "  Max logit: " << maxLogit << " (token " << bestTok << ")\n";
    std::cout << "  Prefill time: " << std::fixed << std::setprecision(1) << prefillMs << " ms\n\n";

    // Greedy decode
    std::cout << "[4/5] Greedy decode (" << decodeLimit << " tokens)...\n";
    int32_t last = toks.empty() ? 1 : toks.back();
    std::vector<int32_t> generated;
    auto t4 = std::chrono::high_resolution_clock::now();
    std::vector<double> stepMs;
    for (int i = 0; i < decodeLimit; ++i) {
        auto stepStart = std::chrono::high_resolution_clock::now();
        std::vector<float> stepLogits = engine.Eval(std::vector<int32_t>{last});
        if (stepLogits.empty()) break;
        size_t best = 0;
        for (size_t j = 1; j < stepLogits.size(); ++j)
            if (stepLogits[j] > stepLogits[best]) best = j;
        last = static_cast<int32_t>(best);
        if (last <= 0) break;
        generated.push_back(last);
        auto stepEnd = std::chrono::high_resolution_clock::now();
        stepMs.push_back(std::chrono::duration<double, std::milli>(stepEnd - stepStart).count());
    }
    auto t5 = std::chrono::high_resolution_clock::now();
    double decodeMs = std::chrono::duration<double, std::milli>(t5 - t4).count();
    std::cout << "  Generated tokens: " << generated.size() << "\n";
    std::cout << "  Token IDs: ";
    for (size_t i = 0; i < generated.size(); ++i) {
        std::cout << generated[i] << (i + 1 < generated.size() ? ", " : "");
    }
    std::cout << "\n";
    std::cout << "  Decode time: " << std::fixed << std::setprecision(1) << decodeMs << " ms\n\n";
    if (!stepMs.empty()) {
        std::cout << "  Per-token decode ms: ";
        for (size_t i = 0; i < stepMs.size(); ++i)
            std::cout << std::fixed << std::setprecision(1) << stepMs[i]
                      << (i + 1 < stepMs.size() ? ", " : "");
        std::cout << "\n";
        std::cout << "  Decode TPS: " << std::fixed << std::setprecision(6)
                  << (1000.0 * stepMs.size() / decodeMs) << "\n\n";
    }

    // Detokenize generated tokens
    std::cout << "[5/5] Detokenizing generated output...\n";
    std::string decoded = engine.Detokenize(generated);
    std::cout << "  Generated text: \"" << decoded << "\"\n\n";

    std::cout << "=== E2E TEST COMPLETE ===\n";
    return 0;
}
