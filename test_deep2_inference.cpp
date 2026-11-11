// ============================================================================
// test_deep2_inference.cpp - Headless Deep2 inference harness
// Loads a GGUF model via Deep2Engine and generates tokens.
// Verifies: model load, context allocation, sampling, token generation.
// ============================================================================

#include "Deep2Engine.h"
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <cstdio>

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: test_deep2_inference <model.gguf> [prompt]" << std::endl;
        return 1;
    }

    const std::string modelPath = argv[1];
    const std::string prompt = (argc > 2) ? argv[2] : "Hello";

    std::cout << "[TEST] Headless Deep2 Inference" << std::endl;
    std::cout << "  Model: " << modelPath << std::endl;
    std::cout << "  Prompt: " << prompt << std::endl;

    // ── Create engine ──────────────────────────────────────────
    Deep2::Deep2Engine engine;

    // ── Configure engine ───────────────────────────────────────
    Deep2::EngineConfig cfg;
    cfg.useKVCache = true;
    cfg.useThreadPool = false;   // deterministic for testing
    cfg.useRoPE = true;
    cfg.maxSeqLen = 0;           // resolved from GGUF metadata

    std::strncpy(cfg.modelPath, modelPath.c_str(), sizeof(cfg.modelPath) - 1);

    // ── Initialize ─────────────────────────────────────────────
    auto t0 = std::chrono::high_resolution_clock::now();
    if (!engine.initialize(cfg))
    {
        std::cerr << "FAIL: engine.initialize() returned false" << std::endl;
        return 1;
    }
    std::cout << "  initialize(): OK" << std::endl;

    // ── Load model ─────────────────────────────────────────────
    if (!engine.loadModel(modelPath))
    {
        std::cerr << "FAIL: engine.loadModel() returned false" << std::endl;
        return 1;
    }
    std::cout << "  loadModel(): OK" << std::endl;

    // ── Report metadata ────────────────────────────────────────
    const auto& meta = engine.getModelMetadata();
    std::cout << "  Architecture: " << meta.architecture << std::endl;
    std::cout << "  Layers: " << meta.numLayers << std::endl;
    std::cout << "  Hidden dim: " << meta.hiddenSize << std::endl;
    std::cout << "  Heads: " << meta.numHeads << std::endl;
    std::cout << "  KV Heads: " << meta.numKeyValueHeads << std::endl;
    std::cout << "  Vocab size: " << meta.vocabSize << std::endl;
    std::cout << "  Context length: " << meta.maxPositionEmbeddings << std::endl;

    // ── Configure sampling (non-greedy) ────────────────────────
    Deep2::GenerationOptions opts;
    opts.maxTokens = 64;
    opts.temperature = 0.7f;
    opts.topP = 0.9f;
    opts.topK = 40;
    opts.repeatPenalty = 1.0f;
    opts.minP = 0.0f;
    opts.seed = 0;

    engine.configureGeneration(opts);
    std::cout << "  Sampling: temperature=0.7 topP=0.9 topK=40 (non-greedy)" << std::endl;

    // ── Generate text ──────────────────────────────────────────
    std::cout << "  Generating..." << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();
    std::string output = engine.generateText(prompt, 64);
    auto t2 = std::chrono::high_resolution_clock::now();

    double genMs = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() / 1000.0;
    std::cout << "  Generation completed in " << genMs << " ms" << std::endl;
    std::cout << "  Output: " << output << std::endl;

    if (output.empty())
    {
        std::cerr << "FAIL: No output generated" << std::endl;
        return 1;
    }

    // ── Test greedy (temperature=0) ────────────────────────────
    std::cout << "\n[TEST] Greedy mode (temperature=0)" << std::endl;
    Deep2::GenerationOptions greedyOpts;
    greedyOpts.maxTokens = 32;
    greedyOpts.temperature = 0.0f;
    greedyOpts.topK = 1;
    greedyOpts.topP = 1.0f;
    engine.configureGeneration(greedyOpts);
    std::string greedyOutput = engine.generateText(prompt, 32);
    std::cout << "  Greedy output: " << greedyOutput << std::endl;

    if (greedyOutput.empty())
    {
        std::cerr << "FAIL: No greedy output generated" << std::endl;
        return 1;
    }

    // ── Test streaming ─────────────────────────────────────────
    std::cout << "\n[TEST] Streaming generation" << std::endl;
    Deep2::GenerationOptions streamOpts;
    streamOpts.maxTokens = 32;
    streamOpts.temperature = 0.7f;
    streamOpts.topP = 0.9f;
    streamOpts.topK = 40;

    std::string streamed;
    auto streamResult = engine.generateStream(prompt, streamOpts,
        [&](int32_t tokenId, const std::string& token) -> bool
        {
            streamed += token;
            std::cout << "  token[" << tokenId << "]: " << token << std::endl;
            return true;
        });

    std::cout << "  Stream completed: " << (streamResult.completed ? "YES" : "NO") << std::endl;
    std::cout << "  Stream tokens: " << streamResult.generatedTokens << std::endl;
    std::cout << "  Streamed text: " << streamed << std::endl;

    if (!streamResult.completed || streamResult.generatedTokens == 0)
    {
        std::cerr << "FAIL: Streaming did not generate tokens" << std::endl;
        return 1;
    }

    std::cout << "\n[PASS] All Deep2 inference tests passed" << std::endl;
    return 0;
}
