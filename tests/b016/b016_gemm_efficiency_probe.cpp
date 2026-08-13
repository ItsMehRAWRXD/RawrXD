// ============================================================================
// b016_gemm_efficiency_probe.cpp — B016: GEMM Efficiency Instrumentation
// Purpose: Measure per-kernel GFLOP/s, arithmetic intensity, and bottleneck
//          classification for the 154 batched AVX-512 GEMMs in B009.
// ============================================================================
#include "rawrxd_transformer.h"
#include "rawrxd_model_loader.h"
#include "rawrxd_tokenizer.h"
#include "inference/NegativeSpaceProfiler.hpp"

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <chrono>

int main(int argc, char** argv)
{
    const char* modelEnv = std::getenv("RAWRXD_TEST_MODEL");
    if (!modelEnv || !*modelEnv) {
        std::printf("[B016] SKIP: set RAWRXD_TEST_MODEL to run B016 GEMM efficiency probe\n");
        return 0;
    }

    const std::string modelPath(modelEnv);

    // ========================================================================
    // Load model
    // ========================================================================
    RawrXDModelLoader loader;
    std::wstring wPath(modelPath.begin(), modelPath.end());
    if (!loader.Load(wPath.c_str(), nullptr, nullptr)) {
        std::printf("[B016] FAIL: could not load model\n");
        return 2;
    }

    RawrXDTransformer::Config cfg{};
    cfg.dim               = loader.getDim();
    cfg.hidden_dim        = loader.getFFNDim();
    cfg.n_layers          = loader.getLayers();
    cfg.n_heads           = loader.getHeads();
    cfg.n_kv_heads        = loader.getKVHeads();
    cfg.vocab_size        = loader.getVocabSize();
    cfg.rope_theta        = 10000.0f;
    cfg.rms_norm_eps      = 1e-5f;
    cfg.weight_residency_pool_max_bytes = 4ULL * 1024 * 1024 * 1024; // 4096 MB

    if (cfg.dim == 0) cfg.dim = 4096;
    if (cfg.n_layers == 0) cfg.n_layers = 32;
    if (cfg.n_heads == 0) cfg.n_heads = 32;
    if (cfg.n_kv_heads == 0) cfg.n_kv_heads = cfg.n_heads;

    RawrXDTokenizer tokenizer;
    tokenizer.Load("vocab.json");

    const int plen = 128;
    const std::string base_prompt = "The quick brown fox jumps over the lazy dog. ";
    std::string prompt;
    while (static_cast<int>(prompt.size()) < plen * 4) {
        prompt += base_prompt;
    }
    std::vector<uint32_t> tokens = tokenizer.Encode(prompt);
    if (tokens.size() > static_cast<size_t>(plen)) {
        tokens.resize(plen);
    }
    if (tokens.empty()) {
        tokens.resize(plen, 1);
    }

    std::printf("[B016] GEMM Efficiency Probe\n");
    std::printf("[B016] Model: %s\n", modelPath.c_str());
    std::printf("[B016] Prompt length=%zu (requested=%d)\n", tokens.size(), plen);
    std::printf("[B016] --------------------------------------------------------------\n");

    // ========================================================================
    // Warm-up forward to populate residency pool
    // ========================================================================
    {
        RawrXDTransformer warmupTransformer;
        warmupTransformer.Initialize(nullptr, nullptr, cfg, &loader);
        std::printf("[B016] Warm-up ForwardBatch (T=%zu) to populate residency pool...\n", tokens.size());
        std::vector<float> warmupLogits = warmupTransformer.ForwardBatch(tokens, 0);
        std::printf("[B016] Warm-up complete. Logits size=%zu\n", warmupLogits.size());
    }

    // ========================================================================
    // Instrumented forward: collect per-GEMM records
    // ========================================================================
    RawrXDTransformer transformer;
    transformer.Initialize(nullptr, nullptr, cfg, &loader);

    std::printf("[B016] Instrumented ForwardBatch (T=%zu) for GEMM efficiency...\n", tokens.size());
    auto t0 = std::chrono::high_resolution_clock::now();
    std::vector<float> logits = transformer.ForwardBatch(tokens, 0);
    auto t1 = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::printf("[B016] ForwardBatch complete in %.2f ms\n", totalMs);

    // ========================================================================
    // The built-in B009-P4 GEMM efficiency report is printed automatically
    // by ForwardBatch at the end of execution.
    // ========================================================================

    // ========================================================================
    // Additional B016-specific analysis: theoretical vs achieved
    // ========================================================================
    std::printf("\n[B016] Additional Analysis: Theoretical vs Achieved\n");
    std::printf("--------------------------------------------------------------\n");

    // For this CPU, assume a conservative AVX-512 theoretical peak.
    // A modern Intel/AMD with AVX-512 can sustain ~50-100 GFLOP/s per core
    // on well-structured GEMMs. We'll use 80 GFLOP/s as a reference.
    constexpr double REFERENCE_PEAK_GFLOPS = 80.0;

    std::printf("[B016] Reference peak (conservative AVX-512): %.1f GFLOP/s\n", REFERENCE_PEAK_GFLOPS);
    std::printf("[B016] If achieved << %.1f, kernel is likely memory-bound or under-vectorized.\n",
                REFERENCE_PEAK_GFLOPS * 0.5);

    std::printf("\n[B016] --------------------------------------------------------------\n");
    std::printf("[B016] VERDICT:\n");
    std::printf("[B016]  - If overall GFLOP/s < %.1f: investigate memory bandwidth or packing.\n",
                REFERENCE_PEAK_GFLOPS * 0.25);
    std::printf("[B016]  - If AI < 8 FLOP/byte: memory-bound; consider blocking / tiling.\n");
    std::printf("[B016]  - If AI > 8 and GFLOP/s < %.1f: vector-underutilized; investigate loop overhead.\n",
                REFERENCE_PEAK_GFLOPS * 0.5);
    std::printf("[B016]  - If achieved ~%.1f+: compute-bound; optimization must reduce FLOPs or use more cores.\n",
                REFERENCE_PEAK_GFLOPS * 0.75);
    std::printf("[B016] --------------------------------------------------------------\n");

    // Negative Space Profiler: analyze bottlenecks
    rawrxd::Profiler_AnalyzeBottlenecks();

    return 0;
}
