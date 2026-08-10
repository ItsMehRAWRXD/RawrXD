// ============================================================================
// b009a_fast_validation.cpp — Fast B009-A Correctness Validation
// Tests only {1, 3, 10} tokens for quick iteration.
// ============================================================================
#include "rawrxd_transformer.h"
#include "rawrxd_model_loader.h"
#include "rawrxd_tokenizer.h"

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <chrono>
#include <vector>
#include <string>

namespace {

constexpr float TOLERANCE_ABSOLUTE = 1e-4f;
constexpr float TOLERANCE_RELATIVE = 1e-3f;

bool WithinTolerance(float a, float b) {
    float diff = std::fabs(a - b);
    float max_val = std::max(std::fabs(a), std::fabs(b));
    if (max_val < 1e-6f) return diff < TOLERANCE_ABSOLUTE;
    return diff < TOLERANCE_ABSOLUTE || (diff / max_val) < TOLERANCE_RELATIVE;
}

bool LogitsMatch(const std::vector<float>& a, const std::vector<float>& b, float& max_diff, float& max_rel_diff) {
    if (a.size() != b.size()) return false;
    max_diff = 0.0f;
    max_rel_diff = 0.0f;
    for (size_t i = 0; i < a.size(); ++i) {
        float diff = std::fabs(a[i] - b[i]);
        max_diff = std::max(max_diff, diff);
        float max_val = std::max(std::fabs(a[i]), std::fabs(b[i]));
        if (max_val > 1e-6f) {
            max_rel_diff = std::max(max_rel_diff, diff / max_val);
        }
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (!WithinTolerance(a[i], b[i])) return false;
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    const char* modelEnv = std::getenv("RAWRXD_TEST_MODEL");
    if (!modelEnv || !*modelEnv) {
        std::printf("SKIP: set RAWRXD_TEST_MODEL to run B009-A fast validation\n");
        return 0;
    }

    RawrXDModelLoader loader;
    std::wstring wPath(modelEnv, modelEnv + std::strlen(modelEnv));
    if (!loader.Load(wPath.c_str(), nullptr, nullptr)) {
        std::printf("FAIL: could not load model\n");
        return 2;
    }

    RawrXDTransformer::Config cfg{};
    cfg.dim = loader.getDim();
    cfg.hidden_dim = loader.getFFNDim();
    cfg.n_layers = loader.getLayers();
    cfg.n_heads = loader.getHeads();
    cfg.n_kv_heads = loader.getKVHeads();
    cfg.vocab_size = loader.getVocabSize();
    cfg.rope_theta = 10000.0f;
    cfg.rms_norm_eps = 1e-5f;

    if (cfg.dim == 0) cfg.dim = 4096;
    if (cfg.n_layers == 0) cfg.n_layers = 32;
    if (cfg.n_heads == 0) cfg.n_heads = 32;
    if (cfg.n_kv_heads == 0) cfg.n_kv_heads = cfg.n_heads;

    RawrXDTokenizer tokenizer;
    tokenizer.Load("vocab.json");

    const std::vector<int> prompt_lengths = {1, 3, 10};
    const std::string base_prompt = "The quick brown fox jumps over the lazy dog. ";
    bool all_passed = true;

    for (int plen : prompt_lengths) {
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

        std::printf("\n[B009-A] Testing prompt length=%zu (requested=%d)\n", tokens.size(), plen);

        // B008 reference
        RawrXDTransformer ref_transformer;
        ref_transformer.Initialize(nullptr, nullptr, cfg, &loader);
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_b008 = ref_transformer.Forward(tokens, 0);
        auto t1 = std::chrono::high_resolution_clock::now();
        double b008_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        // B009-A ForwardBatch
        RawrXDTransformer batch_transformer;
        batch_transformer.Initialize(nullptr, nullptr, cfg, &loader);
        t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_b009 = batch_transformer.ForwardBatch(tokens, 0);
        t1 = std::chrono::high_resolution_clock::now();
        double b009_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        float max_diff = 0.0f, max_rel_diff = 0.0f;
        bool match = LogitsMatch(logits_b008, logits_b009, max_diff, max_rel_diff);

        if (match) {
            std::printf("  MATCH at length=%d: max_diff=%.6f max_rel=%.6f (B008=%.1fms B009=%.1fms)\n",
                        plen, max_diff, max_rel_diff, b008_ms, b009_ms);
        } else {
            std::printf("  MISMATCH at length=%d: max_diff=%.6f max_rel=%.6f (B008=%.1fms B009=%.1fms)\n",
                        plen, max_diff, max_rel_diff, b008_ms, b009_ms);
            all_passed = false;
        }
    }

    std::printf("\n========================================\n");
    if (all_passed) {
        std::printf("PASS: B009-A fast validation (all lengths MATCH)\n");
        return 0;
    } else {
        std::printf("FAIL: B009-A fast validation (some lengths MISMATCH)\n");
        return 1;
    }
}
