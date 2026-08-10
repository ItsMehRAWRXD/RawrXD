// ============================================================================
// b009_batched_prefill_certification.cpp — B009 Batched Prefill Certification
// Validates batched prefill correctness and performance against B008 reference.
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
#include <filesystem>
#include <numeric>
#include <algorithm>

namespace {

struct TestResult {
    const char* id;
    const char* description;
    bool passed;
    std::string detail;
};

std::vector<TestResult> results;

void Record(const char* id, const char* desc, bool passed, const std::string& detail = "") {
    results.push_back({id, desc, passed, detail});
}

bool Check(bool condition, const char* id, const char* desc, const std::string& detail = "") {
    Record(id, desc, condition, detail);
    return condition;
}

// ============================================================================
// Numerical tolerance for differential validation
// ============================================================================
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

// ============================================================================
// Benchmark metrics
// ============================================================================
struct PrefillMetrics {
    int prompt_tokens;
    double latency_ms;
    double tokens_per_sec;
    double first_token_latency_ms;
    double peak_memory_mb;
    size_t kv_cache_footprint_mb;
};

std::vector<PrefillMetrics> b008_metrics;
std::vector<PrefillMetrics> b009_metrics;

// ============================================================================
// B008 Reference: single-token sequential prefill (existing path)
// ============================================================================
std::vector<float> B008_ReferencePrefill(
    RawrXDTransformer& transformer,
    const std::vector<uint32_t>& tokens,
    int start_pos)
{
    // The existing Forward() already processes tokens sequentially.
    // For B008 reference, we call it directly.
    return transformer.Forward(tokens, start_pos);
}

// ============================================================================
// B009 Batched Prefill (layer-outer batched implementation)
// ============================================================================
std::vector<float> B009_BatchedPrefill(
    RawrXDTransformer& transformer,
    const std::vector<uint32_t>& tokens,
    int start_pos)
{
    return transformer.ForwardBatch(tokens, start_pos);
}

} // namespace

int main(int argc, char** argv) {
    const char* modelEnv = std::getenv("RAWRXD_TEST_MODEL");
    if (!modelEnv || !*modelEnv) {
        std::printf("SKIP: set RAWRXD_TEST_MODEL to run B009 certification\n");
        return 0;
    }

    const std::string modelPath(modelEnv);
    if (!std::filesystem::exists(modelPath)) {
        std::printf("FAIL: model path does not exist: %s\n", modelPath.c_str());
        return 2;
    }

    // ========================================================================
    // Load model
    // ========================================================================
    RawrXDModelLoader loader;
    std::wstring wPath(modelPath.begin(), modelPath.end());
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

    RawrXDTransformer transformer;
    transformer.Initialize(nullptr, nullptr, cfg, &loader);

    // Tokenizer for prompt encoding
    RawrXDTokenizer tokenizer;
    tokenizer.Load("vocab.json");

    // ========================================================================
    // Test prompts at different lengths
    // ========================================================================
    const std::vector<int> prompt_lengths = {1, 3, 10, 32, 128};
    const std::string base_prompt = "The quick brown fox jumps over the lazy dog. ";

    bool all_correctness_passed = true;

    for (int plen : prompt_lengths) {
        // Build prompt of approximately plen tokens
        std::string prompt;
        while (static_cast<int>(prompt.size()) < plen * 4) {
            prompt += base_prompt;
        }

        std::vector<uint32_t> tokens = tokenizer.Encode(prompt);
        if (tokens.size() > static_cast<size_t>(plen)) {
            tokens.resize(plen);
        }
        if (tokens.empty()) {
            tokens.resize(plen, 1); // fallback: repeat token 1
        }

        std::printf("\n[B009] Testing prompt length=%zu (requested=%d)\n", tokens.size(), plen);

        // -------------------------------------------------------------------
        // B008 reference run (fresh transformer instance for isolation)
        // -------------------------------------------------------------------
        RawrXDTransformer ref_transformer;
        ref_transformer.Initialize(nullptr, nullptr, cfg, &loader);
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_b008 = B008_ReferencePrefill(ref_transformer, tokens, 0);
        auto t1 = std::chrono::high_resolution_clock::now();
        double b008_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        b008_metrics.push_back({
            static_cast<int>(tokens.size()),
            b008_ms,
            tokens.size() * 1000.0 / std::max(b008_ms, 0.001),
            b008_ms, // first token = total for prefill
            0.0,     // TODO: memory measurement
            0        // TODO: KV footprint
        });

        // -------------------------------------------------------------------
        // B009 batched run (fresh transformer instance for isolation)
        // -------------------------------------------------------------------
        RawrXDTransformer batch_transformer;
        batch_transformer.Initialize(nullptr, nullptr, cfg, &loader);
        t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_b009 = B009_BatchedPrefill(batch_transformer, tokens, 0);
        t1 = std::chrono::high_resolution_clock::now();
        double b009_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        b009_metrics.push_back({
            static_cast<int>(tokens.size()),
            b009_ms,
            tokens.size() * 1000.0 / std::max(b009_ms, 0.001),
            b009_ms,
            0.0,
            0
        });

        // -------------------------------------------------------------------
        // Differential validation
        // -------------------------------------------------------------------
        float max_diff = 0.0f, max_rel_diff = 0.0f;
        bool match = LogitsMatch(logits_b008, logits_b009, max_diff, max_rel_diff);

        char test_id[32];
        std::snprintf(test_id, sizeof(test_id), "B009-%03d", plen);
        char desc[128];
        std::snprintf(desc, sizeof(desc), "differential correctness (%d tokens)", plen);

        char detail[256];
        std::snprintf(detail, sizeof(detail),
                      "B008=%.2fms B009=%.2fms max_diff=%.6f max_rel=%.6f",
                      b008_ms, b009_ms, max_diff, max_rel_diff);

        bool ok = Check(match, test_id, desc, detail);
        all_correctness_passed = all_correctness_passed && ok;

        if (!match) {
            std::printf("  MISMATCH at length=%d: max_diff=%.6f max_rel=%.6f\n",
                        plen, max_diff, max_rel_diff);
        } else {
            std::printf("  MATCH at length=%d: max_diff=%.6f max_rel=%.6f\n",
                        plen, max_diff, max_rel_diff);
        }
    }

    // ========================================================================
    // Performance comparison table
    // ========================================================================
    std::printf("\n========================================\n");
    std::printf("  B009 Performance Comparison\n");
    std::printf("========================================\n");
    std::printf("%-8s %-12s %-12s %-12s %-12s\n",
                "Tokens", "B008(ms)", "B009(ms)", "Speedup", "Tokens/sec");
    for (size_t i = 0; i < b008_metrics.size(); ++i) {
        double speedup = b008_metrics[i].latency_ms / std::max(b009_metrics[i].latency_ms, 0.001);
        std::printf("%-8d %-12.2f %-12.2f %-12.2fx %-12.2f\n",
                    b008_metrics[i].prompt_tokens,
                    b008_metrics[i].latency_ms,
                    b009_metrics[i].latency_ms,
                    speedup,
                    b009_metrics[i].tokens_per_sec);
    }

    // ========================================================================
    // Summary
    // ========================================================================
    int passed = 0, failed = 0;
    for (const auto& r : results) {
        if (r.passed) {
            ++passed;
            std::printf("PASS %s: %s\n", r.id, r.description);
        } else {
            ++failed;
            std::printf("FAIL %s: %s — %s\n", r.id, r.description, r.detail.c_str());
        }
    }

    std::printf("\n");
    if (failed == 0) {
        std::printf("PASS: B009-A layer-outer ForwardBatch correctness validation (%d/%d)\n", passed, passed);
        std::printf("NOTE: B009-A validates numerical equivalence. B009-B batched GEMM performance TBD.\n");
        return 0;
    } else {
        std::printf("FAIL: B009-A layer-outer ForwardBatch correctness validation (%d passed, %d failed)\n", passed, failed);
        return 1;
    }
}
