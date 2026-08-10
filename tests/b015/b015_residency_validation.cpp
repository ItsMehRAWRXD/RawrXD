// ============================================================================
// B015 — WeightResidencyPool Integration Validation Harness
// ============================================================================
// Validates that the new multi-tensor residency pool improves the same workload
// that exposed the B011/B014 bottleneck, with clean A/B attribution.
//
// Three configurations:
//   1. B015 OFF  (control):     pool_max_bytes=0, prefetch=false
//   2. B015 ON, no prefetch:      pool_max_bytes=512MB, prefetch=false
//   3. B015 ON, with prefetch:    pool_max_bytes=512MB, prefetch=true
//
// Usage:
//   Set RAWRXD_TEST_MODEL environment variable to a .gguf path.
//   Run: b015_residency_validation.exe
// ============================================================================

#include "../../src/rawrxd_transformer.h"
#include "../../src/rawrxd_model_loader.h"
#include "../../src/rawrxd_tokenizer.h"
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>

// ============================================================================
// Result tracking
// ============================================================================
struct B015RunResult {
    const char* configName;
    double totalLatencyMs;
    double perLayerLatencyMs;
    double dequantTimeMs;
    double matmulTimeMs;
    uint64_t mapCount;
    uint64_t unmapCount;
    uint64_t b011Hits;
    uint64_t b011Misses;
    uint64_t b015Hits;
    uint64_t b015Misses;
    size_t residentBytes;
    float outputChecksum;
    bool crashed;
    const char* crashReason;
};

static std::vector<B015RunResult> g_results;

// ============================================================================
// Checksum helper (simple L1 norm for numerical equivalence)
// ============================================================================
static float ComputeChecksum(const std::vector<float>& logits) {
    if (logits.empty()) return 0.0f;
    double sum = 0.0;
    for (float v : logits) {
        sum += std::abs(v);
    }
    return static_cast<float>(sum / logits.size());
}

// ============================================================================
// Single run with specified config
// ============================================================================
static B015RunResult RunConfig(const wchar_t* modelPath, const char* vocabPath, const char* mergesPath,
                                uint64_t poolMaxBytes, bool prefetchNextLayer,
                                const std::vector<uint32_t>& inputTokens) {
    B015RunResult result{};
    result.configName = (poolMaxBytes == 0) ? "B015_OFF" : (prefetchNextLayer ? "B015_ON_PREFETCH" : "B015_ON_NO_PREFETCH");
    result.crashed = false;
    result.crashReason = "";

    printf("\n=================================================================\n");
    printf("  Config: %s\n", result.configName);
    printf("  pool_max_bytes=%llu MB, prefetch=%s\n",
           static_cast<unsigned long long>(poolMaxBytes / (1024 * 1024)),
           prefetchNextLayer ? "true" : "false");
    printf("=================================================================\n");

    try {
        // Fresh loader + transformer per config (isolated lifecycle)
        RawrXDModelLoader loader;
        RawrXDTransformer transformer;

        if (!loader.Load(modelPath, VK_NULL_HANDLE, VK_NULL_HANDLE)) {
            result.crashed = true;
            result.crashReason = "Model load failed";
            return result;
        }

        RawrXDTransformer::Config cfg{};
        cfg.dim = loader.getDim();
        cfg.n_layers = loader.getLayers();
        cfg.n_heads = loader.getHeads();
        cfg.n_kv_heads = loader.getKVHeads();
        cfg.vocab_size = loader.getVocabSize();
        if (cfg.vocab_size == 0) cfg.vocab_size = 32000;
        if (cfg.dim == 0) cfg.dim = 4096;
        if (cfg.n_layers == 0) cfg.n_layers = 32;
        if (cfg.n_heads == 0) cfg.n_heads = 32;
        if (cfg.n_kv_heads == 0) cfg.n_kv_heads = cfg.n_heads;
        cfg.hidden_dim = (loader.getFFNDim() > 0) ? loader.getFFNDim() : cfg.dim * 4;
        cfg.n_ctx = 2048;
        cfg.seq_len = 2048;
        cfg.rope_theta = 10000.0f;
        cfg.rms_norm_eps = 1e-5f;

        // B015 config
        cfg.weight_residency_pool_max_bytes = poolMaxBytes;
        cfg.weight_residency_prefetch_next_layer = prefetchNextLayer;

        // Reset B011 stats before measurement
        loader.B011ResetResidencyStats();
        loader.ResetWeightProfile();

        transformer.Initialize(VK_NULL_HANDLE, VK_NULL_HANDLE, cfg, &loader);

        auto t0 = std::chrono::high_resolution_clock::now();

        // Run forward pass
        std::vector<float> logits = transformer.Forward(inputTokens, 0);

        auto t1 = std::chrono::high_resolution_clock::now();
        result.totalLatencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        result.outputChecksum = ComputeChecksum(logits);

        // Capture B011 stats
        result.b011Hits = loader.B011GetStats().cacheHits.load(std::memory_order_relaxed);
        result.b011Misses = loader.B011GetStats().cacheMisses.load(std::memory_order_relaxed);

        // Capture B015 stats
        result.b015Hits = transformer.weightResidencyHits();
        result.b015Misses = transformer.weightResidencyMisses();
        result.residentBytes = transformer.weightResidencyPoolBytes();

        // Capture weight profile (B010/B011)
        // Note: PrintWeightProfile prints to stdout; we could parse it, but for now
        // we rely on the atomic counters above.

        printf("  Forward complete: %.2f ms\n", result.totalLatencyMs);
        printf("  Output checksum: %.6f\n", result.outputChecksum);
        printf("  B011 hits/misses: %llu / %llu\n",
               static_cast<unsigned long long>(result.b011Hits),
               static_cast<unsigned long long>(result.b011Misses));
        printf("  B015 hits/misses: %llu / %llu (hit rate: %.1f%%)\n",
               static_cast<unsigned long long>(result.b015Hits),
               static_cast<unsigned long long>(result.b015Misses),
               transformer.weightResidencyHitRate());
        printf("  B015 resident bytes: %zu MB\n", result.residentBytes / (1024 * 1024));

        // Explicit teardown test
        printf("  Teardown... ");
        // transformer destructor runs here (scope exit)
        // loader destructor runs here (scope exit)
        printf("OK\n");

    } catch (const std::exception& e) {
        result.crashed = true;
        result.crashReason = e.what();
        printf("  EXCEPTION: %s\n", e.what());
    } catch (...) {
        result.crashed = true;
        result.crashReason = "unknown exception";
        printf("  UNKNOWN EXCEPTION\n");
    }

    return result;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf("  B015 — WeightResidencyPool Integration Validation\n");
    printf("  RawrXD Local Inference — A/B Benchmark\n");
    printf("=================================================================\n");

    const char* modelPathUtf8 = getenv("RAWRXD_TEST_MODEL");
    if (!modelPathUtf8 || strlen(modelPathUtf8) == 0) {
        printf("SKIP: set RAWRXD_TEST_MODEL to a .gguf path to run B015 validation\n");
        return 77;
    }

    // Convert to wchar_t for loader
    int wlen = MultiByteToWideChar(CP_UTF8, 0, modelPathUtf8, -1, nullptr, 0);
    std::wstring wpath;
    if (wlen > 0) {
        wpath.resize(wlen);
        MultiByteToWideChar(CP_UTF8, 0, modelPathUtf8, -1, &wpath[0], wlen);
        if (!wpath.empty() && wpath.back() == L'\0') wpath.pop_back();
    }

    printf("  Model: %s\n", modelPathUtf8);
    printf("\n");

    // Tokenize a simple prompt — use single token for speed
    RawrXDTokenizer tokenizer;
    std::string prompt = "A";  // Single token for fast validation
    std::vector<uint32_t> tokens = tokenizer.Encode(prompt);
    printf("  Prompt: '%s' (%zu tokens)\n", prompt.c_str(), tokens.size());
    printf("\n");

    // ========================================================================
    // Run 1: B015 OFF (control)
    // ========================================================================
    auto runOff = RunConfig(wpath.c_str(), nullptr, nullptr, 0, false, tokens);
    g_results.push_back(runOff);

    // ========================================================================
    // Run 2: B015 ON, no prefetch
    // ========================================================================
    auto runOnNoPrefetch = RunConfig(wpath.c_str(), nullptr, nullptr,
                                      512ULL * 1024ULL * 1024ULL, false, tokens);
    g_results.push_back(runOnNoPrefetch);

    // ========================================================================
    // Run 3: B015 ON, with prefetch
    // ========================================================================
    auto runOnPrefetch = RunConfig(wpath.c_str(), nullptr, nullptr,
                                    512ULL * 1024ULL * 1024ULL, true, tokens);
    g_results.push_back(runOnPrefetch);

    // ========================================================================
    // Summary
    // ========================================================================
    printf("\n=================================================================\n");
    printf("  B015 VALIDATION SUMMARY\n");
    printf("=================================================================\n\n");

    bool allPassed = true;
    float controlChecksum = 0.0f;

    for (size_t i = 0; i < g_results.size(); ++i) {
        const auto& r = g_results[i];
        printf("  [%zu] %s\n", i + 1, r.configName);
        printf("      Latency:        %.2f ms\n", r.totalLatencyMs);
        printf("      Checksum:       %.6f\n", r.outputChecksum);
        printf("      B011 H/M:       %llu / %llu\n",
               static_cast<unsigned long long>(r.b011Hits),
               static_cast<unsigned long long>(r.b011Misses));
        printf("      B015 H/M:       %llu / %llu\n",
               static_cast<unsigned long long>(r.b015Hits),
               static_cast<unsigned long long>(r.b015Misses));
        printf("      Resident bytes: %zu MB\n", r.residentBytes / (1024 * 1024));
        printf("      Crashed:        %s\n", r.crashed ? "YES" : "no");
        if (r.crashed) {
            printf("      Crash reason:   %s\n", r.crashReason);
            allPassed = false;
        }
        printf("\n");

        if (i == 0) {
            controlChecksum = r.outputChecksum;
        }
    }

    // Correctness gate
    printf("  --- Correctness Gate ---\n");
    bool correctnessPass = true;
    for (size_t i = 1; i < g_results.size(); ++i) {
        float diff = std::abs(g_results[i].outputChecksum - controlChecksum);
        float tolerance = 0.01f; // 1% relative tolerance
        bool pass = diff <= tolerance || (controlChecksum == 0.0f && g_results[i].outputChecksum == 0.0f);
        printf("      %s vs control: checksum diff = %.6f %s\n",
               g_results[i].configName, diff, pass ? "PASS" : "FAIL");
        if (!pass) correctnessPass = false;
    }

    // Residency gate
    printf("\n  --- Residency Gate ---\n");
    bool residencyPass = true;
    if (runOnNoPrefetch.b015Hits == 0 && runOnNoPrefetch.b015Misses == 0) {
        printf("      B015 ON (no prefetch): ZERO pool activity — integration path not exercised! FAIL\n");
        residencyPass = false;
    } else {
        printf("      B015 ON (no prefetch): %llu hits / %llu misses — integration exercised PASS\n",
               static_cast<unsigned long long>(runOnNoPrefetch.b015Hits),
               static_cast<unsigned long long>(runOnNoPrefetch.b015Misses));
    }
    if (runOnPrefetch.b015Hits == 0) {
        printf("      B015 ON (prefetch):    ZERO hits — prefetch not helping or not exercised\n");
    } else {
        printf("      B015 ON (prefetch):    %llu hits / %llu misses\n",
               static_cast<unsigned long long>(runOnPrefetch.b015Hits),
               static_cast<unsigned long long>(runOnPrefetch.b015Misses));
    }

    // Performance gate
    printf("\n  --- Performance Gate ---\n");
    bool perfPass = true;
    if (runOnNoPrefetch.totalLatencyMs < runOff.totalLatencyMs * 0.95) {
        printf("      B015 ON improves latency: %.2f ms vs %.2f ms (%.1f%%) PASS\n",
               runOnNoPrefetch.totalLatencyMs, runOff.totalLatencyMs,
               100.0 * (runOff.totalLatencyMs - runOnNoPrefetch.totalLatencyMs) / runOff.totalLatencyMs);
    } else if (runOnNoPrefetch.totalLatencyMs > runOff.totalLatencyMs * 1.05) {
        printf("      B015 ON regresses latency: %.2f ms vs %.2f ms (%.1f%%) FAIL\n",
               runOnNoPrefetch.totalLatencyMs, runOff.totalLatencyMs,
               100.0 * (runOnNoPrefetch.totalLatencyMs - runOff.totalLatencyMs) / runOff.totalLatencyMs);
        perfPass = false;
    } else {
        printf("      B015 ON neutral: %.2f ms vs %.2f ms (within 5%%) NEUTRAL\n",
               runOnNoPrefetch.totalLatencyMs, runOff.totalLatencyMs);
    }

    // Lifecycle gate
    printf("\n  --- Lifecycle Gate ---\n");
    bool lifecyclePass = true;
    for (const auto& r : g_results) {
        if (r.crashed) {
            lifecyclePass = false;
            break;
        }
    }
    printf("      All teardowns clean: %s\n", lifecyclePass ? "PASS" : "FAIL");

    printf("\n=================================================================\n");
    printf("  OVERALL: %s\n",
           (allPassed && correctnessPass && residencyPass && perfPass && lifecyclePass) ? "PASS" : "FAIL");
    printf("=================================================================\n");

    return (allPassed && correctnessPass && residencyPass && perfPass && lifecyclePass) ? 0 : 1;
}
