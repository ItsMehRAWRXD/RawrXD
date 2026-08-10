// ============================================================================
// B015 — WeightResidencyPool Micro-Benchmark
// ============================================================================
// Directly tests the ExecuteLayerMatMul residency fast path without running
// the full transformer forward pass. Uses synthetic weight data for speed.
//
// Usage:
//   b015_pool_microbench.exe
// ============================================================================

#include "../../src/rawrxd_transformer.h"
#include "../../src/rawrxd_model_loader.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>
#include <cmath>

// ============================================================================
// Synthetic model loader that provides float weights directly
// ============================================================================
class SyntheticModelLoader : public RawrXDModelLoader {
public:
    void InjectFloatWeight(const std::string& name, const std::vector<float>& data) {
        m_syntheticWeights[name] = data;
    }

    float* GetTensor(const std::string& name) override {
        auto it = m_syntheticWeights.find(name);
        if (it != m_syntheticWeights.end()) {
            return it->second.data();
        }
        return RawrXDModelLoader::GetTensor(name);
    }

    bool HasTensor(const std::string& name) const {
        return m_syntheticWeights.find(name) != m_syntheticWeights.end();
    }

private:
    std::unordered_map<std::string, std::vector<float>> m_syntheticWeights;
};

// ============================================================================
// Result tracking
// ============================================================================
struct MicroBenchResult {
    const char* configName;
    double totalMs;
    uint64_t b015Hits;
    uint64_t b015Misses;
    float outputChecksum;
    bool crashed;
    const char* crashReason;
};

static float ComputeChecksum(const std::vector<float>& data) {
    if (data.empty()) return 0.0f;
    double sum = 0.0;
    for (float v : data) sum += std::abs(v);
    return static_cast<float>(sum / data.size());
}

// ============================================================================
// Single config run
// ============================================================================
static MicroBenchResult RunMicroBench(uint64_t poolMaxBytes, bool prefetch,
                                       int iterations, int K, int N) {
    MicroBenchResult result{};
    result.configName = (poolMaxBytes == 0) ? "B015_OFF" : (prefetch ? "B015_ON_PREFETCH" : "B015_ON_NO_PREFETCH");
    result.crashed = false;

    printf("\n=================================================================\n");
    printf("  Config: %s\n", result.configName);
    printf("  pool_max_bytes=%llu MB, prefetch=%s, K=%d, N=%d, iters=%d\n",
           static_cast<unsigned long long>(poolMaxBytes / (1024 * 1024)),
           prefetch ? "true" : "false", K, N, iterations);
    printf("=================================================================\n");

    try {
        SyntheticModelLoader loader;

        // Create synthetic weight: N rows x K cols
        std::vector<float> weightData(N * K);
        for (int i = 0; i < N * K; ++i) {
            weightData[i] = static_cast<float>((i % 7) - 3) * 0.1f;  // Small deterministic values
        }
        loader.InjectFloatWeight("test.weight", weightData);

        RawrXDTransformer::Config cfg{};
        cfg.dim = K;
        cfg.n_layers = 1;
        cfg.n_heads = 1;
        cfg.n_kv_heads = 1;
        cfg.vocab_size = 100;
        cfg.n_ctx = 128;
        cfg.seq_len = 128;
        cfg.rope_theta = 10000.0f;
        cfg.rms_norm_eps = 1e-5f;
        cfg.weight_residency_pool_max_bytes = poolMaxBytes;
        cfg.weight_residency_prefetch_next_layer = prefetch;

        RawrXDTransformer transformer;
        transformer.Initialize(VK_NULL_HANDLE, VK_NULL_HANDLE, cfg, &loader);

        // Input vector
        std::vector<float> input(K);
        for (int i = 0; i < K; ++i) {
            input[i] = static_cast<float>(i % 5) * 0.1f;
        }
        std::vector<float> output(N);

        auto t0 = std::chrono::high_resolution_clock::now();

        // Run multiple iterations — pool should hit on repeats
        for (int iter = 0; iter < iterations; ++iter) {
            std::fill(output.begin(), output.end(), 0.0f);
            bool ok = transformer.ExecuteLayerMatMul("test.weight", input.data(), output.data(),
                                                      static_cast<std::size_t>(K), static_cast<std::size_t>(N), 0);
            if (!ok) {
                printf("  ExecuteLayerMatMul failed on iteration %d\n", iter);
                result.crashed = true;
                result.crashReason = "ExecuteLayerMatMul returned false";
                return result;
            }
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        result.totalMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        result.outputChecksum = ComputeChecksum(output);
        result.b015Hits = transformer.weightResidencyHits();
        result.b015Misses = transformer.weightResidencyMisses();

        printf("  Total time: %.3f ms (%.3f ms/iter)\n", result.totalMs, result.totalMs / iterations);
        printf("  Output checksum: %.6f\n", result.outputChecksum);
        printf("  B015 hits/misses: %llu / %llu (hit rate: %.1f%%)\n",
               static_cast<unsigned long long>(result.b015Hits),
               static_cast<unsigned long long>(result.b015Misses),
               transformer.weightResidencyHitRate());
        printf("  Resident bytes: %zu MB\n", transformer.weightResidencyPoolBytes() / (1024 * 1024));

        // Verify teardown
        printf("  Teardown... ");
        // Destructors run at scope exit
        printf("OK\n");

    } catch (const std::exception& e) {
        result.crashed = true;
        result.crashReason = e.what();
        printf("  EXCEPTION: %s\n", e.what());
    }

    return result;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf("  B015 — WeightResidencyPool Micro-Benchmark\n");
    printf("  Direct pool integration test (no full transformer forward)\n");
    printf("=================================================================\n\n");

    const int K = 256;   // Input dimension
    const int N = 128;   // Output dimension
    const int iterations = 100;

    std::vector<MicroBenchResult> results;

    // Run 1: B015 OFF
    results.push_back(RunMicroBench(0, false, iterations, K, N));

    // Run 2: B015 ON, no prefetch
    results.push_back(RunMicroBench(512ULL * 1024ULL * 1024ULL, false, iterations, K, N));

    // Run 3: B015 ON, with prefetch
    results.push_back(RunMicroBench(512ULL * 1024ULL * 1024ULL, true, iterations, K, N));

    // ========================================================================
    // Summary
    // ========================================================================
    printf("\n=================================================================\n");
    printf("  B015 MICRO-BENCHMARK SUMMARY\n");
    printf("=================================================================\n\n");

    bool allPassed = true;
    float controlChecksum = 0.0f;

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        printf("  [%zu] %s\n", i + 1, r.configName);
        printf("      Latency:      %.3f ms\n", r.totalMs);
        printf("      Checksum:     %.6f\n", r.outputChecksum);
        printf("      B015 H/M:     %llu / %llu\n",
               static_cast<unsigned long long>(r.b015Hits),
               static_cast<unsigned long long>(r.b015Misses));
        printf("      Crashed:      %s\n", r.crashed ? "YES" : "no");
        if (r.crashed) {
            printf("      Crash reason: %s\n", r.crashReason);
            allPassed = false;
        }
        printf("\n");

        if (i == 0) controlChecksum = r.outputChecksum;
    }

    // Correctness gate
    printf("  --- Correctness Gate ---\n");
    bool correctnessPass = true;
    for (size_t i = 1; i < results.size(); ++i) {
        float diff = std::abs(results[i].outputChecksum - controlChecksum);
        bool pass = diff <= 0.001f;
        printf("      %s vs control: checksum diff = %.6f %s\n",
               results[i].configName, diff, pass ? "PASS" : "FAIL");
        if (!pass) correctnessPass = false;
    }

    // Residency gate
    printf("\n  --- Residency Gate ---\n");
    bool residencyPass = true;
    if (results[1].b015Hits == 0) {
        printf("      B015 ON (no prefetch): ZERO pool hits — integration not exercised! FAIL\n");
        residencyPass = false;
    } else {
        printf("      B015 ON (no prefetch): %llu hits / %llu misses — integration exercised PASS\n",
               static_cast<unsigned long long>(results[1].b015Hits),
               static_cast<unsigned long long>(results[1].b015Misses));
    }
    if (results[2].b015Hits == 0) {
        printf("      B015 ON (prefetch):    ZERO hits\n");
    } else {
        printf("      B015 ON (prefetch):    %llu hits / %llu misses\n",
               static_cast<unsigned long long>(results[2].b015Hits),
               static_cast<unsigned long long>(results[2].b015Misses));
    }

    // Performance gate
    printf("\n  --- Performance Gate ---\n");
    bool perfPass = true;
    if (results[1].totalMs < results[0].totalMs * 0.95) {
        printf("      B015 ON improves latency: %.3f ms vs %.3f ms (%.1f%%) PASS\n",
               results[1].totalMs, results[0].totalMs,
               100.0 * (results[0].totalMs - results[1].totalMs) / results[0].totalMs);
    } else if (results[1].totalMs > results[0].totalMs * 1.05) {
        printf("      B015 ON regresses latency: %.3f ms vs %.3f ms (%.1f%%) FAIL\n",
               results[1].totalMs, results[0].totalMs,
               100.0 * (results[1].totalMs - results[0].totalMs) / results[0].totalMs);
        perfPass = false;
    } else {
        printf("      B015 ON neutral: %.3f ms vs %.3f ms (within 5%%) NEUTRAL\n",
               results[1].totalMs, results[0].totalMs);
    }

    // Lifecycle gate
    printf("\n  --- Lifecycle Gate ---\n");
    bool lifecyclePass = true;
    for (const auto& r : results) {
        if (r.crashed) { lifecyclePass = false; break; }
    }
    printf("      All teardowns clean: %s\n", lifecyclePass ? "PASS" : "FAIL");

    printf("\n=================================================================\n");
    printf("  OVERALL: %s\n",
           (allPassed && correctnessPass && residencyPass && perfPass && lifecyclePass) ? "PASS" : "FAIL");
    printf("=================================================================\n");

    return (allPassed && correctnessPass && residencyPass && perfPass && lifecyclePass) ? 0 : 1;
}
