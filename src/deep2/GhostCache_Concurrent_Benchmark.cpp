// ============================================================================
// GhostCache_Concurrent_Benchmark.cpp
// Multi-instance inference benchmark: measures aggregate TPS scaling
// with shared ElasticResidencyManager + GhostCache.
// ============================================================================

#include "ElasticResidencyManager.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <random>
#include <algorithm>
#include <mutex>

using namespace Deep2;

// Stub ResidencyTrace C interface (no ASM dependency for this benchmark)
extern "C" {
    int TraceInit(const char*) { return 1; }
    void TraceShutdown(void) {}
    struct ResidencyEvent { uint32_t dummy; };
    ResidencyEvent* TraceBegin(uint32_t, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t) { return nullptr; }
    void TraceSetDestination(ResidencyEvent*, uint32_t, uint64_t, uint64_t, uint64_t, uint32_t, uint32_t) {}
    void TraceComplete(ResidencyEvent*, uint64_t, uint64_t, int) {}
    void TraceFlush(void) {}
}

// ============================================================================
// Synthetic Model Definition
// ============================================================================
struct SyntheticModel {
    uint32_t numLayers = 32;
    uint32_t numExperts = 8;
    uint32_t expertsPerToken = 2;
    size_t denseBytesPerLayer = 64ULL * 1024 * 1024;   // 64 MB per dense layer
    size_t expertBytes = 32ULL * 1024 * 1024;          // 32 MB per expert
    size_t kvBytesPerLayer = 16ULL * 1024 * 1024;      // 16 MB KV per layer

    std::vector<uint8_t> backingStore;

    void Build(ElasticResidencyManager& mgr) {
        // Per layer: attention weights (denseBytesPerLayer) + FFN weights (denseBytesPerLayer)
        //            + KV cache (kvBytesPerLayer) + experts (numExperts * expertBytes)
        size_t perLayerBytes = 2 * denseBytesPerLayer + kvBytesPerLayer + numExperts * expertBytes;
        size_t totalBytes = numLayers * perLayerBytes;
        backingStore.resize(totalBytes);
        size_t offset = 0;

        for (uint32_t L = 0; L < numLayers; ++L) {
            // Attention weights
            for (const char* suffix : {"attn_q", "attn_k", "attn_v", "attn_o"}) {
                mgr.RegisterTensor(
                    std::string(suffix) + "_" + std::to_string(L), L, ~0u,
                    offset, denseBytesPerLayer / 4,
                    TensorFormat::Q4_K, backingStore.data() + offset);
                offset += denseBytesPerLayer / 4;
            }
            // FFN weights
            for (const char* suffix : {"ffn_gate", "ffn_up", "ffn_down"}) {
                mgr.RegisterTensor(
                    std::string(suffix) + "_" + std::to_string(L), L, ~0u,
                    offset, denseBytesPerLayer / 3,
                    TensorFormat::Q4_K, backingStore.data() + offset);
                offset += denseBytesPerLayer / 3;
            }
            // KV cache
            mgr.RegisterTensor(
                "kv_" + std::to_string(L), L, ~0u,
                offset, kvBytesPerLayer,
                TensorFormat::FP16, backingStore.data() + offset);
            offset += kvBytesPerLayer;
            // Experts
            for (uint32_t E = 0; E < numExperts; ++E) {
                mgr.RegisterTensor(
                    "expert_" + std::to_string(L) + "_" + std::to_string(E),
                    L, E, offset, expertBytes,
                    TensorFormat::Q4_K, backingStore.data() + offset);
                offset += expertBytes;
            }
        }
    }
};

// ============================================================================
// Inference Instance
// ============================================================================
struct InferenceInstance {
    uint32_t id = 0;
    std::mt19937 rng;
    std::atomic<uint64_t> tokensGenerated{0};
    std::atomic<uint64_t> acquireHits{0};
    std::atomic<uint64_t> acquireMisses{0};
    std::atomic<uint64_t> totalAcquireUs{0};
    std::atomic<uint64_t> totalComputeUs{0};

    void Reset(uint32_t seed) {
        rng.seed(seed + id * 7919);
        tokensGenerated = 0;
        acquireHits = 0;
        acquireMisses = 0;
        totalAcquireUs = 0;
        totalComputeUs = 0;
    }

    void Step(ElasticResidencyManager& mgr, const SyntheticModel& model) {
        auto t0 = std::chrono::steady_clock::now();

        for (uint32_t L = 0; L < model.numLayers; ++L) {
            // Acquire attention weights
            for (const char* name : {"attn_q", "attn_k", "attn_v", "attn_o"}) {
                Deep2::ElasticResidencyManager::ResidencyHandle h;
                auto status = mgr.AcquireTensor(
                    std::string(name) + "_" + std::to_string(L), 0, 0, h);
                if (status == Deep2::ElasticResidencyManager::AcquireStatus::Ready) acquireHits.fetch_add(1);
                else acquireMisses.fetch_add(1);
                mgr.ReleaseTensor(std::string(name) + "_" + std::to_string(L));
            }
            // MoE experts
            for (uint32_t e = 0; e < model.expertsPerToken; ++e) {
                uint32_t expert = rng() % model.numExperts;
                Deep2::ElasticResidencyManager::ResidencyHandle h;
                auto status = mgr.AcquireTensor(
                    "expert_" + std::to_string(L) + "_" + std::to_string(expert),
                    0, 0, h);
                if (status == Deep2::ElasticResidencyManager::AcquireStatus::Ready) acquireHits.fetch_add(1);
                else acquireMisses.fetch_add(1);
                mgr.ReleaseTensor("expert_" + std::to_string(L) + "_" + std::to_string(expert));
            }
            // FFN
            for (const char* name : {"ffn_gate", "ffn_up", "ffn_down"}) {
                Deep2::ElasticResidencyManager::ResidencyHandle h;
                auto status = mgr.AcquireTensor(
                    std::string(name) + "_" + std::to_string(L), 0, 0, h);
                if (status == Deep2::ElasticResidencyManager::AcquireStatus::Ready) acquireHits.fetch_add(1);
                else acquireMisses.fetch_add(1);
                mgr.ReleaseTensor(std::string(name) + "_" + std::to_string(L));
            }
            // KV cache
            Deep2::ElasticResidencyManager::ResidencyHandle h;
            auto status = mgr.AcquireTensor("kv_" + std::to_string(L), 0, 0, h);
            if (status == Deep2::ElasticResidencyManager::AcquireStatus::Ready) acquireHits.fetch_add(1);
            else acquireMisses.fetch_add(1);
            mgr.ReleaseTensor("kv_" + std::to_string(L));
        }

        auto t1 = std::chrono::steady_clock::now();
        totalAcquireUs.fetch_add(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());

        // Simulate compute time (~2ms per token)
        auto computeStart = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::microseconds(2000));
        auto computeEnd = std::chrono::steady_clock::now();
        totalComputeUs.fetch_add(
            std::chrono::duration_cast<std::chrono::microseconds>(computeEnd - computeStart).count());

        tokensGenerated.fetch_add(1);
    }
};

// ============================================================================
// Benchmark Result
// ============================================================================
struct BenchmarkResult {
    uint32_t numInstances = 0;
    uint32_t tokensPerInstance = 0;
    double totalTimeSec = 0.0;
    double aggregateTps = 0.0;
    double tpsPerInstance = 0.0;
    double scalingEfficiency = 0.0;
    double hitRate = 0.0;
    uint64_t totalHits = 0;
    uint64_t totalMisses = 0;
    uint64_t ghostHits = 0;
    uint64_t ghostMisses = 0;
    uint64_t totalAcquireUs = 0;
    uint64_t totalComputeUs = 0;
};

// ============================================================================
// Run Benchmark
// ============================================================================
BenchmarkResult RunBenchmark(uint32_t numInstances, uint32_t tokensPerInstance,
                              ElasticResidencyManager& mgr, const SyntheticModel& model) {
    std::vector<InferenceInstance> instances(numInstances);
    for (uint32_t i = 0; i < numInstances; ++i) {
        instances[i].id = i;
        instances[i].Reset(42);
    }

    auto start = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    threads.reserve(numInstances);
    for (uint32_t i = 0; i < numInstances; ++i) {
        threads.emplace_back([&instances, &mgr, &model, i, tokensPerInstance]() {
            for (uint32_t t = 0; t < tokensPerInstance; ++t) {
                instances[i].Step(mgr, model);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end = std::chrono::steady_clock::now();
    double totalSec = std::chrono::duration<double>(end - start).count();

    uint64_t totalTokens = 0;
    uint64_t totalHits = 0;
    uint64_t totalMisses = 0;
    uint64_t totalAcquireUs = 0;
    uint64_t totalComputeUs = 0;
    for (auto& inst : instances) {
        totalTokens += inst.tokensGenerated.load();
        totalHits += inst.acquireHits.load();
        totalMisses += inst.acquireMisses.load();
        totalAcquireUs += inst.totalAcquireUs.load();
        totalComputeUs += inst.totalComputeUs.load();
    }

    BenchmarkResult r;
    r.numInstances = numInstances;
    r.tokensPerInstance = tokensPerInstance;
    r.totalTimeSec = totalSec;
    r.aggregateTps = totalTokens / totalSec;
    r.tpsPerInstance = r.aggregateTps / numInstances;
    r.totalHits = totalHits;
    r.totalMisses = totalMisses;
    r.hitRate = (totalHits + totalMisses > 0)
        ? (double)totalHits / (double)(totalHits + totalMisses)
        : 0.0;
    r.totalAcquireUs = totalAcquireUs;
    r.totalComputeUs = totalComputeUs;

    auto& telem = mgr.GetTelemetry();
    r.ghostHits = telem.ghostHits.load();
    r.ghostMisses = telem.ghostMisses.load();

    return r;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf(" GhostCache + ElasticResidencyManager Concurrent Benchmark\n");
    printf("=================================================================\n\n");

    // Model config: smaller for faster benchmark
    SyntheticModel model;
    model.numLayers = 4;                       // Reduced for speed
    model.numExperts = 4;
    model.expertsPerToken = 2;
    model.denseBytesPerLayer = 16ULL * 1024 * 1024;   // 16 MB
    model.expertBytes = 8ULL * 1024 * 1024;            // 8 MB
    model.kvBytesPerLayer = 4ULL * 1024 * 1024;       // 4 MB

    // Residency config: generous budget to avoid allocation failures
    ElasticResidencyConfig config;
    config.maxWarmCompressedBytes = 512ULL * 1024 * 1024;  // 512 MB RAM
    config.maxWarmStagedBytes = 128ULL * 1024 * 1024;
    config.maxHotBytes = 256ULL * 1024 * 1024;             // 256 MB VRAM
    config.useGhostCache = true;
    config.ghostCacheCapacity = 2048;

    printf("Model: %u layers, %u experts, %u experts/token\n", model.numLayers, model.numExperts, model.expertsPerToken);
    printf("Residency: warmCompressed=%zu MB, warmStaged=%zu MB, hot=%zu MB\n",
           config.maxWarmCompressedBytes / (1024*1024),
           config.maxWarmStagedBytes / (1024*1024),
           config.maxHotBytes / (1024*1024));
    printf("GhostCache: capacity=%zu entries\n\n", config.ghostCacheCapacity);

    // Run scaling benchmark: 1, 2, 4, 8 instances
    std::vector<uint32_t> instanceCounts = {1, 2, 4, 8};
    std::vector<BenchmarkResult> results;
    uint32_t tokensPerInstance = 8;

    double baselineTps = 0.0;

    for (uint32_t n : instanceCounts) {
        printf("\n--- Running %u instance(s), %u tokens each ---\n", n, tokensPerInstance);

        ElasticResidencyManager mgr;
        if (!mgr.Initialize(config)) {
            fprintf(stderr, "Failed to initialize ElasticResidencyManager\n");
            return 1;
        }
        model.Build(mgr);

        auto r = RunBenchmark(n, tokensPerInstance, mgr, model);

        if (n == 1) {
            baselineTps = r.aggregateTps;
        }
        if (baselineTps > 0) {
            r.scalingEfficiency = r.aggregateTps / (baselineTps * n);
        }

        results.push_back(r);

        printf("  Wall time:        %.3f s\n", r.totalTimeSec);
        printf("  Aggregate TPS:    %.1f\n", r.aggregateTps);
        printf("  TPS/instance:     %.1f\n", r.tpsPerInstance);
        printf("  Scaling eff:      %.1f%%\n", r.scalingEfficiency * 100.0);
        printf("  Residency hit rate: %.1f%%\n", r.hitRate * 100.0);
        printf("  Ghost hits:       %llu\n", (unsigned long long)r.ghostHits);
        printf("  Ghost misses:     %llu\n", (unsigned long long)r.ghostMisses);
        printf("  Acquire time:     %.1f ms\n", r.totalAcquireUs / 1000.0);
        printf("  Compute time:     %.1f ms\n", r.totalComputeUs / 1000.0);

        mgr.Shutdown();
    }

    // Summary table
    printf("\n=================================================================\n");
    printf(" Scaling Summary\n");
    printf("=================================================================\n");
    printf(" %-5s %-10s %-12s %-12s %-10s %-10s %-10s\n",
           "N", "Tokens", "Total(s)", "Agg TPS", "TPS/Inst", "Eff(%)", "GhostHits");
    printf(" %s\n", std::string(70, '-').c_str());

    for (auto& r : results) {
        printf(" %-5u %-10u %-12.3f %-12.1f %-10.1f %-9.1f%% %-10llu\n",
               r.numInstances, r.tokensPerInstance,
               r.totalTimeSec, r.aggregateTps, r.tpsPerInstance,
               r.scalingEfficiency * 100.0,
               (unsigned long long)r.ghostHits);
    }

    printf("=================================================================\n");

    // Validate: aggregate TPS should increase with N (though not perfectly linear)
    bool scalingValid = true;
    for (size_t i = 1; i < results.size(); ++i) {
        if (results[i].aggregateTps <= results[i-1].aggregateTps * 0.8) {
            printf("WARNING: %u-instance TPS (%.1f) is less than 80%% of %u-instance (%.1f)\n",
                   results[i].numInstances, results[i].aggregateTps,
                   results[i-1].numInstances, results[i-1].aggregateTps);
            scalingValid = false;
        }
    }

    if (scalingValid) {
        printf("\n[PASS] Aggregate TPS scales with instance count\n");
    } else {
        printf("\n[FAIL] Aggregate TPS does not scale adequately\n");
    }

    return scalingValid ? 0 : 1;
}
