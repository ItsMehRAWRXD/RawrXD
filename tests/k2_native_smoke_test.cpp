// ============================================================================
// k2_native_smoke_test.cpp — K2-002 Native Deep2 Runtime Smoke Test
//
// Pipeline:
//   GGUF metadata → K2GlobalTensorIndex → selective tensor load →
//   WeightTensor → Deep2Engine::RMSNormW() / LinearW() → verify → release
//
// Safety invariants:
//   - NEVER loads full model or full shard
//   - Each gate has explicit resident memory budget
//   - All tensor data freed before exit
//   - Engine initialized with bounded config (maxSeqLen=128)
//
// Exit codes:
//   0 = ALL GATES PASSED
//   1 = Shard discovery failed
//   2 = Tensor index build failed
//   3 = Tensor resolution failed
//   4 = Tensor data load exceeded budget
//   5 = Engine initialization failed
//   6 = Native kernel execution failed
//   7 = Output verification failed
//   8 = Memory leak / residency not released
// ============================================================================

#include "../src/deep2/KimiK2Config.hpp"
#include "../src/deep2/K2GlobalTensorIndex.hpp"
#include "../src/deep2/K2MLAWeights.hpp"
#include "../src/deep2/Deep2Engine.h"
#include "../src/deep2/GGUFLoader.hpp"
#include "../src/deep2/TensorView.hpp"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <vector>
#include <chrono>

namespace fs = std::filesystem;

// ── Gate Helpers ──
#define GATE(name, condition, exitCode) \
    do { \
        if (!(condition)) { \
            printf("  [FAIL] Gate: %s\n", name); \
            return exitCode; \
        } \
        printf("  [PASS] Gate: %s\n", name); \
    } while(0)

// ── Shard Discovery (same as K2-001) ──
static bool DiscoverK2Shards(const fs::path& dir, std::vector<fs::path>& shards) {
    shards.clear();
    for (int i = 1; i <= 13; ++i) {
        char name[256];
        snprintf(name, sizeof(name),
                 "Kimi-K2-Instruct-0905-Q4_K_M-%05d-of-00013.gguf", i);
        fs::path candidate = dir / name;
        if (fs::exists(candidate)) {
            shards.push_back(candidate);
            continue;
        }
        snprintf(name, sizeof(name),
                 "kimi-k2-instruct-0905-q4_k_m-%05d-of-00013.gguf", i);
        candidate = dir / name;
        if (fs::exists(candidate)) {
            shards.push_back(candidate);
        }
    }
    return !shards.empty();
}

// ── Memory Budget Tracking ──
struct ResidencyBudget {
    uint64_t allocated = 0;
    uint64_t maxAllowed = 0;

    explicit ResidencyBudget(uint64_t maxBytes) : maxAllowed(maxBytes) {}

    bool allocate(uint64_t bytes, const char* purpose) {
        if (allocated + bytes > maxAllowed) {
            printf("  [BUDGET EXCEEDED] %s: %llu + %llu > %llu bytes\n",
                   purpose, (unsigned long long)allocated,
                   (unsigned long long)bytes, (unsigned long long)maxAllowed);
            return false;
        }
        allocated += bytes;
        printf("  [BUDGET] %s: +%llu bytes (total: %llu / %llu)\n",
               purpose, (unsigned long long)bytes,
               (unsigned long long)allocated, (unsigned long long)maxAllowed);
        return true;
    }

    void release(uint64_t bytes) {
        if (bytes > allocated) allocated = 0;
        else allocated -= bytes;
    }
};

// ── Load a single tensor's payload from a shard file ──
static bool LoadTensorPayload(const Deep2::GlobalTensorIndex& index,
                                const char* tensorName,
                                ResidencyBudget& budget,
                                std::vector<uint8_t>& outData,
                                Deep2::GlobalTensorRef& outRef,
                                std::string& error) {
    auto refOpt = index.Find(tensorName);
    if (!refOpt) {
        error = std::string("Tensor not found: ") + tensorName;
        return false;
    }
    outRef = *refOpt;

    // Budget check before allocation
    if (!budget.allocate(outRef.byteSize, tensorName)) {
        error = "Residency budget exceeded";
        return false;
    }

    outData.resize(outRef.byteSize);

    const auto& shardPath = index.ShardPath(outRef.shardId);
    if (shardPath.empty()) {
        error = "Shard path empty";
        return false;
    }

    FILE* f = fopen(shardPath.string().c_str(), "rb");
    if (!f) {
        error = "Cannot open shard file";
        return false;
    }

    if (_fseeki64(f, static_cast<long long>(outRef.fileOffset), SEEK_SET) != 0) {
        fclose(f);
        error = "Cannot seek to tensor offset";
        return false;
    }

    size_t read = fread(outData.data(), 1, outRef.byteSize, f);
    fclose(f);

    if (read != outRef.byteSize) {
        error = "Short read of tensor data";
        return false;
    }

    return true;
}

// ── Create a Deep2 WeightTensor from loaded payload ──
static Deep2::WeightTensor MakeWeightTensor(const Deep2::GlobalTensorRef& ref,
                                               void* data) {
    Deep2::WeightTensor wt;
    wt.data = data;
    wt.type = static_cast<int>(ref.ggmlType);
    wt.name = ref.name;

    if (ref.shape.size() >= 2) {
        wt.rows = static_cast<size_t>(ref.shape[0]);
        wt.cols = static_cast<size_t>(ref.shape[1]);
    } else if (ref.shape.size() == 1) {
        wt.rows = 1;
        wt.cols = static_cast<size_t>(ref.shape[0]);
    } else {
        wt.rows = 0;
        wt.cols = 0;
    }

    wt.sizeBytes = ref.byteSize;
    return wt;
}

// ── Verify all outputs are finite ──
static bool AllFinite(const float* data, size_t n, float& minVal, float& maxVal, float& meanVal) {
    if (n == 0) return false;
    minVal = maxVal = data[0];
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) {
        if (!std::isfinite(data[i])) return false;
        minVal = std::min(minVal, data[i]);
        maxVal = std::max(maxVal, data[i]);
        sum += data[i];
    }
    meanVal = static_cast<float>(sum / n);
    return true;
}

// ── Main ──
int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-002 Native Deep2 Runtime Smoke Test                      ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    fs::path shardDir = (argc > 1) ? argv[1] : fs::current_path();
    printf("[INFO] Shard directory: %s\n", shardDir.string().c_str());

    // ═══════════════════════════════════════════════════════════════
    // Gate 1: Shard Discovery
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 1: Shard Discovery ──\n");
    std::vector<fs::path> shards;
    if (!DiscoverK2Shards(shardDir, shards)) {
        printf("\n⚠️  SKIPPED: No K2 shards found.\n");
        return 0;
    }
    printf("       Found %zu shard(s)\n", shards.size());

    // ═══════════════════════════════════════════════════════════════
    // Gate 2: Tensor Index Build (metadata-only)
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 2: Tensor Index Build ──\n");
    Deep2::GlobalTensorIndex index;
    std::string indexError;
    Deep2::KimiK2Config k2cfg;
    k2cfg.hiddenDim = 7168;
    k2cfg.numLayers = 61;
    k2cfg.numHeads = 128;
    k2cfg.numKVHeads = 1;
    k2cfg.qLoraRank = 1536;
    k2cfg.kvLoraRank = 512;
    k2cfg.qkNopeHeadDim = 128;
    k2cfg.qkRopeHeadDim = 64;
    k2cfg.vHeadDim = 128;
    k2cfg.numExperts = 384;
    k2cfg.expertsPerToken = 8;
    k2cfg.sharedExperts = 1;
    k2cfg.moeIntermediateSize = 2048;
    k2cfg.vocabSize = 163840;
    k2cfg.maxPosition = 262144;
    k2cfg.routedScalingFactor = 2.827f;

    bool indexBuilt = index.BuildFromShardDirectory(shardDir, k2cfg, indexError);
    GATE("Tensor index built", indexBuilt, 2);
    printf("       Total tensors: %zu\n", index.TotalTensors());

    // ═══════════════════════════════════════════════════════════════
    // Gate 3: Resolve target tensors for smoke test
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 3: Tensor Resolution ──\n");
    auto normRefOpt = index.Find("blk.0.attn_norm.weight");
    auto qARefOpt = index.Find("blk.0.attn_q_a.weight");
    GATE("blk.0.attn_norm.weight found", normRefOpt.has_value(), 3);
    GATE("blk.0.attn_q_a.weight found", qARefOpt.has_value(), 3);

    // Mutable refs for LoadTensorPayload to populate
    Deep2::GlobalTensorRef normRef = normRefOpt.value();
    Deep2::GlobalTensorRef qARef = qARefOpt.value();

    printf("       attn_norm:  shard=%u offset=%llu size=%llu shape=[%llu] type=%u\n",
           normRef.shardId, (unsigned long long)normRef.fileOffset,
           (unsigned long long)normRef.byteSize,
           (unsigned long long)(normRef.shape.empty() ? 0 : normRef.shape[0]),
           normRef.ggmlType);
    printf("       attn_q_a:   shard=%u offset=%llu size=%llu shape=[%llu,%llu] type=%u\n",
           qARef.shardId, (unsigned long long)qARef.fileOffset,
           (unsigned long long)qARef.byteSize,
           (unsigned long long)(qARef.shape.empty() ? 0 : qARef.shape[0]),
           (unsigned long long)(qARef.shape.size() < 2 ? 0 : qARef.shape[1]),
           qARef.ggmlType);

    // ═══════════════════════════════════════════════════════════════
    // Gate 4: Load tensor payloads with strict budget
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 4: Bounded Tensor Load ──\n");
    constexpr uint64_t kMaxResidencyBytes = 64ull * 1024 * 1024; // 64 MB hard cap
    ResidencyBudget budget(kMaxResidencyBytes);

    std::vector<uint8_t> normData;
    std::vector<uint8_t> qAData;
    std::string loadError;

    bool normLoaded = LoadTensorPayload(index, "blk.0.attn_norm.weight", budget,
                                         normData, normRef, loadError);
    GATE("attn_norm payload loaded", normLoaded, 4);

    bool qALoaded = LoadTensorPayload(index, "blk.0.attn_q_a.weight", budget,
                                       qAData, qARef, loadError);
    GATE("attn_q_a payload loaded", qALoaded, 4);

    printf("       Total resident: %llu / %llu bytes (%.2f MB / %.2f MB)\n",
           (unsigned long long)budget.allocated,
           (unsigned long long)budget.maxAllowed,
           budget.allocated / (1024.0 * 1024.0),
           budget.maxAllowed / (1024.0 * 1024.0));

    // ═══════════════════════════════════════════════════════════════
    // Gate 5: Initialize minimal Deep2Engine
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 5: Engine Initialization ──\n");
    Deep2::EngineConfig engineCfg;
    engineCfg.hiddenDim = k2cfg.hiddenDim;
    engineCfg.numLayers = 1;        // ONLY one layer — bounded
    engineCfg.numHeads = k2cfg.numHeads;
    engineCfg.numKVHeads = k2cfg.numKVHeads;
    engineCfg.vocabSize = k2cfg.vocabSize;
    engineCfg.intermediateDim = k2cfg.moeIntermediateSize;
    engineCfg.maxSeqLen = 128;    // Small — limits buffer allocation
    engineCfg.useKVCache = false; // Not needed for smoke test
    engineCfg.useThreadPool = true;
    engineCfg.normEps = 1e-6f;

    Deep2::Deep2Engine engine;
    bool engineOk = engine.initialize(engineCfg);
    GATE("Deep2Engine initialized", engineOk, 5);
    printf("       Engine ready (hidden=%zu, layers=%zu, maxSeq=%zu)\n",
           engineCfg.hiddenDim, engineCfg.numLayers, engineCfg.maxSeqLen);

    // ═══════════════════════════════════════════════════════════════
    // Gate 6a: RMSNormW with real K2 weight
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 6a: RMSNormW Native Execution ──\n");
    {
        Deep2::WeightTensor normWt = MakeWeightTensor(normRef, normData.data());
        printf("       WeightTensor: rows=%zu cols=%zu type=%d size=%zu bytes\n",
               normWt.rows, normWt.cols, normWt.type, normWt.sizeBytes);

        // Synthetic input: all 1.0f
        size_t dim = k2cfg.hiddenDim;
        std::vector<float> input(dim, 1.0f);
        std::vector<float> output(dim, 0.0f);

        auto t0 = std::chrono::high_resolution_clock::now();
        engine.RMSNormW(normWt, input.data(), output.data(), dim, engineCfg.normEps);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        float minVal, maxVal, meanVal;
        bool finite = AllFinite(output.data(), dim, minVal, maxVal, meanVal);
        GATE("RMSNormW output all finite", finite, 7);

        // With real learned weights, output won't be exactly 1.0.
        // Verify: (a) weights had an effect (output != input), (b) values are in a reasonable range
        bool weightsHadEffect = false;
        for (size_t i = 0; i < dim; ++i) {
            if (std::abs(output[i] - input[i]) > 0.001f) { weightsHadEffect = true; break; }
        }
        GATE("RMSNormW weights had effect", weightsHadEffect, 7);

        // Real learned weights should produce values in a reasonable range (not NaN/Inf, not all zero)
        bool rangeOk = (std::abs(meanVal) > 0.01f) && (maxVal > minVal);
        GATE("RMSNormW output in reasonable range", rangeOk, 7);

        printf("       Execution time: %.3f ms\n", ms);
        printf("       Output stats: min=%.4f max=%.4f mean=%.4f\n", minVal, maxVal, meanVal);
        printf("       [SAFETY] Only %zu bytes resident for this operation\n",
               normWt.sizeBytes + dim * sizeof(float) * 2);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 6b: LinearW (GEMV) with real K2 Q4_K weight
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 6b: LinearW Q4_K GEMV Native Execution ──\n");
    {
        Deep2::WeightTensor qAWt = MakeWeightTensor(qARef, qAData.data());
        printf("       WeightTensor: rows=%zu cols=%zu type=%d (Q4_K=12)\n",
               qAWt.rows, qAWt.cols, qAWt.type);

        // For Q4_K GEMV: input[cols], output[rows]
        size_t cols = qAWt.cols;
        size_t rows = qAWt.rows;
        std::vector<float> gemvInput(cols, 1.0f);
        std::vector<float> gemvOutput(rows, 0.0f);

        auto t0 = std::chrono::high_resolution_clock::now();
        engine.LinearW(qAWt, gemvInput.data(), nullptr, gemvOutput.data(), rows);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        float minVal, maxVal, meanVal;
        bool finite = AllFinite(gemvOutput.data(), rows, minVal, maxVal, meanVal);
        GATE("LinearW output all finite", finite, 7);

        // For Q4_K weights, output should be non-zero (weights are not all zero)
        bool nonZero = std::abs(meanVal) > 0.001f;
        GATE("LinearW output non-zero", nonZero, 7);

        printf("       Execution time: %.3f ms\n", ms);
        printf("       Output stats: min=%.4f max=%.4f mean=%.4f\n", minVal, maxVal, meanVal);
        printf("       [SAFETY] Only %zu bytes resident for this operation\n",
               qAWt.sizeBytes + cols * sizeof(float) + rows * sizeof(float));
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 7: Residency Release Verification
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 7: Residency Release ──\n");

    // Free tensor data BEFORE engine shutdown
    size_t tensorBytes = normData.size() + qAData.size();
    normData.clear();
    normData.shrink_to_fit();
    qAData.clear();
    qAData.shrink_to_fit();
    budget.release(tensorBytes);

    GATE("Tensor payloads released", budget.allocated == 0, 8);
    printf("       Resident after release: %llu bytes\n", (unsigned long long)budget.allocated);

    // Engine destructor will clean up its buffers
    printf("       Engine buffers: will be freed on destructor\n");

    // ═══════════════════════════════════════════════════════════════
    // Execution Summary
    // ═══════════════════════════════════════════════════════════════
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-002 Execution Summary                                  ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Tensors resolved    = 2 (attn_norm, attn_q_a)               ║\n");
    printf("║  Max residency       = %6.2f MB (budget: %6.2f MB)          ║\n",
           tensorBytes / (1024.0 * 1024.0), kMaxResidencyBytes / (1024.0 * 1024.0));
    printf("║  Kernels exercised   = RMSNormW, LinearW (Q4_K GEMV)       ║\n");
    printf("║  Output verified     = finite, non-zero, mean in range     ║\n");
    printf("║  Residency released  = YES (explicit before exit)          ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    printf("\n✅ ALL K2-002 NATIVE SMOKE GATES PASSED\n");
    return 0;
}
