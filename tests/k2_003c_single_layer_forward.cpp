// ============================================================================
// K2-003C — Single-Layer Forward with Real K2 Weights (Bounded)
// ============================================================================
//
// Purpose: Prove that one complete transformer layer (blk.0) can execute
//          on real K2 Q4_K weights with finite, deterministic output.
//
// Scope: ONE layer, ONE token, bounded memory.
// Budget: 256 MiB resident (same as K2-002/003)
//
// Execution chain:
//   hidden [hiddenDim] → RMSNorm → MLA(Q/K/V/O) → residual → output
//
// Hard requirements:
//   - All intermediate buffers finite (no NaN/Inf)
//   - Deterministic repeatability
//   - Memory stays within 256 MiB budget
//   - Automatic cleanup, residency returns to zero
//
// Usage: k2_003c_single_layer_forward <shard-directory>
// Exit codes:
//   0 = ALL GATES PASSED
//   1 = Shard discovery failed
//   2 = Index build failed
//   3 = Tensor load failed
//   4 = Layer execution failed
//   5 = Output validation failed
//   6 = Determinism failed
//   7 = Budget exceeded
// ============================================================================

#include "../src/deep2/KimiK2Config.hpp"
#include "../src/deep2/K2GlobalTensorIndex.hpp"
#include "../src/deep2/K2MLAWeights.hpp"
#include "../src/deep2/GGUFLoader.hpp"
#include "../src/deep2/TensorView.hpp"
#include "../src/deep2/UniversalTensorDescriptor.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <vector>
#include <chrono>
#include <algorithm>

namespace fs = std::filesystem;

// ── Hard Budget ──
constexpr uint64_t kBudgetBytes = 256ull * 1024 * 1024;
static uint64_t g_currentResidency = 0;
static uint64_t g_peakResidency = 0;

// ── Residency Accounting ──
static void TrackAlloc(uint64_t bytes) {
    g_currentResidency += bytes;
    if (g_currentResidency > g_peakResidency) g_peakResidency = g_currentResidency;
}
static void TrackFree(uint64_t bytes) {
    g_currentResidency = (bytes <= g_currentResidency) ? g_currentResidency - bytes : 0;
}

// ── Gate Helpers ──
#define GATE(name, condition, exitCode) \
    do { \
        if (!(condition)) { \
            printf("  [FAIL] Gate: %s\n", name); \
            return exitCode; \
        } \
        printf("  [PASS] Gate: %s\n", name); \
    } while(0)

// ── Shard Discovery ──
static bool DiscoverK2Shards(const fs::path& dir, std::vector<fs::path>& shards) {
    shards.clear();
    for (int i = 1; i <= 13; ++i) {
        char name[256];
        snprintf(name, sizeof(name),
                 "Kimi-K2-Instruct-0905-Q4_K_M-%05d-of-00013.gguf", i);
        fs::path candidate = dir / name;
        if (fs::exists(candidate)) { shards.push_back(candidate); continue; }
        snprintf(name, sizeof(name),
                 "kimi-k2-instruct-0905-q4_k_m-%05d-of-00013.gguf", i);
        candidate = dir / name;
        if (fs::exists(candidate)) { shards.push_back(candidate); }
    }
    return !shards.empty();
}

// ── Load tensor payload from shard into resident buffer ──
static bool LoadTensorPayload(const Deep2::GlobalTensorIndex& index,
                               const char* name,
                               std::vector<uint8_t>& outBytes,
                               std::string& error) {
    auto refOpt = index.Find(name);
    if (!refOpt) { error = std::string("Tensor not found: ") + name; return false; }
    const auto& ref = *refOpt;

    const auto& shardPath = index.ShardPath(ref.shardId);
    std::ifstream f(shardPath.string(), std::ios::binary);
    if (!f) { error = "Cannot open shard"; return false; }
    f.seekg(static_cast<std::streamoff>(ref.fileOffset));
    if (!f.good()) { error = "Seek failed"; return false; }

    outBytes.resize(ref.byteSize);
    f.read(reinterpret_cast<char*>(outBytes.data()), ref.byteSize);
    if (static_cast<size_t>(f.gcount()) != ref.byteSize) {
        error = "Read size mismatch"; return false;
    }
    return true;
}

// ── Build a TensorView from raw payload bytes ──
static RawrXD::TensorView MakeTensorView(
    const std::vector<uint8_t>& payload,
    const Deep2::GlobalTensorIndex& index,
    const char* name,
    RawrXD::QuantType qt)
{
    auto refOpt = index.Find(name);
    if (!refOpt) return RawrXD::TensorView();
    const auto& ref = *refOpt;

    RawrXD::UniversalTensorDescriptor desc;
    desc.numDims = ref.nDims;
    for (uint8_t i = 0; i < ref.nDims && i < 8; ++i) desc.shape[i] = ref.shape[i];
    desc.layout = RawrXD::TensorLayout::BLOCKED;
    desc.role = RawrXD::TensorRole::WEIGHT;
    desc.memorySpace = RawrXD::UniversalTensorDescriptor::MemorySpace::HOST;
    desc.data = const_cast<void*>((const void*)payload.data());
    desc.quantType = qt;

    // Block sizes per quant type
    switch (qt) {
        case RawrXD::QuantType::F32: desc.blockSize = 1;   desc.blockSizeBytes = 4; break;
        case RawrXD::QuantType::F16: desc.blockSize = 1;   desc.blockSizeBytes = 2; break;
        case RawrXD::QuantType::Q4_K: desc.blockSize = 256; desc.blockSizeBytes = 144; break;
        default: desc.blockSize = 1; desc.blockSizeBytes = 1; break;
    }

    return RawrXD::TensorView::FromBuffer(desc, const_cast<void*>((const void*)payload.data()), false);
}

// ── RMSNorm (scalar) ──
static void rmsNorm(const float* input, const float* weight,
                    float* output, size_t n, float eps) {
    float ss = 0.0f;
    for (size_t i = 0; i < n; ++i) ss += input[i] * input[i];
    float invRms = 1.0f / std::sqrt(ss / static_cast<float>(n) + eps);
    for (size_t i = 0; i < n; ++i) output[i] = input[i] * invRms * weight[i];
}

// ── Validate output: finite, no NaN/Inf ──
static bool ValidateFinite(const float* data, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (std::isnan(data[i]) || std::isinf(data[i])) return false;
    }
    return true;
}

// ── Compute simple checksum for determinism ──
static uint64_t ComputeChecksum(const float* data, size_t count) {
    uint64_t sum = 0;
    for (size_t i = 0; i < count; ++i) {
        uint32_t bits;
        memcpy(&bits, &data[i], sizeof(uint32_t));
        sum = (sum << 1) | (sum >> 63);
        sum ^= bits;
    }
    return sum;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-003C — Single-Layer Forward (Real K2 Weights)          ║\n");
    printf("║  Budget: %llu MiB   Scope: blk.0, one token                ║\n",
           (unsigned long long)(kBudgetBytes / (1024 * 1024)));
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    fs::path shardDir = (argc > 1) ? argv[1] : fs::current_path();
    printf("[INFO] Shard directory: %s\n", shardDir.string().c_str());

    // ═══════════════════════════════════════════════════════════════
    // Gate 1: Shard Discovery
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 1: Shard Discovery ──\n");
    std::vector<fs::path> shards;
    if (!DiscoverK2Shards(shardDir, shards)) {
        printf("  [SKIP] No K2 shards found — skipping K2-003C.\n");
        return 0;
    }
    printf("       Found %zu shard(s)\n", shards.size());

    // ═══════════════════════════════════════════════════════════════
    // Gate 2: Tensor Index Build
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 2: Tensor Index Build ──\n");
    Deep2::GlobalTensorIndex index;
    std::string indexError;
    Deep2::KimiK2Config k2cfg;
    k2cfg.hiddenDim = 7168;
    k2cfg.numLayers = 61;
    k2cfg.numHeads = 128;
    k2cfg.qLoraRank = 1536;
    k2cfg.kvLoraRank = 512;
    k2cfg.qkNopeHeadDim = 128;
    k2cfg.qkRopeHeadDim = 64;
    k2cfg.vHeadDim = 128;
    GATE("Index built", index.BuildFromShardDirectory(shardDir, k2cfg, indexError), 2);
    printf("       Total tensors indexed: %zu\n", index.TotalTensors());

    // ═══════════════════════════════════════════════════════════════
    // Gate 3: Resolve MLA weights for layer 0
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 3: Resolve blk.0 MLA Weights ──\n");
    Deep2::MLAWeights mla;
    std::string mlaErr;
    GATE("MLA resolved", mla.ResolveFromTensorIndex(index, 0, mlaErr), 3);
    printf("       attn_q_a:     [%llu, %llu]\n",
           (unsigned long long)mla.attnQ_a.dims()[0], (unsigned long long)mla.attnQ_a.dims()[1]);
    printf("       attn_q_b:     [%llu, %llu]\n",
           (unsigned long long)mla.attnQ_b.dims()[0], (unsigned long long)mla.attnQ_b.dims()[1]);
    printf("       attn_output:  [%llu, %llu]\n",
           (unsigned long long)mla.attnO.dims()[0], (unsigned long long)mla.attnO.dims()[1]);

    // ═══════════════════════════════════════════════════════════════
    // Gate 4: Load actual tensor payloads under budget
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 4: Load Tensor Payloads ──\n");

    const char* tensorNames[] = {
        "blk.0.attn_q_a.weight",
        "blk.0.attn_q_b.weight",
        "blk.0.attn_kv_a_mqa.weight",
        "blk.0.attn_k_b.weight",
        "blk.0.attn_v_b.weight",
        "blk.0.attn_output.weight",
        "blk.0.attn_norm.weight",
        "blk.0.attn_q_a_norm.weight",
        "blk.0.attn_kv_a_norm.weight",
    };
    constexpr size_t kNumTensors = sizeof(tensorNames) / sizeof(tensorNames[0]);

    std::vector<std::vector<uint8_t>> payloads(kNumTensors);
    uint64_t totalLoaded = 0;
    for (size_t i = 0; i < kNumTensors; ++i) {
        std::string loadErr;
        if (!LoadTensorPayload(index, tensorNames[i], payloads[i], loadErr)) {
            printf("  [WARN] %s: %s\n", tensorNames[i], loadErr.c_str());
            continue;
        }
        totalLoaded += payloads[i].size();
        printf("       %s: %zu bytes\n", tensorNames[i], payloads[i].size());
    }
    TrackAlloc(totalLoaded);
    printf("       Total loaded: %llu bytes (%.1f MiB)\n",
           (unsigned long long)totalLoaded, totalLoaded / (1024.0 * 1024.0));
    GATE("Within budget", g_currentResidency <= kBudgetBytes, 7);

    // ═══════════════════════════════════════════════════════════════
    // Gate 5: Build TensorViews with actual data
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 5: Materialize TensorViews ──\n");
    mla.attnQ_a     = MakeTensorView(payloads[0], index, tensorNames[0], RawrXD::QuantType::Q4_K);
    mla.attnQ_b     = MakeTensorView(payloads[1], index, tensorNames[1], RawrXD::QuantType::Q4_K);
    mla.attnKV_a_mqa= MakeTensorView(payloads[2], index, tensorNames[2], RawrXD::QuantType::Q4_K);
    mla.attnK_b     = MakeTensorView(payloads[3], index, tensorNames[3], RawrXD::QuantType::Q4_K);
    mla.attnV_b     = MakeTensorView(payloads[4], index, tensorNames[4], RawrXD::QuantType::Q4_K);
    mla.attnO       = MakeTensorView(payloads[5], index, tensorNames[5], RawrXD::QuantType::Q4_K);
    mla.attnNorm    = MakeTensorView(payloads[6], index, tensorNames[6], RawrXD::QuantType::F32);
    mla.attnQ_a_norm= MakeTensorView(payloads[7], index, tensorNames[7], RawrXD::QuantType::F32);
    mla.attnKV_a_norm=MakeTensorView(payloads[8], index, tensorNames[8], RawrXD::QuantType::F32);

    bool allData = mla.attnQ_a.data() && mla.attnQ_b.data() && mla.attnKV_a_mqa.data() &&
                   mla.attnK_b.data() && mla.attnV_b.data() && mla.attnO.data();
    GATE("All weight tensors materialized", allData, 3);

    // ═══════════════════════════════════════════════════════════════
    // Gate 6: Single-Token Forward Execution
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 6: Single-Token Forward ──\n");

    // Synthetic hidden state (deterministic)
    size_t hiddenDim = k2cfg.hiddenDim;
    std::vector<float> hidden(hiddenDim);
    for (size_t i = 0; i < hiddenDim; ++i) {
        hidden[i] = std::sin(float(i) * 0.01f) * 0.1f;
    }

    // Pre-norm buffer
    std::vector<float> normed(hiddenDim);
    const float* normW = mla.attnNorm.asF32();
    if (normW) {
        rmsNorm(hidden.data(), normW, normed.data(), hiddenDim, 1e-5f);
    } else {
        memcpy(normed.data(), hidden.data(), hiddenDim * sizeof(float));
    }

    // Allocate output buffer
    std::vector<float> mlaOut(hiddenDim, 0.0f);

    // Execute MLA forward (uses KimiK2Config directly)
    std::string execErr;
    Deep2::MLAForward mlaFwd;
    auto t0 = std::chrono::high_resolution_clock::now();
    bool execOk = mlaFwd.Execute(normed.data(), mlaOut.data(),
                                  mla, k2cfg, execErr);
    auto t1 = std::chrono::high_resolution_clock::now();
    double execMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (!execOk) {
        printf("       Error: %s\n", execErr.c_str());
    }
    GATE("MLAForward executed", execOk, 4);
    printf("       Execution time: %.3f ms\n", execMs);

    // Residual add: output = hidden + mlaOut
    std::vector<float> finalOut(hiddenDim);
    for (size_t i = 0; i < hiddenDim; ++i) {
        finalOut[i] = hidden[i] + mlaOut[i];
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 7: Output Validation (finite, reasonable range)
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 7: Output Validation ──\n");
    GATE("All outputs finite", ValidateFinite(finalOut.data(), hiddenDim), 5);

    float minVal = finalOut[0], maxVal = finalOut[0], sumVal = 0.0f;
    for (size_t i = 0; i < hiddenDim; ++i) {
        minVal = std::min(minVal, finalOut[i]);
        maxVal = std::max(maxVal, finalOut[i]);
        sumVal += finalOut[i];
    }
    float meanVal = sumVal / hiddenDim;
    printf("       min=%.4f max=%.4f mean=%.4f\n", minVal, maxVal, meanVal);

    // Reasonable range check: after one layer, values should not explode
    GATE("Output range reasonable (|max| < 100)", std::abs(maxVal) < 100.0f && std::abs(minVal) < 100.0f, 5);

    // ═══════════════════════════════════════════════════════════════
    // Gate 8: Determinism
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 8: Determinism ──\n");
    std::vector<float> mlaOut2(hiddenDim, 0.0f);
    Deep2::MLAForward mlaFwd2;
    bool execOk2 = mlaFwd2.Execute(normed.data(), mlaOut2.data(),
                                    mla, k2cfg, execErr);
    GATE("Second execution succeeded", execOk2, 6);

    uint64_t cs1 = ComputeChecksum(mlaOut.data(), hiddenDim);
    uint64_t cs2 = ComputeChecksum(mlaOut2.data(), hiddenDim);
    printf("       Checksum 1: 0x%016llx\n", (unsigned long long)cs1);
    printf("       Checksum 2: 0x%016llx\n", (unsigned long long)cs2);
    GATE("Deterministic (checksums match)", cs1 == cs2, 6);

    // ═══════════════════════════════════════════════════════════════
    // Gate 9: Residency Cleanup
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 9: Residency Cleanup ──\n");
    // Release payloads (TensorViews don't own data, so just clear vectors)
    for (auto& p : payloads) { TrackFree(p.size()); p.clear(); p.shrink_to_fit(); }
    printf("       Peak residency: %.1f MiB\n", g_peakResidency / (1024.0 * 1024.0));
    printf("       Final residency: %.1f MiB\n", g_currentResidency / (1024.0 * 1024.0));
    GATE("Final residency is zero", g_currentResidency == 0, 7);
    GATE("Peak within budget", g_peakResidency <= kBudgetBytes, 7);

    // ═══════════════════════════════════════════════════════════════
    // Telemetry Report
    // ═══════════════════════════════════════════════════════════════
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-003C Execution Telemetry                               ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  LAYER           = %-40s  ║\n", "blk.0");
    printf("║  HIDDEN_DIM      = %-40zu  ║\n", hiddenDim);
    printf("║  EXEC_MS         = %-40.3f  ║\n", execMs);
    printf("║  PEAK_RESIDENCY  = %-40.1f MiB ║\n", g_peakResidency / (1024.0 * 1024.0));
    printf("║  FINAL_RESIDENCY = %-40.1f MiB ║\n", g_currentResidency / (1024.0 * 1024.0));
    printf("║  OUTPUT_MIN      = %-40.4f  ║\n", minVal);
    printf("║  OUTPUT_MAX      = %-40.4f  ║\n", maxVal);
    printf("║  OUTPUT_MEAN     = %-40.4f  ║\n", meanVal);
    printf("║  DETERMINISTIC   = %-40s  ║\n", (cs1 == cs2) ? "YES" : "NO");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    printf("\n✅ ALL K2-003C GATES PASSED\n");
    return 0;
}
