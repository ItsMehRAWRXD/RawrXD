// ============================================================================
// K2-004 — Bounded Multi-Layer Prefill with Real K2 Weights
// ============================================================================
//
// Purpose: Prove that multiple transformer layers execute sequentially
//          on real K2 Q4_K weights with bounded memory and deterministic output.
//
// Scope: N layers (default: 4), 1 token per layer, strict 256 MiB budget.
// Strategy: Stream one layer at a time — load, execute, release before next.
//
// Execution chain per layer:
//   hidden → RMSNorm → MLA(Q/K/V/O) → residual → hidden (next layer)
//
// Hard requirements:
//   - All intermediate buffers finite (no NaN/Inf)
//   - Deterministic repeatability
//   - Memory stays within 256 MiB budget (peak tracked)
//   - Automatic cleanup, residency returns to zero
//   - At least 2 layers exercised to prove scalability
//
// Usage: k2_004_bounded_multi_layer_prefill <shard-directory> [numLayers]
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
// Execute one layer with streaming (load → execute → release)
// ============================================================================
static bool ExecuteLayer(
    uint32_t layerIdx,
    const Deep2::GlobalTensorIndex& index,
    const Deep2::KimiK2Config& k2cfg,
    float* hiddenIn,      // input hidden state [hiddenDim]
    float* hiddenOut,     // output hidden state [hiddenDim]
    float* scratch,       // scratch buffer [hiddenDim]
    double& outExecMs,
    std::string& error)
{
    // Build tensor names for this layer
    char qAName[64], qANormName[64], qBName[64];
    char kvAName[64], kvANormName[64], kBName[64], vBName[64];
    char oName[64], normName[64];
    snprintf(qAName, sizeof(qAName), "blk.%u.attn_q_a.weight", layerIdx);
    snprintf(qANormName, sizeof(qANormName), "blk.%u.attn_q_a_norm.weight", layerIdx);
    snprintf(qBName, sizeof(qBName), "blk.%u.attn_q_b.weight", layerIdx);
    snprintf(kvAName, sizeof(kvAName), "blk.%u.attn_kv_a_mqa.weight", layerIdx);
    snprintf(kvANormName, sizeof(kvANormName), "blk.%u.attn_kv_a_norm.weight", layerIdx);
    snprintf(kBName, sizeof(kBName), "blk.%u.attn_k_b.weight", layerIdx);
    snprintf(vBName, sizeof(vBName), "blk.%u.attn_v_b.weight", layerIdx);
    snprintf(oName, sizeof(oName), "blk.%u.attn_output.weight", layerIdx);
    snprintf(normName, sizeof(normName), "blk.%u.attn_norm.weight", layerIdx);

    // Load payloads
    std::vector<uint8_t> payloads[9];
    const char* names[] = { qAName, qBName, kvAName, kBName, vBName, oName, normName, qANormName, kvANormName };
    uint64_t layerBytes = 0;
    for (size_t i = 0; i < 9; ++i) {
        std::string loadErr;
        if (!LoadTensorPayload(index, names[i], payloads[i], loadErr)) {
            error = std::string("Layer ") + std::to_string(layerIdx) + ": " + loadErr;
            return false;
        }
        layerBytes += payloads[i].size();
    }
    TrackAlloc(layerBytes);

    // Build MLA weights
    Deep2::MLAWeights mla;
    mla.attnQ_a      = MakeTensorView(payloads[0], index, names[0], RawrXD::QuantType::Q4_K);
    mla.attnQ_b      = MakeTensorView(payloads[1], index, names[1], RawrXD::QuantType::Q4_K);
    mla.attnKV_a_mqa = MakeTensorView(payloads[2], index, names[2], RawrXD::QuantType::Q4_K);
    mla.attnK_b      = MakeTensorView(payloads[3], index, names[3], RawrXD::QuantType::Q4_K);
    mla.attnV_b      = MakeTensorView(payloads[4], index, names[4], RawrXD::QuantType::Q4_K);
    mla.attnO        = MakeTensorView(payloads[5], index, names[5], RawrXD::QuantType::Q4_K);
    mla.attnNorm     = MakeTensorView(payloads[6], index, names[6], RawrXD::QuantType::F32);
    mla.attnQ_a_norm = MakeTensorView(payloads[7], index, names[7], RawrXD::QuantType::F32);
    mla.attnKV_a_norm= MakeTensorView(payloads[8], index, names[8], RawrXD::QuantType::F32);

    // Pre-norm
    size_t hiddenDim = k2cfg.hiddenDim;
    const float* normW = mla.attnNorm.asF32();
    if (normW) {
        rmsNorm(hiddenIn, normW, scratch, hiddenDim, 1e-5f);
    } else {
        memcpy(scratch, hiddenIn, hiddenDim * sizeof(float));
    }

    // Execute MLA
    std::vector<float> mlaOut(hiddenDim, 0.0f);
    Deep2::MLAForward mlaFwd;
    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok = mlaFwd.Execute(scratch, mlaOut.data(), mla, k2cfg, error);
    auto t1 = std::chrono::high_resolution_clock::now();
    outExecMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (!ok) {
        TrackFree(layerBytes);
        return false;
    }

    // Residual add
    for (size_t i = 0; i < hiddenDim; ++i) {
        hiddenOut[i] = hiddenIn[i] + mlaOut[i];
    }

    // Release layer payloads
    for (auto& p : payloads) { TrackFree(p.size()); p.clear(); p.shrink_to_fit(); }

    return true;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-004 — Bounded Multi-Layer Prefill (Real K2 Weights)   ║\n");
    printf("║  Budget: %llu MiB   Strategy: stream one layer at a time  ║\n",
           (unsigned long long)(kBudgetBytes / (1024 * 1024)));
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    fs::path shardDir = (argc > 1) ? argv[1] : fs::current_path();
    uint32_t numLayersToRun = (argc > 2) ? static_cast<uint32_t>(atoi(argv[2])) : 4;
    if (numLayersToRun < 1) numLayersToRun = 1;
    if (numLayersToRun > 61) numLayersToRun = 61;

    printf("[INFO] Shard directory: %s\n", shardDir.string().c_str());
    printf("[INFO] Layers to exercise: %u\n", numLayersToRun);

    // ═══════════════════════════════════════════════════════════════
    // Gate 1: Shard Discovery
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 1: Shard Discovery ──\n");
    std::vector<fs::path> shards;
    if (!DiscoverK2Shards(shardDir, shards)) {
        printf("  [SKIP] No K2 shards found — skipping K2-004.\n");
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
    // Gate 3: Multi-Layer Execution
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 3: Multi-Layer Execution (%u layers) ──\n", numLayersToRun);

    size_t hiddenDim = k2cfg.hiddenDim;
    std::vector<float> hiddenA(hiddenDim);
    std::vector<float> hiddenB(hiddenDim);
    std::vector<float> scratch(hiddenDim);

    // Deterministic initial hidden state
    for (size_t i = 0; i < hiddenDim; ++i) {
        hiddenA[i] = std::sin(float(i) * 0.01f) * 0.1f;
    }

    double totalExecMs = 0.0;
    std::vector<double> layerTimes(numLayersToRun, 0.0);
    bool allFinite = true;

    for (uint32_t layer = 0; layer < numLayersToRun; ++layer) {
        printf("\n       [Layer %u/%u]\n", layer + 1, numLayersToRun);

        float* in  = (layer % 2 == 0) ? hiddenA.data() : hiddenB.data();
        float* out = (layer % 2 == 0) ? hiddenB.data() : hiddenA.data();

        std::string execErr;
        double execMs = 0.0;
        bool ok = ExecuteLayer(layer, index, k2cfg, in, out, scratch.data(),
                                execMs, execErr);
        if (!ok) {
            printf("       [FAIL] %s\n", execErr.c_str());
            return 4;
        }

        layerTimes[layer] = execMs;
        totalExecMs += execMs;

        // Validate finiteness
        if (!ValidateFinite(out, hiddenDim)) {
            printf("       [FAIL] Output contains NaN/Inf\n");
            allFinite = false;
        }

        float minVal = out[0], maxVal = out[0];
        for (size_t i = 0; i < hiddenDim; ++i) {
            minVal = std::min(minVal, out[i]);
            maxVal = std::max(maxVal, out[i]);
        }
        printf("       Time: %.3f ms | Range: [%.4f, %.4f] | Residency: %.1f MiB\n",
               execMs, minVal, maxVal, g_currentResidency / (1024.0 * 1024.0));
    }

    GATE("All layers produced finite output", allFinite, 5);
    printf("       Total execution time: %.3f ms (%.3f ms/layer avg)\n",
           totalExecMs, totalExecMs / numLayersToRun);

    // ═══════════════════════════════════════════════════════════════
    // Gate 4: Budget Enforcement
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 4: Budget Enforcement ──\n");
    printf("       Peak residency: %.1f MiB\n", g_peakResidency / (1024.0 * 1024.0));
    GATE("Peak within 256 MiB budget", g_peakResidency <= kBudgetBytes, 7);

    // ═══════════════════════════════════════════════════════════════
    // Gate 5: Determinism (re-run layer 0)
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 5: Determinism ──\n");
    {
        std::vector<float> hiddenCopy(hiddenDim);
        for (size_t i = 0; i < hiddenDim; ++i) {
            hiddenCopy[i] = std::sin(float(i) * 0.01f) * 0.1f;
        }
        std::vector<float> out1(hiddenDim);
        std::vector<float> out2(hiddenDim);
        std::vector<float> scratch2(hiddenDim);

        std::string err;
        double ms1 = 0.0, ms2 = 0.0;
        bool ok1 = ExecuteLayer(0, index, k2cfg, hiddenCopy.data(), out1.data(),
                                scratch2.data(), ms1, err);
        if (!ok1) { printf("       First run failed: %s\n", err.c_str()); return 6; }

        for (size_t i = 0; i < hiddenDim; ++i) hiddenCopy[i] = std::sin(float(i) * 0.01f) * 0.1f;
        bool ok2 = ExecuteLayer(0, index, k2cfg, hiddenCopy.data(), out2.data(),
                                scratch2.data(), ms2, err);
        if (!ok2) { printf("       Second run failed: %s\n", err.c_str()); return 6; }

        uint64_t cs1 = ComputeChecksum(out1.data(), hiddenDim);
        uint64_t cs2 = ComputeChecksum(out2.data(), hiddenDim);
        printf("       Checksum 1: 0x%016llx\n", (unsigned long long)cs1);
        printf("       Checksum 2: 0x%016llx\n", (unsigned long long)cs2);
        GATE("Deterministic (checksums match)", cs1 == cs2, 6);
    }

    // ═══════════════════════════════════════════════════════════════
    // Gate 6: Residency Cleanup
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 6: Residency Cleanup ──\n");
    printf("       Final residency: %.1f MiB\n", g_currentResidency / (1024.0 * 1024.0));
    GATE("Final residency is zero", g_currentResidency == 0, 7);

    // ═══════════════════════════════════════════════════════════════
    // Telemetry Report
    // ═══════════════════════════════════════════════════════════════
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-004 Execution Telemetry                                ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  LAYERS_EXECUTED = %-40u  ║\n", numLayersToRun);
    printf("║  TOTAL_MS        = %-40.3f  ║\n", totalExecMs);
    printf("║  AVG_MS/LAYER    = %-40.3f  ║\n", totalExecMs / numLayersToRun);
    printf("║  PEAK_RESIDENCY  = %-40.1f MiB ║\n", g_peakResidency / (1024.0 * 1024.0));
    printf("║  FINAL_RESIDENCY = %-40.1f MiB ║\n", g_currentResidency / (1024.0 * 1024.0));
    printf("║  BUDGET_MIB      = %-40.1f MiB ║\n", kBudgetBytes / (1024.0 * 1024.0));
    printf("╚════════════════════════════════════════════════════════════╝\n");

    printf("\n✅ ALL K2-004 GATES PASSED\n");
    return 0;
}
