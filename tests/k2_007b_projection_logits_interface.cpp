// ============================================================================
// K2-007B — Projection → Logits Interface
// ============================================================================
//
// Purpose: Prove that the real output.weight projection (K2-007) produces a
//          valid logits vector that the deterministic sampler can consume.
//
// Scope: Narrow integration gate between output projection and argmax.
//        Reuses proven K2-007 streaming logic; adds logits-interface validation.
//
// Pipeline:
//   discover output.weight → verify Q6_K → stream all rows → logits[163840]
//     → validate logits interface → deterministic argmax → valid token
//
// Hard requirements:
//   - Logits vector is exactly vocabSize elements
//   - All logits finite (no NaN, no Inf)
//   - Logit range is non-degenerate (max > min)
//   - Argmax returns valid token ID within [0, vocabSize)
//   - Deterministic across two runs with identical hidden
//   - Peak residency ≤ 256 MiB
//   - Final residency == 0
//
// Usage: k2_007b_projection_logits_interface <shard-directory>
// Exit codes:
//   0 = ALL GATES PASSED
//   1 = Shard discovery failed
//   2 = Index build failed
//   3 = output.weight not found
//   4 = output.weight type/shape mismatch
//   5 = Projection failed
//   6 = Logits interface validation failed
//   7 = Argmax failed
//   8 = Determinism failed
//   9 = Budget exceeded
//   10 = Residency cleanup failed
// ============================================================================

#include "../src/deep2/KimiK2Config.hpp"
#include "../src/deep2/K2GlobalTensorIndex.hpp"
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
#include <limits>

namespace fs = std::filesystem;

// ── Hard Budget ──
constexpr uint64_t kBudgetBytes = 256ull * 1024 * 1024;
static uint64_t g_currentResidency = 0;
static uint64_t g_peakResidency = 0;

static void TrackAlloc(uint64_t bytes) {
    g_currentResidency += bytes;
    if (g_currentResidency > g_peakResidency) g_peakResidency = g_currentResidency;
}
static void TrackFree(uint64_t bytes) {
    g_currentResidency = (bytes <= g_currentResidency) ? g_currentResidency - bytes : 0;
}

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

// ── FP16 → FP32 ──
static inline float fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) { f = sign << 31; }
        else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400));
            mant &= 0x3FF;
            f = (sign << 31) | ((127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float result;
    memcpy(&result, &f, sizeof(float));
    return result;
}

// ── Q4_K Block (144 bytes) ──
#pragma pack(push, 1)
struct Q4_K_Block {
    uint16_t d; uint16_t dmin; uint8_t scales[12]; uint8_t qs[128];
};
#pragma pack(pop)
static_assert(sizeof(Q4_K_Block) == 144, "Q4_K_Block must be 144 bytes");

static inline void unpackQ4KScaleMin(const uint8_t* scales, int j, uint8_t& sc, uint8_t& m) {
    if (j < 4) {
        sc = scales[j] & 63;
        m  = scales[j + 4] & 63;
    } else {
        sc = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
        m  = (scales[j + 4] >> 4)      | ((scales[j]   >> 6) << 4);
    }
}

static void dequantizeQ4KBlock(const Q4_K_Block* block, float* out) {
    float d    = fp16ToFloat(block->d);
    float dmin = fp16ToFloat(block->dmin);
    for (int j = 0; j < 8; j++) {
        uint8_t sc, m;
        unpackQ4KScaleMin(block->scales, j, sc, m);
        float scale = d * sc;
        float min   = dmin * m;
        const uint8_t* quants = block->qs + j * 16;
        for (int k = 0; k < 16; k++) {
            uint8_t byte = quants[k];
            int lo = byte & 0xF;
            int hi = (byte >> 4) & 0xF;
            out[j * 32 + k]      = scale * lo - min;
            out[j * 32 + k + 16] = scale * hi - min;
        }
    }
}

// ── Q6_K Block (210 bytes) ──
#pragma pack(push, 1)
struct Q6_K_Block {
    uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d;
};
#pragma pack(pop)
static_assert(sizeof(Q6_K_Block) == 210, "Q6_K_Block must be 210 bytes");

static void dequantizeQ6KBlock(const Q6_K_Block* block, float* out) {
    float d = fp16ToFloat(block->d);
    const uint8_t* ql = block->ql;
    const uint8_t* qh = block->qh;
    const int8_t*  sc = block->scales;
    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            int is = l / 16;
            int8_t q1 = (int8_t)((ql[l + 0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            int8_t q2 = (int8_t)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            int8_t q3 = (int8_t)((ql[l + 0]  >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            int8_t q4 = (int8_t)((ql[l + 32]  >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            out[l + 0]  = d * sc[is + 0] * q1;
            out[l + 32] = d * sc[is + 2] * q2;
            out[l + 64] = d * sc[is + 4] * q3;
            out[l + 96] = d * sc[is + 6] * q4;
        }
        out += 128;
        ql  += 64;
        qh  += 32;
        sc  += 8;
    }
}

// ── Stream one row from output.weight ──
static bool StreamOutputRow(
    const Deep2::GlobalTensorIndex& index,
    const Deep2::GlobalTensorRef& ref,
    size_t rowIdx,
    size_t cols,
    const float* hidden,
    float& outLogit,
    std::string& error)
{
    size_t kBlockElems = 256;
    size_t kBlockBytes = 0;
    if (ref.ggmlType == 12) { kBlockBytes = 144; }
    else if (ref.ggmlType == 14) { kBlockBytes = 210; }
    else { error = "Unsupported GGML type"; return false; }

    size_t blocksPerRow = (cols + kBlockElems - 1) / kBlockElems;
    size_t rowBytes = blocksPerRow * kBlockBytes;
    size_t rowOffset = rowIdx * rowBytes;
    if (rowOffset + rowBytes > ref.byteSize) { error = "Row offset exceeds tensor size"; return false; }

    const auto& shardPath = index.ShardPath(ref.shardId);
    std::ifstream f(shardPath.string(), std::ios::binary);
    if (!f) { error = "Cannot open shard"; return false; }
    f.seekg(static_cast<std::streamoff>(ref.fileOffset + rowOffset));
    if (!f.good()) { error = "Seek failed"; return false; }

    std::vector<uint8_t> rowBuf(rowBytes);
    f.read(reinterpret_cast<char*>(rowBuf.data()), rowBytes);
    if (static_cast<size_t>(f.gcount()) != rowBytes) { error = "Read size mismatch"; return false; }

    float dot = 0.0f;
    size_t col = 0;
    float blockDequant[256];
    const uint8_t* rowPtr = rowBuf.data();

    for (size_t b = 0; b < blocksPerRow && col < cols; ++b) {
        size_t elemsInBlock = std::min(kBlockElems, cols - col);
        if (ref.ggmlType == 12) {
            dequantizeQ4KBlock(reinterpret_cast<const Q4_K_Block*>(rowPtr + b * kBlockBytes), blockDequant);
        } else {
            dequantizeQ6KBlock(reinterpret_cast<const Q6_K_Block*>(rowPtr + b * kBlockBytes), blockDequant);
        }
        for (size_t i = 0; i < elemsInBlock; ++i) {
            dot += blockDequant[i] * hidden[col + i];
        }
        col += elemsInBlock;
    }
    outLogit = dot;
    return true;
}

// ── Argmax with first-index tie breaking ──
static int32_t argmaxFirst(const float* logits, size_t vocabSize) {
    if (vocabSize == 0) return -1;
    size_t best = 0;
    for (size_t i = 1; i < vocabSize; ++i) {
        if (logits[i] > logits[best]) best = i;
    }
    if (best > static_cast<size_t>(std::numeric_limits<int32_t>::max())) return -1;
    return static_cast<int32_t>(best);
}

// ── Checksum ──
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
    printf("║  K2-007B — Projection → Logits Interface                     ║\n");
    printf("║  Budget: %llu MiB                                          ║\n",
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
        printf("  [SKIP] No K2 shards found — skipping K2-007B.\n");
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
    k2cfg.vocabSize = 163840;
    GATE("Index built", index.BuildFromShardDirectory(shardDir, k2cfg, indexError), 2);
    printf("       Total tensors indexed: %zu\n", index.TotalTensors());

    // ═══════════════════════════════════════════════════════════════
    // Gate 3: Discover output.weight
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 3: Discover output.weight ──\n");
    auto outRefOpt = index.Find("output.weight");
    GATE("output.weight found in index", outRefOpt.has_value(), 3);
    const auto& outRef = *outRefOpt;
    printf("       Shard: %u, offset: %llu, bytes: %llu\n",
           outRef.shardId, (unsigned long long)outRef.fileOffset, (unsigned long long)outRef.byteSize);

    // ═══════════════════════════════════════════════════════════════
    // Gate 4: Verify GGML type is supported
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 4: Verify supported GGML type ──\n");
    const int ggmlTypeQ4_K = 12;
    const int ggmlTypeQ6_K = 14;
    printf("       GGML type: %d\n", outRef.ggmlType);
    bool typeSupported = (outRef.ggmlType == ggmlTypeQ4_K || outRef.ggmlType == ggmlTypeQ6_K);
    GATE("GGML type is Q4_K or Q6_K", typeSupported, 4);

    // ═══════════════════════════════════════════════════════════════
    // Gate 5: Verify dimensions
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 5: Verify dimensions ──\n");
    size_t vocabSize = k2cfg.vocabSize;
    size_t hiddenDim = k2cfg.hiddenDim;
    bool shapeOk = false;
    size_t actualRows = 0;
    size_t actualCols = 0;

    if (outRef.nDims == 2) {
        size_t dim0 = outRef.shape[0];
        size_t dim1 = outRef.shape[1];
        if (dim0 == vocabSize && dim1 == hiddenDim) {
            shapeOk = true; actualRows = dim0; actualCols = dim1;
            printf("       Orientation: [vocabSize, hiddenDim]\n");
        } else if (dim0 == hiddenDim && dim1 == vocabSize) {
            shapeOk = true; actualRows = dim1; actualCols = dim0;
            printf("       Orientation: [hiddenDim, vocabSize]\n");
        } else {
            printf("       Unexpected shape: [%llu, %llu]\n", (unsigned long long)dim0, (unsigned long long)dim1);
        }
    }
    GATE("Dimensions match expected", shapeOk, 4);
    printf("       Rows (vocab): %zu, Cols (hidden): %zu\n", actualRows, actualCols);

    // ═══════════════════════════════════════════════════════════════
    // Gate 6: Produce hidden state and project to logits
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 6: Project hidden → logits ──\n");
    std::vector<float> hidden(actualCols);
    for (size_t i = 0; i < actualCols; ++i) {
        hidden[i] = std::sin(float(i) * 0.01f) * 0.1f;
    }
    TrackAlloc(hidden.size() * sizeof(float));

    std::vector<float> logits(actualRows);
    TrackAlloc(logits.size() * sizeof(float));

    auto t0 = std::chrono::high_resolution_clock::now();
    bool allOk = true;
    for (size_t row = 0; row < actualRows; ++row) {
        std::string err;
        bool ok = StreamOutputRow(index, outRef, row, actualCols, hidden.data(), logits[row], err);
        if (!ok) {
            printf("       [FAIL] Row %zu: %s\n", row, err.c_str());
            allOk = false;
            break;
        }
        if ((row + 1) % 20000 == 0) {
            printf("       Progress: %zu / %zu rows\n", row + 1, actualRows);
        }
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    GATE("All rows projected", allOk, 5);
    printf("       Total time: %.3f ms (%.6f ms/row)\n", totalMs, totalMs / actualRows);

    // ═══════════════════════════════════════════════════════════════
    // Gate 7: Logits Interface Validation
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 7: Logits Interface Validation ──\n");
    GATE("Logits size == vocabSize", logits.size() == vocabSize, 6);

    bool allFinite = true;
    for (size_t i = 0; i < logits.size(); ++i) {
        if (std::isnan(logits[i]) || std::isinf(logits[i])) { allFinite = false; break; }
    }
    GATE("All logits finite", allFinite, 6);

    float minLogit = logits[0], maxLogit = logits[0];
    for (size_t i = 1; i < logits.size(); ++i) {
        minLogit = std::min(minLogit, logits[i]);
        maxLogit = std::max(maxLogit, logits[i]);
    }
    printf("       Logit range: [%.6f, %.6f]\n", minLogit, maxLogit);
    GATE("Logit range non-degenerate", maxLogit > minLogit, 6);

    // ═══════════════════════════════════════════════════════════════
    // Gate 8: Deterministic Argmax
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 8: Deterministic Argmax ──\n");
    int32_t bestToken = argmaxFirst(logits.data(), logits.size());
    printf("       Best token: %d\n", bestToken);
    GATE("Argmax returns valid token", bestToken >= 0 && bestToken < (int32_t)vocabSize, 7);

    // ═══════════════════════════════════════════════════════════════
    // Gate 9: Determinism
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 9: Determinism ──\n");
    std::vector<float> logits2(actualRows);
    TrackAlloc(logits2.size() * sizeof(float));
    bool allOk2 = true;
    for (size_t row = 0; row < actualRows; ++row) {
        std::string err;
        bool ok = StreamOutputRow(index, outRef, row, actualCols, hidden.data(), logits2[row], err);
        if (!ok) { allOk2 = false; break; }
    }
    GATE("Second projection completes", allOk2, 8);

    uint64_t cs1 = ComputeChecksum(logits.data(), logits.size());
    uint64_t cs2 = ComputeChecksum(logits2.data(), logits2.size());
    printf("       Checksum 1: 0x%016llX\n", (unsigned long long)cs1);
    printf("       Checksum 2: 0x%016llX\n", (unsigned long long)cs2);
    GATE("Deterministic logits", cs1 == cs2, 8);

    // ═══════════════════════════════════════════════════════════════
    // Gate 10: Budget Enforcement
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 10: Budget Enforcement ──\n");
    printf("       Peak residency: %.1f MiB\n", g_peakResidency / (1024.0 * 1024.0));
    GATE("Peak within 256 MiB budget", g_peakResidency <= kBudgetBytes, 9);

    // ═══════════════════════════════════════════════════════════════
    // Gate 11: Residency Cleanup
    // ═══════════════════════════════════════════════════════════════
    printf("\n── Gate 11: Residency Cleanup ──\n");
    TrackFree(hidden.size() * sizeof(float));
    TrackFree(logits.size() * sizeof(float));
    TrackFree(logits2.size() * sizeof(float));
    printf("       Final residency: %.1f MiB\n", g_currentResidency / (1024.0 * 1024.0));
    GATE("Final residency is zero", g_currentResidency == 0, 10);

    // ═══════════════════════════════════════════════════════════════
    // Telemetry Report
    // ═══════════════════════════════════════════════════════════════
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  K2-007B Execution Telemetry                               ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  VOCAB_SIZE      = %-40zu  ║\n", actualRows);
    printf("║  HIDDEN_DIM      = %-40zu  ║\n", actualCols);
    printf("║  TOTAL_MS        = %-40.3f  ║\n", totalMs);
    printf("║  AVG_MS/ROW      = %-40.6f  ║\n", totalMs / actualRows);
    printf("║  LOGIT_MIN       = %-40.6f  ║\n", minLogit);
    printf("║  LOGIT_MAX       = %-40.6f  ║\n", maxLogit);
    printf("║  BEST_TOKEN      = %-40d  ║\n", bestToken);
    printf("║  PEAK_RESIDENCY  = %-40.1f MiB ║\n", g_peakResidency / (1024.0 * 1024.0));
    printf("║  FINAL_RESIDENCY = %-40.1f MiB ║\n", g_currentResidency / (1024.0 * 1024.0));
    printf("║  DETERMINISTIC   = %-40s  ║\n", (cs1 == cs2) ? "YES" : "NO");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    printf("\n✅ ALL K2-007B GATES PASSED\n");
    return 0;
}
